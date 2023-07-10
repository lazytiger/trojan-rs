use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Write},
    net::{Shutdown, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use mio::{
    net::{TcpStream, UdpSocket},
    Token,
};
use rustls::{ClientConfig, ClientConnection, Connection, ServerName};
use smoltcp::{iface::SocketHandle, socket::udp::Socket, wire::IpEndpoint};
use trust_dns_proto::{op::Message, serialize::binary::BinDecodable};

use crate::{
    tun::{
        device::VpnDevice,
        proto::{TrojanRequest, UdpAssociate, UdpParseResultEndpoint, UDP_ASSOCIATE},
        tls_conn::TlsConn,
        udp::UdpSocketRef,
        utils::{read_once, send_all},
        waker::WakerMode,
    },
    types,
    types::VpnError,
};

pub struct DnsServer {
    server_addr: SocketAddr,
    config: Arc<ClientConfig>,
    hostname: ServerName,
    listener: SocketHandle,
    trusted: TlsConn,
    trusted_rbuffer: BytesMut,
    trusted_lbuffer: BytesMut,
    trusted_addr: SocketAddr,
    blocked_domains: HashSet<String>,
    store: HashMap<String, QueryResult>,
    untrusted: UdpSocket,
    buffer: Vec<u8>,
    untrusted_addr: SocketAddr,
    dns_cache_time: u64,
    pub pass: String,
}

struct QueryResult {
    addresses: Vec<(IpEndpoint, u16)>,
    response: Option<Message>,
    expire_time: Instant,
}

impl DnsServer {
    pub fn new(
        server_addr: SocketAddr,
        config: Arc<ClientConfig>,
        hostname: ServerName,
        listener: SocketHandle,
        trusted_addr: SocketAddr,
        untrusted_addr: SocketAddr,
        dns_cache_time: u64,
        mtu: usize,
        pass: String,
        blocked_domains: HashSet<String>,
    ) -> types::Result<DnsServer> {
        let trusted = new_tls_conn(server_addr, config.clone(), hostname.clone(), &pass)?;
        let untrusted = UdpSocket::bind("0.0.0.0:0".parse().unwrap())?;
        Ok(DnsServer {
            server_addr,
            config,
            hostname,
            listener,
            trusted,
            trusted_rbuffer: Default::default(),
            trusted_lbuffer: Default::default(),
            trusted_addr,
            blocked_domains,
            store: Default::default(),
            untrusted,
            buffer: vec![0u8; mtu],
            untrusted_addr,
            dns_cache_time,
            pass,
        })
    }

    pub fn add_domain(&mut self, domain: String) {
        self.blocked_domains.insert(domain);
    }

    pub fn del_domain(&mut self, domain: &String) {
        self.blocked_domains.remove(domain);
    }

    fn do_request(&mut self, device: &mut VpnDevice) {
        let now = Instant::now();
        let mut buffer = self.buffer.clone();
        let listener = device.get_udp_socket_mut(self.listener, WakerMode::None);
        while let Ok((len, endpoint)) = listener.recv_slice(buffer.as_mut_slice()) {
            let endpoint = endpoint.endpoint;
            log::info!("got dns request {} bytes", len);
            let data = &buffer.as_slice()[..len];
            if let Ok(message) = Message::from_bytes(data) {
                if message.query_count() == 1 {
                    let query = &message.queries()[0];
                    let name = query.name().to_utf8();
                    log::error!("found dns query:{}", name);
                    let key = Self::get_message_key(&message);
                    let (renew, respond) = if let Some(QueryResult {
                        response: Some(response),
                        expire_time,
                        ..
                    }) = self.store.get_mut(&key)
                    {
                        log::error!("query:{} found in cache", key);
                        response.set_id(message.id());
                        if let Err(err) =
                            listener.send_slice(response.to_vec().unwrap().as_slice(), endpoint)
                        {
                            log::error!("send response to {:?} failed:{:?}", endpoint, err);
                        }
                        (*expire_time <= now, false)
                    } else {
                        (true, true)
                    };

                    if renew {
                        if self.is_blocked(&name) {
                            if !self.query_trusted(data) {
                                log::error!("send to trusted dns failed");
                                continue;
                            }
                            log::info!("domain:{} is blocked", name);
                        } else {
                            if let Err(err) = self.untrusted.send_to(data, self.untrusted_addr) {
                                log::error!("send to poisoned dns failed:{}", err);
                                continue;
                            }
                            log::info!("domain:{} is not blocked", name);
                        }
                        if respond {
                            self.add_request(key, endpoint, message.id());
                        }
                    }
                } else {
                    log::error!(
                        "query count:{} found in message:{:?}",
                        message.query_count(),
                        message
                    );
                }
            } else {
                log::warn!("not a dns message found");
            }
        }
    }

    fn do_trusted_response(&mut self, device: &mut VpnDevice) {
        let socket = UdpSocketRef {
            socket: device.get_udp_socket_mut(self.listener, WakerMode::None),
            endpoint: None,
        };

        loop {
            let mut closed = false;
            match read_once(&mut self.trusted, &mut self.trusted_rbuffer) {
                Ok(true) => {}
                Ok(false) => return,
                Err(err) => {
                    log::info!("remote closed with error:{:?}", err);
                    closed = true;
                }
            }

            if closed {
                self.reset_trusted();
                return;
            }

            let mut trusted_rbuffer = self.trusted_rbuffer.split();
            let mut buffer = trusted_rbuffer.as_ref();
            loop {
                match UdpAssociate::parse_endpoint(buffer) {
                    UdpParseResultEndpoint::Continued => {
                        let offset = trusted_rbuffer.len() - buffer.len();
                        if buffer.is_empty() {
                            trusted_rbuffer.clear();
                        } else {
                            let len = buffer.len();
                            trusted_rbuffer.copy_within(offset.., 0);
                            unsafe {
                                trusted_rbuffer.set_len(len);
                            }
                        }
                        log::info!(
                            "continue parsing with {} bytes left",
                            self.trusted_rbuffer.len()
                        );
                        break;
                    }
                    UdpParseResultEndpoint::Packet(packet) => {
                        let payload = &packet.payload[..packet.length];
                        if let Ok(message) = Message::from_bytes(payload) {
                            log::info!("get response from trusted");
                            self.dispatch_message(message, socket.socket);
                        }
                        buffer = &packet.payload[packet.length..];
                    }
                    UdpParseResultEndpoint::InvalidProtocol => {
                        log::info!("invalid protocol close now");
                        self.reset_trusted();
                        return;
                    }
                }
            }
            self.trusted_rbuffer.unsplit(trusted_rbuffer);
        }
    }

    fn do_untrusted_response(&mut self, device: &mut VpnDevice) {
        while let Ok((len, from)) = self.untrusted.recv_from(self.buffer.as_mut_slice()) {
            let data = &self.buffer.as_slice()[..len];
            if let Ok(message) = Message::from_bytes(data) {
                log::info!("get response from untrusted");
                self.dispatch_message(
                    message,
                    device.get_udp_socket_mut(self.listener, WakerMode::None),
                );
            } else {
                log::error!("invalid response message received from {}", from);
            }
        }
    }

    fn dispatch_message(&mut self, mut message: Message, listener: &mut Socket) {
        let now = Instant::now();
        let name = Self::get_message_key(&message);
        log::error!("query {} found in dns server", name);
        if message.header().truncated() {
            log::error!("{} message truncated", name);
        }
        message.take_additionals();
        message.take_name_servers();
        let mut header = message.header().clone();
        header.set_truncated(false);
        header.set_name_server_count(0);
        header.set_additional_count(0);
        message.set_header(header);
        log::debug!("response:{:?}", message);
        if let Some(result) = self.store.get_mut(&name) {
            for (address, id) in &result.addresses {
                message.set_id(*id);
                if let Err(err) =
                    listener.send_slice(message.to_vec().unwrap().as_slice(), *address)
                {
                    log::error!("send to {:?} failed:{:?}", address, err);
                } else {
                    log::debug!("send response to {}", address);
                }
            }
            let mut timeout = 0;
            for record in message.answers() {
                timeout = record.ttl();
                log::info!(
                    "got response {} -> {}, expire in {} seconds",
                    name,
                    record.to_string(),
                    timeout,
                );
            }
            result.expire_time = now + Duration::new(timeout as u64, 0);
            result.addresses.clear();
            result.response.replace(message);
        } else {
            log::error!("key:{} not found in store", name);
        }
    }

    fn query_trusted(&mut self, body: &[u8]) -> bool {
        let mut header = BytesMut::new();
        UdpAssociate::generate(&mut header, &self.trusted_addr, body.len() as u16);
        if !self.trusted_lbuffer.is_empty() {
            match send_all(&mut self.trusted, &mut self.trusted_lbuffer) {
                Ok(true) => {
                    log::info!("send all completed");
                }
                Ok(false) => {
                    log::info!("last request not finished, discard new request");
                    self.flush_trusted();
                    return false;
                }
                Err(err) => {
                    log::info!("remote connection break:{:?}", err);
                    self.reset_trusted();
                    return false;
                }
            }
        }
        let mut data = header.as_ref();
        let mut offset = 0;
        while !data.is_empty() {
            match self.trusted.write(data) {
                Ok(0) => {
                    log::info!("remote connection break with 0 bytes");
                    self.reset_trusted();
                    return false;
                }
                Ok(n) => {
                    log::info!("send {} byte raw data", n);
                    offset += n;
                    data = &data[n..];
                    if data.is_empty() && offset == header.len() {
                        data = body;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::info!("write to remote blocked");
                    break;
                }
                Err(err) => {
                    log::info!("remote connection break:{:?}", err);
                    self.reset_trusted();
                    return false;
                }
            }
        }
        let remaining = header.len() + body.len() - offset;
        if remaining != 0 {
            self.trusted_lbuffer.extend_from_slice(data);
            if data.len() < header.len() {
                self.trusted_lbuffer.extend_from_slice(body);
            }
        }
        self.flush_trusted()
    }

    fn flush_trusted(&mut self) -> bool {
        if let Err(err) = self.trusted.flush() {
            let ret = err.kind() == ErrorKind::WouldBlock;
            if !ret {
                log::error!("flush trusted failed:{:?}", err);
            }
            ret
        } else {
            true
        }
    }

    fn reset_trusted(&mut self) {
        let _ = self.trusted.stream.shutdown(Shutdown::Both);
        self.trusted = new_tls_conn(
            self.server_addr,
            self.config.clone(),
            self.hostname.clone(),
            &self.pass,
        )
        .unwrap();
        self.trusted_rbuffer.clear();
        self.trusted_lbuffer.clear();
    }

    fn get_message_key(message: &Message) -> String {
        let query = &message.queries()[0];
        let name = query.name().to_utf8();
        name + "|" + query.query_type().to_string().as_str()
    }

    fn is_blocked(&self, name: &str) -> bool {
        let split: Vec<_> = name.split(".").collect();
        let len = if name.ends_with(".") {
            split.len() - 1
        } else {
            split.len()
        };
        for i in 0..(len - 1) {
            let name = split.as_slice()[i..len].join(".");
            log::info!("test domain:{}", name);
            if self.blocked_domains.contains(name.as_str()) {
                return true;
            }
        }
        false
    }
    fn add_request(&mut self, name: String, address: IpEndpoint, id: u16) {
        let result = if let Some(result) = self.store.get_mut(&name) {
            result
        } else {
            self.store.insert(
                name.clone(),
                QueryResult {
                    addresses: vec![],
                    response: None,
                    expire_time: Instant::now() + Duration::new(self.dns_cache_time, 0),
                },
            );
            self.store.get_mut(&name).unwrap()
        };
        result.addresses.push((address, id));
    }

    pub fn ready(&mut self, device: &mut VpnDevice) {
        self.do_request(device);
        self.do_trusted_response(device);
        self.do_untrusted_response(device);
    }
}

fn new_tls_conn(
    server_addr: SocketAddr,
    config: Arc<ClientConfig>,
    hostname: ServerName,
    pass: &String,
) -> Result<TlsConn, VpnError> {
    let server = TcpStream::connect(server_addr)?;
    //sys::set_mark(&server, self.marker)?;
    #[cfg(not(target_os = "windows"))]
    server.set_nodelay(true)?;

    let session = ClientConnection::new(config, hostname)?;
    let mut conn = TlsConn::new(0, Token(0), Connection::Client(session), server);
    let empty_addr = "0.0.0.0:0".parse().unwrap();

    let mut buffer = BytesMut::new();
    TrojanRequest::generate(&mut buffer, UDP_ASSOCIATE, pass.as_bytes(), &empty_addr);

    conn.write(buffer.as_ref())?;
    Ok(conn)
}
