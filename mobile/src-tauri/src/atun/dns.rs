use std::{
    collections::{HashMap, HashSet},
    io::Error,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rustls::{ClientConfig, ServerName};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc::Sender,
};
use trust_dns_proto::{op::Message, serialize::binary::BinDecodable};

use crate::atun::{
    device::UdpStream,
    init_tls_conn,
    proto::{UdpAssociate, UdpParseResultEndpoint},
    tls_stream::{TlsClientReadHalf, TlsClientWriteHalf},
};

pub async fn start_trust_response(
    sender: Sender<Response>,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    buffer_size: usize,
    string: String,
) -> Option<TlsClientWriteHalf> {
    match init_tls_conn(config, buffer_size, server_addr, server_name).await {
        Ok(client) => {
            let (read_half, write_half) = client.into_split();
            spawn(do_trust_response(sender, read_half));
            Some(write_half)
        }
        Err(err) => {
            log::error!("connect to server failed:{:?}", err);
            None
        }
    }
}

pub async fn start_distrust_response(sender: Sender<Response>) -> Option<Arc<UdpSocket>> {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        let socket = Arc::new(socket);
        spawn(do_distrust_response(sender, socket.clone()));
        Some(socket)
    } else {
        log::error!("create udp socket failed");
        None
    }
}

fn get_message_key(message: &Message) -> String {
    let query = &message.queries()[0];
    let name = query.name().to_utf8();
    name + "|" + query.query_type().to_string().as_str()
}

pub async fn start_dns(
    mut local: UdpStream,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    buffer_size: usize,
    pass: String,
    trusted_addr: SocketAddr,
    distrusted_addr: SocketAddr,
    blocked_domains: HashSet<String>,
) {
    let mut buffer = vec![0u8; 1500];
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
    let mut distrust = start_distrust_response(sender.clone()).await.unwrap();
    let mut trust = start_trust_response(
        sender.clone(),
        config.clone(),
        server_addr,
        server_name.clone(),
        buffer_size,
        pass.clone(),
    )
    .await
    .unwrap();
    let mut dns_store = HashMap::new();

    loop {
        tokio::select! {
            req = local.recv(buffer.as_mut_slice()) => {
                match req {
                    Ok((n, source)) => {
                        if let Ok(message) = Message::from_bytes(&buffer.as_slice()[..n]) {
                            if message.query_count() != 1 {
                                continue;
                            }
                            let key = get_message_key(&message);
                            if dns_store.entry(key).or_insert_with(||DnsItem::new(message.clone())).respond(&mut local, source, message.id()).await {
                                let name = message.query().unwrap().name().to_utf8();
                                if is_blocked(&blocked_domains, &name) {
                                    let mut header = BytesMut::new();
                                    UdpAssociate::generate(&mut header, &trusted_addr, n as u16);
                                    let _ = trust.write_all(header.as_ref()).await;
                                    let _ = trust.write_all(&buffer.as_slice()[..n]).await;
                                } else {
                                    let _ = distrust.send(&buffer.as_slice()[..n]).await;
                                }
                            }
                        }
                    },
                    Err(err) => {
                        log::error!("recv from local udp failed:{}", err);
                        break;
                    }
                }
            },
            resp = receiver.recv() => {
                match resp {
                    Some(Response::Message(m))  => {
                        let key = get_message_key(&m);
                        dns_store.entry(key).or_insert_with(||DnsItem::new(m.clone())).notify(m, &mut local).await;
                    },
                    Some(Response::DistrustClosed) => {
                        distrust = start_distrust_response(sender.clone()).await.unwrap();
                    },
                    Some(Response::TrustClosed) => {
                        trust = start_trust_response(
                            sender.clone(),
                            config.clone(),
                            server_addr,
                            server_name.clone(),
                            buffer_size,
                            pass.clone())
                        .await
                        .unwrap();
                    },
                    None => {
                        log::error!("sender closed, quit now");
                        break;
                    }
                }
            }
        }
    }
}

pub async fn do_distrust_response(sender: Sender<Response>, socket: Arc<UdpSocket>) {
    let mut buffer = vec![0u8; 1500];
    loop {
        match socket.recv(buffer.as_mut_slice()).await {
            Ok(n) => {
                if let Ok(message) = Message::from_bytes(&buffer.as_slice()[..n]) {
                    if let Err(err) = sender.send(Response::Message(message)).await {
                        log::error!("sender closed with error:{}", err);
                        break;
                    }
                }
            }
            Err(err) => {
                log::error!("recv from untrusted socket failed:{}", err);
                break;
            }
        }
    }
    let _ = sender.send(Response::DistrustClosed).await;
}

pub async fn do_trust_response(sender: Sender<Response>, mut remote: TlsClientReadHalf) {
    let mut buffer = vec![0u8; 1500];
    let mut offset = 0;
    'main: loop {
        match remote.read(&mut buffer.as_mut_slice()[offset..]).await {
            Ok(0) | Err(_) => {
                log::error!("read from server failed");
                break;
            }
            Ok(n) => {
                offset += n;
                let mut data = &buffer.as_slice()[..offset];
                loop {
                    match UdpAssociate::parse_endpoint(data) {
                        UdpParseResultEndpoint::Continued => {
                            if data.is_empty() {
                                offset = 0;
                            } else {
                                let remaining = offset - data.len();
                                offset = data.len();
                                buffer.copy_within(remaining.., 0);
                            }
                            log::info!("continue parsing with {} bytes left", buffer.len());
                            break;
                        }
                        UdpParseResultEndpoint::Packet(packet) => {
                            let payload = &packet.payload[..packet.length];
                            if let Ok(message) = Message::from_bytes(payload) {
                                if let Err(err) = sender.send(Response::Message(message)).await {
                                    break 'main;
                                }
                            }
                            data = &packet.payload[packet.length..];
                        }
                        UdpParseResultEndpoint::InvalidProtocol => {
                            log::info!("invalid protocol close now");
                            break 'main;
                        }
                    }
                }
            }
        }
    }
    let _ = sender.send(Response::TrustClosed).await;
}

fn is_blocked(blocked: &HashSet<String>, name: &str) -> bool {
    let split: Vec<_> = name.split(".").collect();
    let len = if name.ends_with(".") {
        split.len() - 1
    } else {
        split.len()
    };
    for i in 0..(len - 1) {
        let name = split.as_slice()[i..len].join(".");
        log::info!("test domain:{}", name);
        if blocked.contains(name.as_str()) {
            return true;
        }
    }
    false
}

pub enum Response {
    Message(Message),
    TrustClosed,
    DistrustClosed,
}

pub struct DnsItem {
    message: Message,
    expire: Instant,
    clients: Vec<(IpEndpoint, u16)>,
}

impl DnsItem {
    pub fn new(message: Message) -> DnsItem {
        Self {
            message,
            clients: Vec::new(),
            expire: Instant::now(),
        }
    }

    pub fn has_response(&self) -> bool {
        self.message.answers().len() > 0
    }

    pub fn add_client(&mut self, client: IpEndpoint, id: u16) {
        self.clients.push((client, id))
    }

    pub async fn notify(&mut self, mut message: Message, stream: &mut UdpStream) {
        for (source, id) in std::mem::take(&mut self.clients) {
            message.set_id(id);
            message.take_additionals();
            message.take_name_servers();
            let _ = stream
                .send(message.to_vec().unwrap().as_slice(), source)
                .await;
        }
        if let Some(answer) = message.answers().get(0) {
            self.expire = Instant::now() + Duration::from_secs(answer.ttl() as u64);
        }
        self.message = message;
    }

    pub async fn respond(&mut self, stream: &mut UdpStream, source: IpEndpoint, id: u16) -> bool {
        if !self.has_response() {
            self.add_client(source, id);
            return true;
        }

        let ttl = self.expire - Instant::now();
        for record in self.message.answers_mut() {
            record.set_ttl(ttl.as_secs() as u32);
        }
        self.message.set_id(id);
        let _ = stream
            .send(self.message.to_vec().unwrap().as_slice(), source)
            .await;
        ttl.is_zero()
    }
}
