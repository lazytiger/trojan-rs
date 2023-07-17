use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::{Buf, BytesMut};
use rustls::{ClientConfig, ServerName};
use smoltcp::wire::IpEndpoint;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    spawn,
    sync::mpsc::Sender,
};
use trust_dns_proto::{op::Message, serialize::binary::BinDecodable};

use tokio_rustls::{TlsClientReadHalf, TlsClientWriteHalf};

use crate::atun::{
    init_tls_conn,
    proto::{UdpAssociate, UdpParseResultEndpoint},
};

pub async fn start_trust_response(
    sender: Sender<Response>,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    request: Arc<BytesMut>,
) -> Option<TlsClientWriteHalf> {
    if let Ok(client) = init_tls_conn(config, server_addr, server_name).await {
        let (read_half, mut write_half) = client.into_split();
        if let Err(err) = write_half.write_all(request.as_ref()).await {
            log::error!("send handshake to remote server failed:{}", err);
            None
        } else {
            spawn(do_trust_response(sender, read_half));
            Some(write_half)
        }
    } else {
        None
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

enum SelectResult {
    Socket(std::io::Result<(IpEndpoint, BytesMut)>),
    Receiver(Option<Response>),
}

pub async fn start_dns(
    mut local: async_smoltcp::UdpSocket,
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
    request: Arc<BytesMut>,
    trusted_addr: SocketAddr,
    distrusted_addr: SocketAddr,
    blocked_domains: HashSet<String>,
) {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1024);
    let mut distrust = start_distrust_response(sender.clone()).await.unwrap();
    let mut trust = start_trust_response(
        sender.clone(),
        config.clone(),
        server_addr,
        server_name.clone(),
        request.clone(),
    )
    .await
    .unwrap();
    let mut dns_store = HashMap::new();

    loop {
        let ret = tokio::select! {
            req = local.recv_from() => {
                SelectResult::Socket(req)

            },
            resp = receiver.recv() => {
                SelectResult::Receiver(resp)
            }
        };
        match ret {
            SelectResult::Socket(req) => match req {
                Ok((source, data)) => {
                    if let Ok(message) = Message::from_bytes(&data.as_ref()) {
                        if message.query_count() != 1 {
                            continue;
                        }
                        let key = get_message_key(&message);
                        if dns_store
                            .entry(key)
                            .or_insert_with(|| DnsItem::new(message.clone()))
                            .respond(&mut local, source, message.id())
                            .await
                        {
                            let name = message.query().unwrap().name().to_utf8();
                            if is_blocked(&blocked_domains, &name) {
                                let mut header = BytesMut::new();
                                UdpAssociate::generate(
                                    &mut header,
                                    &trusted_addr,
                                    data.len() as u16,
                                );
                                if trust.write_all(header.as_ref()).await.is_err()
                                    || trust.write_all(data.as_ref()).await.is_err()
                                {
                                    let _ = trust.shutdown().await;
                                }
                            } else {
                                let _ = distrust.send_to(data.as_ref(), distrusted_addr).await;
                            }
                        }
                    }
                }
                Err(err) => {
                    log::error!("recv from local udp failed:{}", err);
                    break;
                }
            },
            SelectResult::Receiver(resp) => match resp {
                Some(Response::Message(m)) => {
                    let key = get_message_key(&m);
                    dns_store
                        .entry(key)
                        .or_insert_with(|| DnsItem::new(m.clone()))
                        .notify(m, &mut local)
                        .await;
                }
                Some(Response::DistrustClosed) => {
                    distrust = start_distrust_response(sender.clone()).await.unwrap();
                }
                Some(Response::TrustClosed) => {
                    trust = start_trust_response(
                        sender.clone(),
                        config.clone(),
                        server_addr,
                        server_name.clone(),
                        request.clone(),
                    )
                    .await
                    .unwrap();
                }
                None => {
                    log::error!("sender closed, quit now");
                    break;
                }
            },
        }
    }
    panic!("dns routine quit");
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
                } else {
                    log::error!("parse dns response from distrusted failed");
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
    let mut buffer = BytesMut::new();
    'main: loop {
        match remote.read_buf(&mut buffer).await {
            Ok(0) | Err(_) => {
                log::error!("read from trust dns server failed");
                break;
            }
            Ok(_) => loop {
                match UdpAssociate::parse_endpoint(buffer.as_ref()) {
                    UdpParseResultEndpoint::Continued => {
                        break;
                    }
                    UdpParseResultEndpoint::Packet(packet) => {
                        let payload = &packet.payload[..packet.length];
                        if let Ok(message) = Message::from_bytes(payload) {
                            if let Err(_) = sender.send(Response::Message(message)).await {
                                break 'main;
                            }
                        }
                        buffer.advance(packet.offset);
                    }
                    UdpParseResultEndpoint::InvalidProtocol => {
                        log::error!("invalid protocol close now");
                        break 'main;
                    }
                }
            },
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
        if blocked.contains(name.as_str()) {
            log::info!("test domain:{} blocked", name);
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

    pub async fn notify(&mut self, mut message: Message, stream: &mut async_smoltcp::UdpSocket) {
        for (source, id) in std::mem::take(&mut self.clients) {
            message.set_id(id);
            message.take_additionals();
            message.take_name_servers();
            let _ = stream
                .send_to(message.to_vec().unwrap().as_slice(), source)
                .await;
            log::info!("send response to {}", source);
        }
        if let Some(answer) = message.answers().get(0) {
            self.expire = Instant::now() + Duration::from_secs(answer.ttl() as u64);
        }
        self.message = message;
    }

    pub async fn respond(
        &mut self,
        stream: &mut async_smoltcp::UdpSocket,
        source: IpEndpoint,
        id: u16,
    ) -> bool {
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
            .send_to(self.message.to_vec().unwrap().as_slice(), source)
            .await;
        ttl.is_zero()
    }
}
