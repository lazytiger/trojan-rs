use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;

use bytes::BytesMut;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::TcpStream;
use mio::net::UdpSocket;
use rustls::{ClientConfig, ClientSession, Session};
use webpki::DNSName;

use crate::config::Opts;
use crate::proto::{MAX_UDP_SIZE, TrojanRequest, UDP_ASSOCIATE, UdpAssociate, UdpParseResult};
use crate::proxy::{MAX_INDEX, MIN_INDEX};
use crate::proxy::udp_cache::UdpSvrCache;
use crate::sys;

pub struct UdpServer {
    udp_listener: Rc<UdpSocket>,
    conns: HashMap<usize, Connection>,
    src_map: HashMap<SocketAddr, usize>,
    next_id: usize,
    recv_buffer: Vec<u8>,
    config: Arc<ClientConfig>,
    hostname: DNSName,
}

struct Connection {
    index: usize,
    src_addr: SocketAddr,
    server_session: ClientSession,
    server: TcpStream,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    server_readiness: Ready,
    closing: bool,
    closed: bool,
    client_recv: usize,
    client_sent: usize,
}

impl UdpServer {
    pub fn new(udp_listener: UdpSocket, config: Arc<ClientConfig>, hostname: DNSName) -> UdpServer {
        UdpServer {
            udp_listener: Rc::new(udp_listener),
            config,
            hostname,
            conns: HashMap::new(),
            src_map: HashMap::new(),
            next_id: MIN_INDEX,
            recv_buffer: vec![0u8; MAX_UDP_SIZE],
        }
    }

    pub fn accept(&mut self, event: &Event, opts: &mut Opts, poll: &Poll) {
        if event.readiness().is_readable() {
            loop {
                match sys::recv_from_with_destination(self.udp_listener.as_ref(), self.recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr, dst_addr)) => {
                        log::info!("udp received {} byte from {} to {}", size, src_addr, dst_addr);
                        let index = if let Some(index) = self.src_map.get(&src_addr) {
                            log::debug!("connection:{} already exists for address{}", index, src_addr);
                            *index
                        } else {
                            log::debug!("address:{} not found, connecting to {}", src_addr, opts.back_addr.as_ref().unwrap());
                            match TcpStream::connect(opts.back_addr.as_ref().unwrap()) {
                                Ok(stream) => {
                                    if let Err(err) = sys::set_mark(&stream, opts.marker) {
                                        log::error!("set mark failed:{}", err);
                                        continue;
                                    } else if let Err(err) = stream.set_nodelay(true) {
                                        log::error!("set nodelay failed:{}", err);
                                        continue;
                                    } else {
                                        let session = ClientSession::new(&self.config, self.hostname.as_ref());
                                        let mut conn = Connection::new(self.next_index(), src_addr, session, stream);
                                        if conn.setup(opts, poll) {
                                            let index = conn.index();
                                            let _ = self.conns.insert(index, conn);
                                            self.src_map.insert(src_addr, index);
                                            log::info!("connection:{} is ready", index);
                                            index
                                        } else {
                                            continue;
                                        }
                                    }
                                }
                                Err(err) => {
                                    log::error!("connection to back server failed:{}", err);
                                    //FIXME should update dns now?
                                    continue;
                                }
                            }
                        };
                        if let Some(conn) = self.conns.get_mut(&index) {
                            let payload = &self.recv_buffer.as_slice()[..size];
                            conn.send_request(payload, &dst_addr);
                        } else {
                            log::error!("impossible, connection should be found now");
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        log::debug!("udp server got no more data");
                        break;
                    }
                    Err(err) => {
                        log::error!("recv from udp listener failed:{}", err);
                        break;
                    }
                }
            }
        }
    }

    pub fn ready(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        let index = Connection::token2index(event.token());
        let src_addr = if let Some(conn) = self.conns.get_mut(&index) {
            conn.ready(event, opts, poll, udp_cache);
            if !conn.is_closed() {
                return;
            }
            conn.src_addr
        } else {
            return;
        };
        self.conns.remove(&index);
        self.src_map.remove(&src_addr);
    }

    pub fn next_index(&mut self) -> usize {
        let index = self.next_id;
        self.next_id += 1;
        if self.next_id >= MAX_INDEX {
            self.next_id = MIN_INDEX;
        }
        index
    }
}

impl Connection {
    fn new(index: usize, src_addr: SocketAddr, session: ClientSession, stream: TcpStream) -> Connection {
        Connection {
            index,
            src_addr,
            server_session: session,
            server: stream,
            send_buffer: BytesMut::new(),
            recv_buffer: BytesMut::new(),
            server_readiness: Ready::readable() | Ready::writable(),
            closing: false,
            closed: false,
            client_recv: 0,
            client_sent: 0,
        }
    }

    fn server_token(&self) -> Token {
        Token(self.index * 3)
    }

    fn token2index(token: Token) -> usize {
        token.0 / 3
    }

    fn setup(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        self.recv_buffer.clear();
        TrojanRequest::generate(&mut self.recv_buffer, UDP_ASSOCIATE, opts.empty_addr.as_ref().unwrap(), opts);
        if let Err(err) = self.server_session.write_all(self.recv_buffer.as_ref()) {
            log::warn!("connection:{} write handshake to server session failed:{}", self.index(), err);
            false
        } else if let Err(err) = poll.register(&self.server, self.server_token(), self.server_readiness, PollOpt::level()) {
            log::warn!("connection:{} register failed:{}", self.index(), err);
            false
        } else {
            true
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn index(&self) -> usize {
        self.index
    }

    fn send_request(&mut self, payload: &[u8], dst_addr: &SocketAddr) {
        self.client_sent += payload.len();
        self.recv_buffer.clear();
        UdpAssociate::generate(&mut self.recv_buffer, dst_addr, payload.len() as u16);
        if let Err(err) = self.server_session.write_all(self.recv_buffer.as_ref()) {
            log::error!("connection:{} write header to server failed:{}", self.index(), err);
            self.closing = true;
        } else if let Err(err) = self.server_session.write_all(payload) {
            log::error!("connection:{} write body to server failed:{}", self.index(), err);
            self.closing = true;
        } else {
            self.try_send_server();
        }
    }

    fn ready(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        if event.readiness().is_writable() {
            self.try_send_server();
        }

        if event.readiness().is_readable() {
            self.try_read_server(opts, udp_cache);
        }

        self.reregister(poll);
        if self.closing {
            self.close_now(poll);
        }
    }

    fn close_now(&mut self, poll: &Poll) {
        let _ = poll.deregister(&self.server);
        let _ = self.server.shutdown(Shutdown::Both);
        self.closed = true;
        log::warn!("connection:{} closed, {} bytes read, {} bytes sent", self.index(), self.client_recv, self.client_sent);
    }

    fn reregister(&mut self, poll: &Poll) {
        let mut changed = false;
        if self.server_session.wants_write() && !self.server_readiness.is_writable() {
            self.server_readiness.insert(Ready::writable());
            changed = true;
        }
        if !self.server_session.wants_write() && self.server_readiness.is_writable() {
            self.server_readiness.remove(Ready::writable());
            changed = true;
        }

        if changed {
            if let Err(err) = poll.reregister(&self.server, self.server_token(), self.server_readiness, PollOpt::level()) {
                self.closing = true;
                log::error!("connection:{} reregister failed:{}", self.index(), err);
            }
        }
    }

    fn try_send_server(&mut self) {
        log::info!("connection:{} trying to send udp bytes to server", self.index());
        loop {
            if !self.server_session.wants_write() {
                break;
            }
            match self.server_session.write_tls(&mut self.server) {
                Ok(size) => {
                    log::info!("connection:{} write {} bytes to server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::warn!("connection:{} write to server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} write to server failed:{}", self.index(), err);
                    self.closing = true;
                    break;
                }
            }
        }
        log::info!("connection:{} send udp bytes to server finished", self.index());
    }

    fn try_read_server(&mut self, opts: &mut Opts, udp_cache: &mut UdpSvrCache) {
        loop {
            match self.server_session.read_tls(&mut self.server) {
                Ok(size) => {
                    if size == 0 {
                        log::warn!("connection:{} read from server failed with eof", self.index());
                        self.closing = true;
                        return;
                    }
                    log::info!("connection:{} read {} bytes from server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} read from server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} read from server failed:{}", self.index(), err);
                    self.closing = true;
                    return;
                }
            }
        }

        if let Err(err) = self.server_session.process_new_packets() {
            log::warn!("connection:{} process new packets failed:{}", self.index(), err);
            self.closing = true;
            return;
        }

        let mut buffer = Vec::new();
        if let Err(err) = self.server_session.read_to_end(&mut buffer) {
            log::warn!("connection:{} read from session failed:{}", self.index(), err);
            self.closing = true;
            return;
        }

        if !buffer.is_empty() {
            self.client_recv += buffer.len();
            self.try_send_client(buffer.as_slice(), opts, udp_cache);
        }
    }

    pub fn try_send_client(&mut self, buffer: &[u8], opts: &mut Opts, udp_cache: &mut UdpSvrCache) {
        if self.send_buffer.is_empty() {
            self.do_send_client(buffer, opts, udp_cache);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send_client(buffer.as_ref(), opts, udp_cache);
        }
    }

    fn do_send_client(&mut self, mut buffer: &[u8], opts: &mut Opts, udp_cache: &mut UdpSvrCache) {
        loop {
            match UdpAssociate::parse(buffer, opts) {
                UdpParseResult::Continued => {
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
                UdpParseResult::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    udp_cache.send_to(self.src_addr, packet.address, payload);
                    buffer = &packet.payload[packet.length..];
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index());
                    self.closing = true;
                    break;
                }
            }
        }
    }
}