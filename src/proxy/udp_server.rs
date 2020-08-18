use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use bytes::BytesMut;
use mio::{Event, Poll, Token};
use mio::net::UdpSocket;
use rustls::ClientSession;

use crate::config::Opts;
use crate::proto::{MAX_UDP_SIZE, TrojanRequest, UDP_ASSOCIATE, UdpAssociate, UdpParseResult};
use crate::proxy::{CHANNEL_CNT, CHANNEL_UDP, MIN_INDEX, next_index};
use crate::proxy::idle_pool::IdlePool;
use crate::proxy::udp_cache::UdpSvrCache;
use crate::sys;
use crate::tls_conn::TlsConn;

pub struct UdpServer {
    udp_listener: Rc<UdpSocket>,
    conns: HashMap<usize, Connection>,
    src_map: HashMap<SocketAddr, usize>,
    next_id: usize,
    recv_buffer: Vec<u8>,
}

struct Connection {
    index: usize,
    src_addr: SocketAddr,
    dst_addr: Option<SocketAddr>,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    server_conn: TlsConn<ClientSession>,
    closing: bool,
    closed: bool,
    client_recv: usize,
    client_sent: usize,
    client_time: Instant,
}

impl UdpServer {
    pub fn new(udp_listener: UdpSocket) -> UdpServer {
        UdpServer {
            udp_listener: Rc::new(udp_listener),
            conns: HashMap::new(),
            src_map: HashMap::new(),
            next_id: MIN_INDEX,
            recv_buffer: vec![0u8; MAX_UDP_SIZE],
        }
    }

    pub fn accept(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, pool: &mut IdlePool) {
        if event.readiness().is_readable() {
            loop {
                match sys::recv_from_with_destination(self.udp_listener.as_ref(), self.recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr, dst_addr)) => {
                        if size >= MAX_UDP_SIZE {
                            log::error!("received {} bytes udp packet, ignore now", size);
                            continue;
                        }
                        log::info!("udp received {} byte from {} to {}", size, src_addr, dst_addr);
                        let index = if let Some(index) = self.src_map.get(&src_addr) {
                            log::debug!("connection:{} already exists for address{}", index, src_addr);
                            *index
                        } else {
                            log::debug!("address:{} not found, connecting to {}", src_addr, opts.back_addr.as_ref().unwrap());
                            if let Some(mut conn) = pool.get(poll) {
                                let index = next_index(&mut self.next_id);
                                conn.reset_index(index, Token(index * CHANNEL_CNT + CHANNEL_UDP));
                                let mut conn = Connection::new(index, conn, src_addr);
                                if conn.setup(opts, poll) {
                                    let _ = self.conns.insert(index, conn);
                                    self.src_map.insert(src_addr, index);
                                    log::info!("connection:{} is ready", index);
                                    index
                                } else {
                                    conn.close_now(poll);
                                    continue;
                                }
                            } else {
                                log::error!("allocate connection failed");
                                continue;
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
        if let Some(conn) = self.conns.get_mut(&index) {
            conn.ready(event, opts, poll, udp_cache);
            if conn.is_closed() {
                let src_addr = conn.src_addr;
                self.conns.remove(&index);
                self.src_map.remove(&src_addr);
            }
        }
    }
}

impl Connection {
    fn new(index: usize, server_conn: TlsConn<ClientSession>, src_addr: SocketAddr) -> Connection {
        Connection {
            index,
            src_addr,
            dst_addr: None,
            server_conn,
            send_buffer: BytesMut::new(),
            recv_buffer: BytesMut::new(),
            closing: false,
            closed: false,
            client_recv: 0,
            client_sent: 0,
            client_time: Instant::now(),
        }
    }

    fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    fn setup(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        self.server_conn.reregister(poll, true);
        self.recv_buffer.clear();
        TrojanRequest::generate(&mut self.recv_buffer, UDP_ASSOCIATE, opts.empty_addr.as_ref().unwrap(), opts);
        self.server_conn.write_session(self.recv_buffer.as_ref())
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn index(&self) -> usize {
        self.index
    }

    fn send_request(&mut self, payload: &[u8], dst_addr: &SocketAddr) {
        if self.dst_addr.is_none() {
            self.dst_addr.replace(*dst_addr);
        } else if self.dst_addr.as_ref().unwrap() != dst_addr {
            self.dst_addr.replace(*dst_addr);
            let secs = self.client_time.elapsed().as_secs();
            log::warn!("connection:{} changed, target address:{}, {} seconds,  {} bytes read, {} bytes sent",
                self.index(), self.dst_addr.as_ref().unwrap(), secs, self.client_recv, self.client_sent);
            self.client_recv = 0;
            self.client_sent = 0;
            self.client_time = Instant::now();
        }
        self.client_sent += payload.len();
        self.recv_buffer.clear();
        UdpAssociate::generate(&mut self.recv_buffer, dst_addr, payload.len() as u16);
        if !self.server_conn.write_session(self.recv_buffer.as_ref()) {
            self.closing = true;
        } else if !self.server_conn.write_session(payload) {
            self.closing = true;
        } else {
            self.try_send_server();
        }
    }

    fn ready(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        if event.readiness().is_readable() {
            self.try_read_server(opts, udp_cache);
        }

        if event.readiness().is_writable() {
            self.try_send_server();
        }

        self.reregister(poll);
        if self.closing || self.server_conn.closing() {
            self.close_now(poll);
        }
    }

    fn close_now(&mut self, poll: &Poll) {
        self.server_conn.close_now(poll);
        self.closed = true;
        let secs = self.client_time.elapsed().as_secs();
        log::warn!("connection:{} closed, target address:{}, {} seconds,  {} bytes read, {} bytes sent",
            self.index(), self.dst_addr.as_ref().unwrap(), secs, self.client_recv, self.client_sent);
    }

    fn reregister(&mut self, poll: &Poll) {
        if self.closing {
            return;
        }
        self.server_conn.reregister(poll, false);
    }

    fn try_send_server(&mut self) {
        self.server_conn.do_send();
    }

    fn try_read_server(&mut self, opts: &mut Opts, udp_cache: &mut UdpSvrCache) {
        if let Some(buffer) = self.server_conn.do_read() {
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
                    self.client_recv += packet.length;
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