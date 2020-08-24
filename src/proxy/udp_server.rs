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
use crate::proto::{MAX_BUFFER_SIZE, MAX_PACKET_SIZE, TrojanRequest, UDP_ASSOCIATE, UdpAssociate, UdpParseResult};
use crate::proxy::{CHANNEL_CNT, CHANNEL_UDP, MIN_INDEX, next_index};
use crate::proxy::idle_pool::IdlePool;
use crate::proxy::udp_cache::UdpSvrCache;
use crate::sys;
use crate::tls_conn::{ConnStatus, TlsConn};

pub struct UdpServer {
    udp_listener: UdpSocket,
    conns: HashMap<usize, Connection>,
    src_map: HashMap<SocketAddr, usize>,
    next_id: usize,
    recv_buffer: Vec<u8>,
}

struct Connection {
    index: usize,
    src_addr: SocketAddr,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    server_conn: TlsConn<ClientSession>,
    status: ConnStatus,
    client_time: Instant,
    socket: Rc<UdpSocket>,
    dst_addr: SocketAddr,
    bytes_read: usize,
    bytes_sent: usize,
}

impl UdpServer {
    pub fn new(udp_listener: UdpSocket) -> UdpServer {
        UdpServer {
            udp_listener,
            conns: HashMap::new(),
            src_map: HashMap::new(),
            next_id: MIN_INDEX,
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
        }
    }

    pub fn accept(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, pool: &mut IdlePool, udp_cache: &mut UdpSvrCache) {
        if event.readiness().is_readable() {
            loop {
                match sys::recv_from_with_destination(&self.udp_listener, self.recv_buffer.as_mut_slice()) {
                    Ok((size, src_addr, dst_addr)) => {
                        if size == MAX_PACKET_SIZE {
                            log::error!("received {} bytes udp data, packet fragmented", size);
                        }
                        log::debug!("udp received {} byte from {} to {}", size, src_addr, dst_addr);
                        let index = if let Some(index) = self.src_map.get(&src_addr) {
                            log::debug!("connection:{} already exists for address{}", index, src_addr);
                            *index
                        } else {
                            log::debug!("address:{} not found, connecting to {}", src_addr, opts.back_addr.as_ref().unwrap());
                            if let Some(mut conn) = pool.get(poll) {
                                let index = next_index(&mut self.next_id);
                                conn.reset_index(index, Token(index * CHANNEL_CNT + CHANNEL_UDP));
                                let mut conn = Connection::new(index, conn, src_addr, udp_cache.get_socket(dst_addr));
                                if conn.setup(opts, poll) {
                                    let _ = self.conns.insert(index, conn);
                                    self.src_map.insert(src_addr, index);
                                    log::debug!("connection:{} is ready", index);
                                    index
                                } else {
                                    conn.shutdown(poll);
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
            if conn.destroyed() {
                let src_addr = conn.src_addr;
                self.conns.remove(&index);
                self.src_map.remove(&src_addr);
                log::debug!("connection:{} removed from list", index);
            }
        }
    }
}

impl Connection {
    fn new(index: usize, server_conn: TlsConn<ClientSession>, src_addr: SocketAddr, socket: Rc<UdpSocket>) -> Connection {
        let dst_addr = socket.local_addr().unwrap();
        Connection {
            index,
            src_addr,
            server_conn,
            socket,
            dst_addr,
            send_buffer: BytesMut::new(),
            recv_buffer: BytesMut::new(),
            status: ConnStatus::Established,
            client_time: Instant::now(),
            bytes_read: 0,
            bytes_sent: 0,
        }
    }

    fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    fn setup(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        self.server_conn.setup(poll);
        self.recv_buffer.clear();
        TrojanRequest::generate(&mut self.recv_buffer, UDP_ASSOCIATE, opts.empty_addr.as_ref().unwrap(), opts);
        self.server_conn.write_session(self.recv_buffer.as_ref())
    }

    fn destroyed(&self) -> bool {
        self.closed() && self.server_conn.closed()
    }

    fn closed(&self) -> bool {
        if let ConnStatus::Closed = self.status {
            true
        } else {
            false
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn send_request(&mut self, payload: &[u8], dst_addr: &SocketAddr) {
        if !self.server_conn.writable() {
            log::warn!("connection:{} too many packets, drop udp packet", self.index);
            return;
        }
        self.bytes_read += payload.len();
        self.recv_buffer.clear();
        UdpAssociate::generate(&mut self.recv_buffer, dst_addr, payload.len() as u16);
        if !self.server_conn.write_session(self.recv_buffer.as_ref()) {
            self.status = ConnStatus::Closing;
        } else if !self.server_conn.write_session(payload) {
            self.status = ConnStatus::Closing;
        }
        self.try_send_server();
    }

    fn shutdown(&mut self, poll: &Poll) {
        log::debug!("connection:{} shutdown now", self.index());
        if self.send_buffer.is_empty() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }
        self.status = ConnStatus::Shutdown;
    }

    fn ready(&mut self, event: &Event, opts: &mut Opts, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        if event.readiness().is_readable() {
            self.try_read_server(opts, udp_cache);
        }
        if event.readiness().is_writable() {
            self.try_send_server();
        }

        self.reregister(poll);
        self.check_close(poll);
        self.server_conn.reregister(poll, self.readable());
        self.server_conn.check_close(poll);
        if self.closed() && !self.server_conn.closed() {
            self.server_conn.shutdown(poll);
        } else if !self.closed() && self.server_conn.closed() {
            self.shutdown(poll);
        }
    }

    fn readable(&self) -> bool {
        self.send_buffer.len() < MAX_BUFFER_SIZE
    }

    fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            self.close_now(poll);
        }
    }

    fn close_now(&mut self, _: &Poll) {
        self.status = ConnStatus::Closed;
        let secs = self.client_time.elapsed().as_secs();
        log::info!("connection:{} address:{} closed, time:{} read {} bytes, send {} bytes", self.index(), self.dst_addr, secs, self.bytes_read, self.bytes_sent);
    }

    fn reregister(&mut self, _: &Poll) {}

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

    fn do_send_udp(&mut self, dst_addr: SocketAddr, data: &[u8], udp_cache: &mut UdpSvrCache) {
        if self.dst_addr != dst_addr {
            log::warn!("connection:{} udp target changed to {}", self.index, dst_addr);
            self.socket = udp_cache.get_socket(dst_addr);
            self.dst_addr = dst_addr;
        }
        match self.socket.send_to(data, &self.src_addr) {
            Ok(size) => {
                self.bytes_sent += size;
                log::debug!("send {} bytes upd data from {} to {}", size, dst_addr, self.src_addr);
                if size != data.len() {
                    log::error!("send {} byte to client fragmented to {}", data.len(), size)
                }
            }
            Err(err) => {
                log::error!("send udp data from {} to {} failed {}", dst_addr, self.src_addr, err);
            }
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
                    self.do_send_udp(packet.address, payload, udp_cache);
                    buffer = &packet.payload[packet.length..];
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index());
                    self.status = ConnStatus::Closing;
                    break;
                }
            }
        }
        if let ConnStatus::Shutdown = self.status {
            if self.send_buffer.is_empty() {
                self.status = ConnStatus::Closing;
                log::debug!("connection:{} is closing for no data to send", self.index);
            }
        }
    }
}