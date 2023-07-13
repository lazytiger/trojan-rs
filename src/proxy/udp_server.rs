use std::{collections::HashMap, io::ErrorKind, net::SocketAddr, rc::Rc, sync::Arc, time::Instant};

use bytes::BytesMut;
use mio::{event::Event, net::UdpSocket, Poll, Token};

use crate::{
    config::OPTIONS,
    idle_pool::IdlePool,
    proto::{TrojanRequest, UdpAssociate, UdpParseResult, MAX_PACKET_SIZE, UDP_ASSOCIATE},
    proxy::{
        net_profiler::NetProfiler, next_index, udp_cache::UdpSvrCache, CHANNEL_CNT, CHANNEL_UDP,
        MIN_INDEX,
    },
    resolver::DnsResolver,
    status::{ConnStatus, StatusProvider},
    sys,
    tls_conn::TlsConn,
    types::{Result, TrojanError},
};

pub struct UdpServer {
    udp_listener: UdpSocket,
    conns: HashMap<usize, Arc<Connection>>,
    src_map: HashMap<SocketAddr, Arc<Connection>>,
    removed: Option<Vec<usize>>,
    next_id: usize,
    recv_buffer: Vec<u8>,
}

struct Connection {
    index: usize,
    src_addr: SocketAddr,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    server_conn: TlsConn,
    status: ConnStatus,
    socket: Rc<UdpSocket>,
    dst_addr: SocketAddr,
    bytes_read: usize,
    bytes_sent: usize,
    last_active: Instant,
}

impl UdpServer {
    pub fn new(udp_listener: UdpSocket) -> UdpServer {
        UdpServer {
            udp_listener,
            conns: HashMap::new(),
            src_map: HashMap::new(),
            removed: Some(Vec::new()),
            next_id: MIN_INDEX,
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
        }
    }

    pub fn accept(
        &mut self,
        poll: &Poll,
        pool: &mut IdlePool,
        udp_cache: &mut UdpSvrCache,
        resolver: &DnsResolver,
        net_profiler: &mut NetProfiler,
    ) {
        loop {
            if let Err(err) = self.accept_once(poll, pool, udp_cache, resolver, net_profiler) {
                if let TrojanError::StdIo(err) = &err {
                    if err.kind() == ErrorKind::WouldBlock {
                        break;
                    }
                }
                log::error!("accept udp data failed:{:?}", err);
            }
        }
    }

    fn accept_once(
        &mut self,
        poll: &Poll,
        pool: &mut IdlePool,
        udp_cache: &mut UdpSvrCache,
        resolver: &DnsResolver,
        net_profiler: &mut NetProfiler,
    ) -> Result<()> {
        let (size, src_addr, dst_addr) =
            sys::recv_from_with_destination(&self.udp_listener, self.recv_buffer.as_mut_slice())?;
        net_profiler.check(dst_addr.ip());
        log::debug!(
            "udp received {} byte from {} to {}",
            size,
            src_addr,
            dst_addr
        );
        let mut conn = if let Some(conn) = self.src_map.get(&src_addr) {
            log::debug!(
                "connection:{} already exists for address{}",
                conn.index,
                src_addr
            );
            conn.clone()
        } else {
            log::debug!(
                "address:{} not found, connecting to {}",
                src_addr,
                OPTIONS.back_addr.as_ref().unwrap()
            );
            if let Some(mut conn) = pool.get(poll, resolver) {
                if let Some(socket) = udp_cache.get_socket(dst_addr) {
                    let index = next_index(&mut self.next_id);
                    if !conn.reset_index(index, Token(index * CHANNEL_CNT + CHANNEL_UDP), poll) {
                        conn.check_status(poll);
                        return Ok(());
                    }
                    let mut conn = Connection::new(index, conn, src_addr, socket);
                    if conn.setup() {
                        let conn = Arc::new(conn);
                        let _ = self.conns.insert(index, conn.clone());
                        self.src_map.insert(src_addr, conn.clone());
                        log::debug!("connection:{} is ready", index);
                        conn
                    } else {
                        conn.check_status(poll);
                        return Ok(());
                    }
                } else {
                    conn.shutdown();
                    conn.check_status(poll);
                    return Ok(());
                }
            } else {
                log::error!("allocate connection failed");
                return Ok(());
            }
        };
        let payload = &self.recv_buffer.as_slice()[..size];
        unsafe { Arc::get_mut_unchecked(&mut conn) }.send_request(payload, &dst_addr, poll);
        if conn.destroyed() {
            self.removed.as_mut().unwrap().push(conn.index);
        }
        Ok(())
    }

    pub fn ready(&mut self, event: &Event, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        let index = Connection::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            unsafe { Arc::get_mut_unchecked(conn) }.ready(event, poll, udp_cache);
            if conn.destroyed() {
                self.removed.as_mut().unwrap().push(index);
            }
        } else {
            log::error!("udp connection:{} not found, check deregister", index);
        }
    }

    pub fn remove_closed(&mut self) {
        if self.removed.as_ref().unwrap().is_empty() {
            return;
        }
        let removed = self.removed.replace(Vec::new()).unwrap();
        for index in removed {
            let mut src_addr = None;
            if let Some(conn) = self.conns.get(&index) {
                src_addr = Some(conn.src_addr);
            }
            if let Some(src_addr) = src_addr {
                self.conns.remove(&index);
                self.src_map.remove(&src_addr);
                log::debug!("connection:{} removed from list", index);
            }
        }
    }
}

impl Connection {
    fn new(
        index: usize,
        server_conn: TlsConn,
        src_addr: SocketAddr,
        socket: Rc<UdpSocket>,
    ) -> Connection {
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
            bytes_read: 0,
            bytes_sent: 0,
            last_active: Instant::now(),
        }
    }

    fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    fn setup(&mut self) -> bool {
        self.recv_buffer.clear();
        TrojanRequest::generate(
            &mut self.recv_buffer,
            UDP_ASSOCIATE,
            OPTIONS.empty_addr.as_ref().unwrap(),
        );
        self.server_conn.write_session(self.recv_buffer.as_ref())
    }

    fn destroyed(&self) -> bool {
        self.deregistered() && self.server_conn.deregistered()
    }

    fn index(&self) -> usize {
        self.index
    }

    fn send_request(&mut self, payload: &[u8], dst_addr: &SocketAddr, poll: &Poll) {
        if self.last_active.elapsed().as_secs() > 120 {
            self.shutdown();
            self.do_status(poll);
            return;
        }
        if !self.server_conn.is_connecting() && !self.server_conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        self.bytes_read += payload.len();
        self.recv_buffer.clear();
        UdpAssociate::generate(&mut self.recv_buffer, dst_addr, payload.len() as u16);
        if self.server_conn.write_session(self.recv_buffer.as_ref()) {
            self.server_conn.write_session(payload);
        }
        self.try_send_server();
        self.do_status(poll);
    }

    fn do_status(&mut self, poll: &Poll) {
        if self.is_shutdown() {
            self.server_conn.peer_closed();
        }
        if self.server_conn.is_shutdown() {
            self.peer_closed();
        }

        self.check_status(poll);
        self.server_conn.check_status(poll);
    }

    fn ready(&mut self, event: &Event, poll: &Poll, udp_cache: &mut UdpSvrCache) {
        self.last_active = Instant::now();
        if event.is_readable() {
            self.try_read_server(udp_cache);
            //It is necessary when establishing connection
            //In the case, user data will be sent only after handshake is done.
            self.server_conn.do_send();
        }
        if event.is_writable() {
            self.server_conn.established();
            self.try_send_server();
        }
        self.do_status(poll);
    }

    fn try_send_server(&mut self) {
        self.server_conn.do_send();
    }

    fn try_read_server(&mut self, udp_cache: &mut UdpSvrCache) {
        if let Some(buffer) = self.server_conn.do_read() {
            self.try_send_client(buffer.as_slice(), udp_cache);
        }
    }

    pub fn try_send_client(&mut self, buffer: &[u8], udp_cache: &mut UdpSvrCache) {
        if self.send_buffer.is_empty() {
            self.do_send_client(buffer, udp_cache);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send_client(buffer.as_ref(), udp_cache);
        }
    }

    fn do_send_udp(&mut self, dst_addr: SocketAddr, data: &[u8], udp_cache: &mut UdpSvrCache) {
        if self.dst_addr != dst_addr {
            log::warn!(
                "connection:{} udp target changed to {}",
                self.index,
                dst_addr
            );
            if let Some(socket) = udp_cache.get_socket(dst_addr) {
                self.socket = socket;
                self.dst_addr = dst_addr;
            } else {
                return;
            }
        }
        match self.socket.send_to(data, self.src_addr) {
            Ok(size) => {
                self.bytes_sent += size;
                log::debug!(
                    "send {} bytes upd data from {} to {}",
                    size,
                    dst_addr,
                    self.src_addr
                );
                if size != data.len() {
                    log::error!("send {} byte to client fragmented to {}", data.len(), size)
                }
            }
            Err(err) => {
                log::error!(
                    "send udp data from {} to {} failed {}",
                    dst_addr,
                    self.src_addr,
                    err
                );
            }
        }
    }

    fn do_send_client(&mut self, mut buffer: &[u8], udp_cache: &mut UdpSvrCache) {
        loop {
            match UdpAssociate::parse(buffer) {
                UdpParseResult::Continued => {
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
                UdpParseResult::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    self.do_send_udp(packet.address.as_socket().unwrap(), payload, udp_cache);
                    buffer = &packet.payload[packet.length..];
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index());
                    self.server_conn.shutdown();
                    break;
                }
            }
        }
    }
}

impl StatusProvider for Connection {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status;
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&mut self) -> bool {
        true
    }

    fn deregister(&mut self, _: &Poll) -> bool {
        true
    }

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
