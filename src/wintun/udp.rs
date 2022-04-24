use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Write},
    sync::Arc,
    time::Instant,
};

use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{iface::SocketHandle, socket::UdpSocket, wire::IpEndpoint, Error};

use crate::{
    proto::{TrojanRequest, UdpAssociate, UdpParseResultEndpoint, UDP_ASSOCIATE},
    proxy::IdlePool,
    resolver::DnsResolver,
    status::StatusProvider,
    tls_conn::TlsConn,
    wintun::{waker::Wakers, SocketSet, CHANNEL_CNT, CHANNEL_UDP, MAX_INDEX, MIN_INDEX},
    OPTIONS,
};

pub struct UdpServer {
    src_map: HashMap<SocketHandle, Arc<UdpListener>>,
    sockets: HashSet<IpEndpoint>,
    conns: HashMap<usize, Arc<UdpListener>>,
}

fn next_index() -> usize {
    static mut NEXT_INDEX: usize = MIN_INDEX;
    unsafe {
        let index = NEXT_INDEX;
        NEXT_INDEX += 1;
        if NEXT_INDEX >= MAX_INDEX {
            NEXT_INDEX = MIN_INDEX;
        }
        index
    }
}

impl UdpServer {
    pub fn new() -> UdpServer {
        UdpServer {
            src_map: Default::default(),
            conns: Default::default(),
            sockets: Default::default(),
        }
    }

    pub fn index2token(index: usize) -> Token {
        Token(index * CHANNEL_CNT + CHANNEL_UDP)
    }

    pub fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub fn new_socket(&mut self, endpoint: IpEndpoint) -> bool {
        if self.sockets.contains(&endpoint) {
            false
        } else {
            self.sockets.insert(endpoint);
            true
        }
    }

    pub fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        wakers: &mut Wakers,
        sockets: &mut SocketSet,
    ) {
        for (handle, event) in wakers.get_events().iter() {
            let handle = *handle;
            let listener = if let Some(listener) = self.src_map.get_mut(&handle) {
                listener
            } else {
                let endpoint = sockets.get_socket::<UdpSocket>(handle).endpoint();
                let listener = Arc::new(UdpListener::new(handle, endpoint));
                self.src_map.insert(handle, listener);
                self.src_map.get_mut(&handle).unwrap()
            };
            let mut_listener = unsafe { Arc::get_mut_unchecked(listener) };
            let (inserts, removes) = mut_listener.do_local(pool, poll, event, resolver, sockets);
            for index in inserts {
                self.conns.insert(index, listener.clone());
            }
            for index in &removes {
                self.conns.remove(index);
            }
            let (rx, tx) = wakers.get_wakers(handle);
            let socket = sockets.get_socket::<UdpSocket>(handle);
            if event.is_readable() {
                socket.register_recv_waker(rx);
            }
            if listener.has_data() {
                socket.register_send_waker(tx);
            }
        }
    }

    pub fn do_remote(
        &mut self,
        event: &Event,
        poll: &Poll,
        sockets: &mut SocketSet,
        wakers: &mut Wakers,
    ) {
        log::debug!("remote event for token:{}", event.token().0);
        let index = Self::token2index(event.token());
        if let Some(listener) = self.conns.get_mut(&index) {
            let listener = unsafe { Arc::get_mut_unchecked(listener) };
            if let Some(index) = listener.ready(event, poll, sockets, wakers) {
                let _ = self.conns.remove(&index);
            }
        } else {
            log::error!("connection:{} not found in udp server", index);
        }
    }

    pub fn check_timeout(&mut self, now: Instant, sockets: &mut SocketSet) {
        let timeouts: Vec<_> = self
            .conns
            .iter_mut()
            .map(|(_, conn)| unsafe { Arc::get_mut_unchecked(conn).check_timeout(now) })
            .collect();

        for to in &timeouts {
            for (index, _) in to {
                let _ = self.conns.remove(index);
            }
        }

        let timeouts: Vec<_> = self
            .src_map
            .iter()
            .filter_map(|(_, conn)| {
                if conn.is_empty() {
                    Some((conn.handle, conn.endpoint))
                } else {
                    None
                }
            })
            .collect();

        for (handle, endpoint) in timeouts {
            log::info!("udp socket:{} removed", handle);
            let _ = self.src_map.remove(&handle);
            let _ = self.sockets.remove(&endpoint);
            let _ = sockets.remove_socket(handle);
        }
    }
}

struct UdpListener {
    handle: SocketHandle,
    src_map: HashMap<IpEndpoint, Arc<Connection>>,
    conns: HashMap<usize, Arc<Connection>>,
    endpoint: IpEndpoint,
}

impl UdpListener {
    fn new(handle: SocketHandle, endpoint: IpEndpoint) -> Self {
        Self {
            handle,
            endpoint,
            src_map: HashMap::new(),
            conns: HashMap::new(),
        }
    }

    pub(crate) fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        event: &crate::wintun::waker::Event,
        resolver: &DnsResolver,
        sockets: &mut SocketSet,
    ) -> (Vec<usize>, Vec<usize>) {
        let socket = sockets.get_socket::<UdpSocket>(self.handle);
        let mut inserts = Vec::new();
        let mut removes = Vec::new();
        if event.is_readable() {
            self.do_read_client(socket, pool, poll, resolver, &mut inserts, &mut removes);
        }
        if event.is_writable() {
            self.do_send_client(sockets);
        }

        (inserts, removes)
    }

    fn do_send_client(&mut self, sockets: &mut SocketSet) {
        for conn in &mut self.conns.values_mut() {
            unsafe { Arc::get_mut_unchecked(conn) }.send_tun(&[], sockets)
        }
    }

    fn has_data(&self) -> bool {
        self.conns
            .iter()
            .any(|(_, conn)| !conn.send_buffer.is_empty())
    }

    fn do_read_client(
        &mut self,
        socket: &mut UdpSocket,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        inserts: &mut Vec<usize>,
        removes: &mut Vec<usize>,
    ) {
        while socket.can_recv() {
            match socket.recv() {
                Ok((payload, src)) => {
                    log::info!("receive {} bytes request from {}", payload.len(), src);
                    let conn = if let Some(conn) = self.src_map.get_mut(&src) {
                        conn
                    } else if let Some(mut conn) = pool.get(poll, resolver) {
                        log::info!("handle:{} not found, create new connection", self.handle);
                        let index = next_index();
                        if !conn.reset_index(index, UdpServer::index2token(index), poll) {
                            conn.check_status(poll);
                            continue;
                        }

                        let mut conn = Connection::new(index, conn, self.handle, src);
                        if conn.setup() {
                            let conn = Arc::new(conn);
                            let _ = self.src_map.insert(src, conn.clone());
                            let _ = self.conns.insert(index, conn.clone());
                            inserts.push(index);
                            self.conns.get_mut(&index).unwrap()
                        } else {
                            conn.conn.check_status(poll);
                            continue;
                        }
                    } else {
                        log::error!("get connection from idle pool failed");
                        continue;
                    };
                    let conn = unsafe { Arc::get_mut_unchecked(conn) };
                    conn.send_request(payload, self.endpoint, poll);
                    if conn.destroyed() {
                        let index = conn.index;
                        let endpoint = conn.src_endpoint;
                        self.remove_conn(&index, &endpoint);
                        removes.push(index);
                    }
                }
                Err(err) => {
                    log::info!("read from udp socket failed:{}", err);
                    break;
                }
            }
        }
    }

    fn remove_conn(&mut self, index: &usize, endpoint: &IpEndpoint) {
        let _ = self.src_map.remove(endpoint);
        let _ = self.conns.remove(index);
        log::info!("connection:{} removed", index);
    }

    fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    fn ready(
        &mut self,
        event: &Event,
        poll: &Poll,
        sockets: &mut SocketSet,
        wakers: &mut Wakers,
    ) -> Option<usize> {
        let index = UdpServer::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.ready(event, poll, sockets, wakers);
            if conn.destroyed() {
                let index = conn.index;
                let endpoint = conn.src_endpoint;
                self.remove_conn(&index, &endpoint);
                return Some(index);
            }
        } else {
            log::warn!("connection:{} not found", index);
        }
        None
    }

    fn check_timeout(&mut self, now: Instant) -> Vec<(usize, IpEndpoint)> {
        let timeouts: Vec<_> = self
            .conns
            .iter()
            .filter_map(|(index, conn)| {
                if conn.timeout(now) {
                    Some((*index, conn.src_endpoint))
                } else {
                    None
                }
            })
            .collect();
        for (index, endpoint) in &timeouts {
            self.remove_conn(index, endpoint);
        }
        timeouts
    }
}

struct Connection {
    index: usize,
    conn: TlsConn,
    handle: SocketHandle,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    src_endpoint: IpEndpoint,
    last_active_time: Instant,
}

impl Connection {
    fn new(
        index: usize,
        conn: TlsConn,
        handle: SocketHandle,
        src_endpoint: IpEndpoint,
    ) -> Connection {
        Connection {
            index,
            conn,
            handle,
            src_endpoint,
            last_active_time: Instant::now(),
            send_buffer: Default::default(),
            recv_buffer: Default::default(),
        }
    }

    fn timeout(&self, now: Instant) -> bool {
        now - self.last_active_time > OPTIONS.udp_idle_duration
    }

    pub(crate) fn destroyed(&self) -> bool {
        self.conn.deregistered()
    }

    fn send_request(&mut self, payload: &[u8], target: IpEndpoint, poll: &Poll) {
        self.last_active_time = Instant::now();
        if !self.conn.is_connecting() && !self.conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        log::info!("sending request to remote");
        self.recv_buffer.clear();
        UdpAssociate::generate_endpoint(&mut self.recv_buffer, &target, payload.len() as u16);
        self.conn.write(self.recv_buffer.as_ref());
        self.conn.write(payload);
        if self.conn.write_session(self.recv_buffer.as_ref()) {
            self.conn.write_session(payload);
        }

        self.conn.do_send();
        self.conn.check_status(poll);
    }

    fn ready(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet, wakers: &mut Wakers) {
        self.last_active_time = Instant::now();
        if event.is_readable() {
            self.send_response(sockets);
        }

        if event.is_writable() {
            self.conn.established();
            self.conn.do_send();
        }

        if !self.send_buffer.is_empty() {
            let socket = sockets.get_socket::<UdpSocket>(self.handle);
            let (_, tx) = wakers.get_wakers(self.handle);
            socket.register_send_waker(tx);
        }

        self.conn.check_status(poll);
    }

    fn setup(&mut self) -> bool {
        self.recv_buffer.clear();
        TrojanRequest::generate(
            &mut self.recv_buffer,
            UDP_ASSOCIATE,
            OPTIONS.empty_addr.as_ref().unwrap(),
        );
        self.conn.write_session(self.recv_buffer.as_ref())
    }

    fn send_response(&mut self, sockets: &mut SocketSet) {
        if let Some(data) = self.conn.do_read() {
            self.send_tun(data.as_slice(), sockets);
        }
    }

    fn send_tun(&mut self, buffer: &[u8], sockets: &mut SocketSet) {
        if self.send_buffer.is_empty() {
            self.do_send_tun(buffer, sockets);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send_tun(buffer.as_ref(), sockets);
        }
    }

    fn do_send_tun(&mut self, mut buffer: &[u8], sockets: &mut SocketSet) {
        if buffer.is_empty() {
            return;
        }
        let socket = sockets.get_socket::<UdpSocket>(self.handle);
        loop {
            match UdpAssociate::parse_endpoint(buffer) {
                UdpParseResultEndpoint::Continued => {
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
                UdpParseResultEndpoint::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    if self.do_send_udp(self.src_endpoint, payload, socket) {
                        buffer = &packet.payload[packet.length..];
                    } else {
                        self.send_buffer.extend_from_slice(buffer);
                        return;
                    }
                }
                UdpParseResultEndpoint::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index);
                    self.conn.shutdown();
                    break;
                }
            }
        }
    }

    fn do_send_udp(&mut self, endpoint: IpEndpoint, data: &[u8], socket: &mut UdpSocket) -> bool {
        log::info!("send response to:{}", endpoint);
        if socket.can_send() {
            if let Err(err) = socket.send_slice(data, endpoint) {
                log::error!("send to local failed:{}", err);
            } else {
                return true;
            }
        } else {
            log::warn!("udp socket buffer is full to:{}", endpoint);
        }
        false
    }
}
