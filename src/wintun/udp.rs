use crate::{
    proto::{TrojanRequest, UdpAssociate, UdpParseResultEndpoint, UDP_ASSOCIATE},
    proxy::IdlePool,
    resolver::DnsResolver,
    status::StatusProvider,
    tls_conn::TlsConn,
    wintun::{CHANNEL_CNT, CHANNEL_UDP, MAX_INDEX, MIN_INDEX},
    OPTIONS,
};
use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{
    socket::{SocketHandle, SocketRef, SocketSet, UdpSocket},
    wire::IpEndpoint,
};
use std::{collections::HashMap, sync::Arc};

pub struct UdpServer {
    src_map: HashMap<SocketHandle, Arc<UdpListener>>,
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
        }
    }

    pub fn index2token(index: usize) -> Token {
        Token(index * CHANNEL_CNT + CHANNEL_UDP)
    }

    pub fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        handles: Vec<SocketHandle>,
        sockets: &mut SocketSet,
    ) {
        for handle in handles {
            let listener = if let Some(listener) = self.src_map.get_mut(&handle) {
                listener
            } else {
                let endpoint = sockets.get::<UdpSocket>(handle).endpoint();
                let listener = Arc::new(UdpListener::new(handle, endpoint));
                self.src_map.insert(handle, listener);
                self.src_map.get_mut(&handle).unwrap()
            };
            let mut_listener = unsafe { Arc::get_mut_unchecked(listener) };
            let indexes = mut_listener.do_local(pool, poll, resolver, sockets);
            for index in indexes {
                self.conns.insert(index, listener.clone());
            }
        }
    }

    pub fn do_remote(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        log::debug!("remote event for token:{}", event.token().0);
        let index = Self::token2index(event.token());
        if let Some(listener) = self.conns.get_mut(&index) {
            let listener = unsafe { Arc::get_mut_unchecked(listener) };
            listener.ready(event, poll, sockets);
            if listener.src_map.is_empty() {
                log::info!("remove udp endpoint:{}", listener.endpoint);
                sockets.remove(listener.handle);
                let _ = self.src_map.remove(&listener.handle);
                let _ = self.conns.remove(&index);
            }
        } else {
            log::error!("connection:{} not found in udp server", index);
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
        resolver: &DnsResolver,
        sockets: &mut SocketSet,
    ) -> Vec<usize> {
        let mut socket = sockets.get::<UdpSocket>(self.handle);
        let mut indexes = Vec::new();
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
                            indexes.push(index);
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
                    conn.send_request(payload, self.endpoint);
                }
                Err(err) => {
                    log::info!("read from udp socket failed:{}", err);
                    break;
                }
            }
        }
        indexes
    }

    fn ready(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        let index = UdpServer::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.ready(event, poll, sockets);
            if conn.destroyed() {
                let _ = self.src_map.remove(&conn.src_endpoint);
                let _ = self.conns.remove(&index);
                log::info!("connection:{} removed", index);
            }
        } else {
            log::warn!("connection:{} not found", index);
        }
    }
}

struct Connection {
    index: usize,
    conn: TlsConn,
    handle: SocketHandle,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    src_endpoint: IpEndpoint,
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
            send_buffer: Default::default(),
            recv_buffer: Default::default(),
        }
    }

    pub(crate) fn destroyed(&self) -> bool {
        //TODO
        self.conn.deregistered()
    }

    fn send_request(&mut self, payload: &[u8], target: IpEndpoint) {
        if !self.conn.is_connecting() && !self.conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        log::info!("sending request to remote");
        self.recv_buffer.clear();
        UdpAssociate::generate_endpoint(&mut self.recv_buffer, &target, payload.len() as u16);
        if self.conn.write_session(self.recv_buffer.as_ref()) {
            self.conn.write_session(payload);
        }

        self.conn.do_send();
    }

    fn ready(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        if event.is_readable() {
            self.send_response(sockets);
        } else {
            self.conn.established();
            self.conn.do_send();
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
        let mut socket = sockets.get::<UdpSocket>(self.handle);
        loop {
            match UdpAssociate::parse_endpoint(buffer) {
                UdpParseResultEndpoint::Continued => {
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
                UdpParseResultEndpoint::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    self.do_send_udp_smoltcp(self.src_endpoint, payload, &mut socket);
                    //self.do_send_udp(packet.address, payload);
                    buffer = &packet.payload[packet.length..];
                }
                UdpParseResultEndpoint::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index);
                    self.conn.shutdown();
                    break;
                }
            }
        }
    }

    fn do_send_udp_smoltcp(
        &mut self,
        endpoint: IpEndpoint,
        data: &[u8],
        socket: &mut SocketRef<UdpSocket>,
    ) {
        log::info!("send response to:{}", endpoint);
        if socket.can_send() {
            if let Err(err) = socket.send_slice(data, endpoint) {
                log::error!("send to local failed:{}", err);
            }
        } else {
            log::warn!("udp socket buffer is full");
        }
    }
}
