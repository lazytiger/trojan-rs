use crate::{
    idle_pool::IdlePool,
    proto::{TrojanRequest, CONNECT, MAX_PACKET_SIZE},
    resolver::DnsResolver,
    status::{ConnStatus, StatusProvider},
    tls_conn::TlsConn,
    wintun::{CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX},
    OPTIONS,
};
use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{
    socket::{SocketHandle, SocketRef, SocketSet, TcpSocket, TcpState},
    wire::IpEndpoint,
};
use std::{collections::HashMap, sync::Arc, time::Instant};

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

pub struct TcpServer {
    conns: HashMap<usize, Arc<Connection>>,
    src_map: HashMap<SocketHandle, Arc<Connection>>,
}

impl TcpServer {
    pub fn new() -> Self {
        Self {
            conns: Default::default(),
            src_map: Default::default(),
        }
    }

    pub(crate) fn check_timeout(&mut self, poll: &Poll, now: Instant, sockets: &mut SocketSet) {
        self.conns.iter_mut().for_each(|(_, conn)| unsafe {
            Arc::get_mut_unchecked(conn).check_timeout(poll, now, sockets)
        });
    }

    pub fn index2token(index: usize) -> Token {
        Token(index * CHANNEL_CNT + CHANNEL_TCP)
    }

    pub fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub(crate) fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        handles: Vec<SocketHandle>,
        sockets: &mut SocketSet,
    ) {
        let mut destroyed = Vec::new();
        for handle in handles {
            let conn = if let Some(conn) = self.src_map.get_mut(&handle) {
                conn
            } else if let Some(mut conn) = pool.get(poll, resolver) {
                let index = next_index();
                if !conn.reset_index(index, TcpServer::index2token(index), poll) {
                    conn.check_status(poll);
                    continue;
                }
                let socket = sockets.get::<TcpSocket>(handle);
                let mut conn = Connection::new(conn, handle, index, socket.local_endpoint());
                if !conn.setup() {
                    conn.conn.check_status(poll);
                    continue;
                }
                let conn = Arc::new(conn);
                let _ = self.src_map.insert(handle, conn.clone());
                let _ = self.conns.insert(index, conn);
                self.conns.get_mut(&index).unwrap()
            } else {
                log::error!("get from idle pool failed");
                continue;
            };
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.do_local(poll, sockets);
            if conn.destroyed() {
                destroyed.push((conn.handle, conn.index));
            }
        }
        for (handle, index) in destroyed {
            self.remove_conn(handle, index);
        }
    }

    pub(crate) fn do_remote(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        let index = Self::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.ready(event, poll, sockets);
            if conn.destroyed() {
                let handle = conn.handle;
                let index = conn.index;
                self.remove_conn(handle, index);
            }
        } else {
            log::warn!("connection:{} not found in tcp sockets", index);
        }
    }
    fn remove_conn(&mut self, handle: SocketHandle, index: usize) {
        log::info!("connection:{}-{} removed", handle, index);
        let _ = self.conns.remove(&index);
        let _ = self.src_map.remove(&handle);
    }
}

pub struct Connection {
    conn: TlsConn,
    handle: SocketHandle,
    index: usize,
    endpoint: IpEndpoint,
    recv_buffer: Vec<u8>,
    send_buffer: BytesMut,
    status: ConnStatus,
    last_active_time: Instant,
    closing: bool,
    read_client: bool,
    read_server: bool,
}

impl Connection {}

impl Connection {
    fn new(conn: TlsConn, handle: SocketHandle, index: usize, endpoint: IpEndpoint) -> Self {
        Self {
            conn,
            handle,
            endpoint,
            index,
            last_active_time: Instant::now(),
            closing: false,
            read_server: false,
            read_client: false,
            status: ConnStatus::Connecting,
            recv_buffer: vec![0; MAX_PACKET_SIZE],
            send_buffer: BytesMut::new(),
        }
    }

    pub(crate) fn check_timeout(&mut self, poll: &Poll, now: Instant, sockets: &mut SocketSet) {
        if self.timeout(now) {
            self.shutdown();
            self.conn.shutdown();
            self.do_check_status(poll, sockets);
        }
    }

    fn timeout(&self, now: Instant) -> bool {
        now - self.last_active_time > OPTIONS.tcp_idle_duration
    }

    fn writable(&self) -> bool {
        self.send_buffer.is_empty() && self.alive()
    }

    fn setup(&mut self) -> bool {
        let mut request = BytesMut::new();
        TrojanRequest::generate_endpoint(&mut request, CONNECT, &self.endpoint);
        self.conn.write_session(request.as_ref())
    }

    fn try_close(&mut self, sockets: &mut SocketSet) {
        let mut socket = sockets.get::<TcpSocket>(self.handle);
        if self.closing || matches!(socket.state(), TcpState::CloseWait) {
            log::info!("client is closed:{}", socket.state());
            socket.close();
            self.closing = false;
            std::mem::drop(socket);
            sockets.remove(self.handle);
        }
    }

    fn do_check_status(&mut self, poll: &Poll, sockets: &mut SocketSet) {
        self.try_close(sockets);
        if self.is_shutdown() {
            self.conn.peer_closed();
        }
        if self.conn.is_shutdown() {
            self.peer_closed();
        }
        self.check_status(poll);
        self.conn.check_status(poll);
        self.try_close(sockets);
    }

    fn destroyed(&self) -> bool {
        self.deregistered() && self.conn.deregistered()
    }

    fn do_local(&mut self, poll: &Poll, sockets: &mut SocketSet) {
        self.last_active_time = Instant::now();
        let mut socket = sockets.get::<TcpSocket>(self.handle);
        if self.conn.writable() {
            self.try_recv_client(&mut socket);
        } else {
            self.read_client = true;
        }

        self.try_send_client(&mut socket, &[]);
        std::mem::drop(socket);

        if self.writable() && self.read_server {
            self.do_recv_server(sockets);
            self.read_server = false;
        }
        self.do_check_status(poll, sockets);
    }

    fn try_recv_client(&mut self, socket: &mut SocketRef<TcpSocket>) {
        let buffer = self.recv_buffer.as_mut_slice();
        while socket.may_recv() {
            match socket.recv_slice(buffer) {
                Ok(size) => {
                    if size == 0 || !self.conn.write_session(&buffer[..size]) {
                        break;
                    }
                    log::info!("receive {} bytes from client", size);
                }
                Err(err) => {
                    log::error!("read from socket failed:{}", err);
                    break;
                }
            }
        }
        self.do_send_server();
    }

    fn try_send_client(&mut self, socket: &mut SocketRef<TcpSocket>, data: &[u8]) {
        if socket.may_send() {
            self.established();
            if self.send_buffer.is_empty() {
                self.do_send_client(socket, data);
            } else {
                self.send_buffer.extend_from_slice(data);
                let buffer = self.send_buffer.split();
                self.do_send_client(socket, buffer.as_ref());
            }
        } else if !data.is_empty() {
            self.send_buffer.extend_from_slice(data);
        }
    }

    fn do_send_client(&mut self, socket: &mut SocketRef<TcpSocket>, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match socket.send_slice(data) {
            Ok(size) => {
                log::info!("send {}:{} bytes to client", size, data.len());
                if size != data.len() {
                    self.send_buffer.extend_from_slice(&data[size..])
                }
            }
            Err(err) => {
                log::error!("send to socket failed:{}", err);
            }
        }
    }

    pub(crate) fn ready(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        self.last_active_time = Instant::now();
        if event.is_readable() {
            if self.writable() {
                self.do_recv_server(sockets);
            } else {
                self.read_server = true;
            }
        }

        if event.is_writable() {
            self.conn.established();
            self.do_send_server();
            if self.conn.writable() && self.read_client {
                let mut socket = sockets.get::<TcpSocket>(self.handle);
                self.try_recv_client(&mut socket);
                self.read_client = false;
            }
        }

        self.do_check_status(poll, sockets);
    }

    fn do_recv_server(&mut self, sockets: &mut SocketSet) {
        if let Some(data) = self.conn.do_read() {
            let mut socket = sockets.get::<TcpSocket>(self.handle);
            self.try_send_client(&mut socket, data.as_slice());
        }
    }

    fn do_send_server(&mut self) {
        self.conn.do_send();
    }
}

impl StatusProvider for Connection {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status;
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&mut self) {
        self.closing = true;
    }

    fn deregister(&mut self, _poll: &Poll) {}

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
