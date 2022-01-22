use std::{collections::HashMap, sync::Arc, time::Instant};

use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{
    iface::SocketHandle,
    socket::{TcpSocket, TcpState},
    wire::IpEndpoint,
};

use crate::{
    idle_pool::IdlePool,
    proto::{TrojanRequest, CONNECT, MAX_PACKET_SIZE},
    resolver::DnsResolver,
    status::{ConnStatus, StatusProvider},
    tls_conn::TlsConn,
    wintun::{waker::Wakers, SocketSet, CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX},
    OPTIONS,
};

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
        let list: Vec<_> = self
            .conns
            .iter_mut()
            .filter_map(|(index, conn)| unsafe {
                if !conn.destroyed() {
                    Arc::get_mut_unchecked(conn).check_timeout(poll, now, sockets);
                }
                if conn.destroyed() {
                    Some((*index, conn.handle))
                } else {
                    None
                }
            })
            .collect();

        for (index, handle) in list {
            self.remove_conn(handle, index, sockets);
        }
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
        wakers: &mut Wakers,
        sockets: &mut SocketSet,
    ) {
        let mut destroyed = Vec::new();
        for (handle, event) in wakers.get_tcp_handles().iter() {
            let handle = *handle;
            log::info!("handle:{}, event:{:?}", handle, event);
            let socket = sockets.get_socket::<TcpSocket>(handle);
            if socket.is_listening() {
                log::info!(
                    "socket:{} {} still listening, remove now",
                    handle,
                    socket.local_endpoint()
                );
                sockets.remove_socket(handle);
                continue; // Filter unused syn packet
            }
            let conn = if let Some(conn) = self.src_map.get_mut(&handle) {
                conn
            } else if let Some(mut conn) = pool.get(poll, resolver) {
                let index = next_index();
                if !conn.reset_index(index, TcpServer::index2token(index), poll) {
                    conn.check_status(poll);
                    continue;
                }
                let mut conn = Connection::new(conn, handle, index, socket.local_endpoint());
                if !conn.setup() {
                    conn.conn.check_status(poll);
                    continue;
                }
                let conn = Arc::new(conn);
                let _ = self.src_map.insert(handle, conn.clone());
                let _ = self.conns.insert(index, conn.clone());
                self.conns.get_mut(&index).unwrap()
            } else {
                log::error!("get from idle pool failed");
                continue;
            };
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.do_local(event, poll, sockets);
            if conn.destroyed() {
                destroyed.push((conn.handle, conn.index));
            } else {
                let socket = sockets.get_socket::<TcpSocket>(handle);
                let (rx, tx) = wakers.get_tcp_wakers(handle);
                if event.is_readable() {
                    socket.register_recv_waker(rx);
                }
                if !conn.send_buffer.is_empty() {
                    socket.register_send_waker(tx);
                }
            }
        }
        for (handle, index) in destroyed {
            self.remove_conn(handle, index, sockets);
        }
    }

    pub(crate) fn do_remote(
        &mut self,
        event: &Event,
        poll: &Poll,
        sockets: &mut SocketSet,
        wakers: &mut Wakers,
    ) {
        let index = Self::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.ready(event, poll, sockets, wakers);
            if conn.destroyed() {
                let handle = conn.handle;
                let index = conn.index;
                self.remove_conn(handle, index, sockets);
            }
        } else {
            log::warn!("connection:{} not found in tcp sockets", index);
        }
    }
    fn remove_conn(&mut self, handle: SocketHandle, index: usize, sockets: &mut SocketSet) {
        if !self.conns.contains_key(&index) {
            return;
        }
        log::info!("connection:{}-{} removed", handle, index);
        sockets.remove_socket(handle);
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
    closed: Option<bool>,
    //None for ok, false for closing, true for closed
    read_client: bool,
    read_server: bool,
    socket_state: TcpState,
}

impl Connection {
    fn new(conn: TlsConn, handle: SocketHandle, index: usize, endpoint: IpEndpoint) -> Self {
        Self {
            conn,
            handle,
            endpoint,
            index,
            last_active_time: Instant::now(),
            closed: None,
            read_server: false,
            read_client: false,
            status: ConnStatus::Connecting,
            socket_state: TcpState::Established,
            recv_buffer: vec![0; MAX_PACKET_SIZE],
            send_buffer: BytesMut::new(),
        }
    }

    pub(crate) fn check_timeout(&mut self, poll: &Poll, now: Instant, sockets: &mut SocketSet) {
        let socket = sockets.get_socket::<TcpSocket>(self.handle);
        log::info!(
            "socket:{} {}<->{} {} {:?} {:?} {:?}",
            self.handle,
            socket.remote_endpoint(),
            socket.local_endpoint(),
            socket.state(),
            self.status,
            self.conn.get_status(),
            self.last_active_time.elapsed(),
        );
        if self.timeout(now) {
            self.close(sockets);
            self.conn.shutdown();
        }
        self.do_check_status(poll, sockets);
    }

    fn close(&mut self, sockets: &mut SocketSet) {
        let socket = sockets.get_socket::<TcpSocket>(self.handle);
        socket.abort();
        self.socket_state = socket.state();
        if !self.shutdown() {
            self.closed.replace(true);
            self.shutdown();
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
        log::info!("send trojan request {} bytes", request.len());
        self.conn.write_session(request.as_ref())
    }

    fn try_close(&mut self, poll: &Poll, sockets: &mut SocketSet) {
        if matches!(self.closed, Some(false)) {
            let socket = sockets.get_socket::<TcpSocket>(self.handle);
            socket.close();
            self.socket_state = socket.state();
            self.closed.replace(true);
            self.shutdown();
            self.check_status(poll);
        }
    }

    fn do_check_status(&mut self, poll: &Poll, sockets: &mut SocketSet) {
        let socket = sockets.get_socket::<TcpSocket>(self.handle);
        self.socket_state = socket.state();
        if self.is_shutdown() {
            self.conn.peer_closed();
        }
        if self.conn.is_shutdown() {
            self.peer_closed();
            self.check_status(poll);
        }
        self.try_close(poll, sockets); //closing -> closed
        self.check_status(poll);
        self.conn.check_status(poll);
    }

    fn destroyed(&self) -> bool {
        self.deregistered() && self.conn.deregistered()
    }

    fn do_local(
        &mut self,
        event: &crate::wintun::waker::Event,
        poll: &Poll,
        sockets: &mut SocketSet,
    ) {
        self.last_active_time = Instant::now();
        if event.is_readable() {
            if self.conn.writable() {
                self.try_recv_client(poll, sockets);
            } else {
                self.read_client = true;
            }
        }

        if event.is_writable() {
            self.established();
            self.try_send_client(sockets, &[]);
        }

        self.do_check_status(poll, sockets);
    }

    fn try_recv_client(&mut self, poll: &Poll, sockets: &mut SocketSet) {
        let socket = sockets.get_socket::<TcpSocket>(self.handle);
        let buffer = self.recv_buffer.as_mut_slice();
        while socket.may_recv() {
            match socket.recv_slice(buffer) {
                Ok(size) => {
                    log::info!("receive {} bytes from client", size);
                    if size == 0 || !self.conn.write_session(&buffer[..size]) {
                        break;
                    }
                }
                Err(err) => {
                    log::error!("read from socket failed:{}", err);
                    break;
                }
            }
        }

        if matches!(socket.state(), TcpState::CloseWait | TcpState::Closed) {
            log::info!("client:{}-{} shutdown now", self.handle, self.index);
            self.close_conn();
            self.try_close(poll, sockets);
        }

        self.do_send_server();
    }

    fn try_send_client(&mut self, sockets: &mut SocketSet, data: &[u8]) {
        let socket = sockets.get_socket::<TcpSocket>(self.handle);
        if socket.may_send() {
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
        if self.writable() && self.read_server {
            self.do_recv_server(sockets);
            self.read_server = false;
        }
    }

    fn do_send_client(&mut self, socket: &mut TcpSocket, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        match socket.send_slice(data) {
            Ok(size) => {
                log::info!(
                    "connection:{} send {}:{} bytes to client",
                    self.index,
                    size,
                    data.len()
                );
                if size != data.len() {
                    self.send_buffer.extend_from_slice(&data[size..])
                }
            }
            Err(err) => {
                log::error!("send to socket failed:{}", err);
            }
        }
    }

    pub(crate) fn ready(
        &mut self,
        event: &Event,
        poll: &Poll,
        sockets: &mut SocketSet,
        wakers: &mut Wakers,
    ) {
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
        }

        if !self.send_buffer.is_empty() {
            let socket = sockets.get_socket::<TcpSocket>(self.handle);
            let (_, tx) = wakers.get_tcp_wakers(self.handle);
            socket.register_send_waker(tx);
        }

        self.do_check_status(poll, sockets);
    }

    fn do_recv_server(&mut self, sockets: &mut SocketSet) {
        if let Some(data) = self.conn.do_read() {
            self.try_send_client(sockets, data.as_slice());
        }
    }

    fn do_send_server(&mut self) {
        self.conn.do_send();
        if self.conn.writable() && self.read_client {
            self.try_recv_client(poll, sockets);
            self.read_client = false;
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
        if self.closed.is_none() {
            self.closed = Some(false);
            false
        } else {
            self.closed.unwrap()
        }
    }

    fn deregister(&mut self, _poll: &Poll) -> bool {
        matches!(self.socket_state, TcpState::Closed | TcpState::TimeWait)
    }

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
