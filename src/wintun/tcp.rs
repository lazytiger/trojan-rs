use crate::{
    idle_pool::IdlePool,
    proto::{TrojanRequest, CONNECT, MAX_PACKET_SIZE},
    resolver::DnsResolver,
    status::StatusProvider,
    tls_conn::TlsConn,
    wintun::{CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX},
};
use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{
    socket::{SocketHandle, SocketRef, SocketSet, TcpSocket},
    wire::IpEndpoint,
};
use std::{collections::HashMap, sync::Arc};

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
                let mut conn = Connection::new(conn, handle, socket.local_endpoint());
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
            conn.do_local(sockets);
        }
    }

    pub(crate) fn do_remote(&mut self, event: &Event, poll: &Poll, sockets: &mut SocketSet) {
        let index = Self::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            let conn = unsafe { Arc::get_mut_unchecked(conn) };
            conn.ready(event, poll, sockets);
        } else {
            log::warn!("connection:{} not found in tcp sockets", index);
        }
    }
}

pub struct Connection {
    conn: TlsConn,
    handle: SocketHandle,
    endpoint: IpEndpoint,
    recv_buffer: Vec<u8>,
    send_buffer: BytesMut,
}

impl Connection {
    fn new(conn: TlsConn, handle: SocketHandle, endpoint: IpEndpoint) -> Self {
        Self {
            conn,
            handle,
            endpoint,
            recv_buffer: vec![0; MAX_PACKET_SIZE],
            send_buffer: BytesMut::new(),
        }
    }

    fn setup(&mut self) -> bool {
        let mut request = BytesMut::new();
        TrojanRequest::generate_endpoint(&mut request, CONNECT, &self.endpoint);
        self.conn.write_session(request.as_ref())
    }

    fn do_local(&mut self, sockets: &mut SocketSet) {
        let mut socket = sockets.get::<TcpSocket>(self.handle);
        self.try_recv_client(&mut socket);
        self.try_send_client(&mut socket, &[]);
    }

    fn try_recv_client(&mut self, socket: &mut SocketRef<TcpSocket>) {
        while socket.may_recv() {
            match socket.recv_slice(self.recv_buffer.as_mut_slice()) {
                Ok(size) => {
                    if !self
                        .conn
                        .write_session(&self.recv_buffer.as_slice()[..size])
                    {
                        //TODO
                    }
                }
                Err(err) => {
                    log::error!("read from socket failed:{}", err);
                }
            }
        }
    }

    fn try_send_client(&mut self, socket: &mut SocketRef<TcpSocket>, data: &[u8]) {
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
    }

    fn do_send_client(&mut self, socket: &mut SocketRef<TcpSocket>, data: &[u8]) {
        match socket.send_slice(data) {
            Ok(size) => {
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
        if event.is_readable() {
            self.do_recv_server(sockets);
        }

        if event.is_writable() {
            self.do_send_server(sockets);
        }

        self.conn.check_status(poll);
    }

    fn do_recv_server(&mut self, sockets: &mut SocketSet) {
        if let Some(data) = self.conn.do_read() {
            let mut socket = sockets.get::<TcpSocket>(self.handle);
            self.try_send_client(&mut socket, data.as_slice());
        }
    }

    fn do_send_server(&mut self, sockets: &mut SocketSet) {
        self.conn.do_send();
    }
}
