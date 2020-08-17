use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::time::Instant;

use bytes::BytesMut;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream};
use rustls::ClientSession;

use crate::config::Opts;
use crate::proto::{CONNECT, TrojanRequest};
use crate::proxy::{CHANNEL_CLIENT, CHANNEL_CNT, CHANNEL_TCP, MIN_INDEX, next_index};
use crate::proxy::idle_pool::IdlePool;
use crate::session::TcpSession;
use crate::sys;
use crate::tls_conn::TlsConn;

pub struct TcpServer {
    tcp_listener: TcpListener,
    conns: HashMap<usize, Connection>,
    next_id: usize,
}

struct Connection {
    index: usize,
    dst_addr: SocketAddr,
    client: TcpStream,
    client_session: TcpSession,
    client_readiness: Ready,
    closed: bool,
    closing: bool,
    client_recv: usize,
    client_sent: usize,
    client_time: Instant,
    server_conn: TlsConn<ClientSession>,
}

impl TcpServer {
    pub fn new(tcp_listener: TcpListener) -> TcpServer {
        TcpServer {
            tcp_listener,
            conns: HashMap::new(),
            next_id: MIN_INDEX,
        }
    }


    pub fn accept(&mut self, _event: &Event, opts: &mut Opts, poll: &Poll, pool: &mut IdlePool) {
        loop {
            match self.tcp_listener.accept() {
                Ok((client, src_addr)) => {
                    if let Err(err) = sys::set_mark(&client, opts.marker) {
                        log::error!("set mark failed:{}", err);
                        continue;
                    } else if let Err(err) = client.set_nodelay(true) {
                        log::error!("set nodelay failed:{}", err);
                        continue;
                    }
                    match sys::get_oridst_addr(&client) {
                        Ok(dst_addr) => {
                            log::info!("got new connection from:{} to:{}", src_addr, dst_addr);
                            if let Some(mut conn) = pool.get(poll) {
                                let index = next_index(&mut self.next_id);
                                conn.reset_index(index, Token(index * CHANNEL_CNT + CHANNEL_TCP));
                                let mut conn = Connection::new(index, conn, dst_addr, client);
                                if conn.setup(opts, poll) {
                                    self.conns.insert(conn.index(), conn);
                                } else {
                                    continue;
                                }
                            } else {
                                log::error!("alloc new connection failed")
                            }
                        }
                        Err(err) => {
                            log::error!("get original destination address failed:{}", err);
                            continue;
                        }
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    log::error!("accept failed:{}", err);
                    continue;
                }
            }
        }
    }


    pub fn ready(&mut self, event: &Event, poll: &Poll) {
        let index = Connection::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            conn.ready(event, poll);
            if conn.closed() {
                self.conns.remove(&index);
            }
        }
    }
}

impl Connection {
    fn new(index: usize, server_conn: TlsConn<ClientSession>, dst_addr: SocketAddr, client: TcpStream) -> Connection {
        Connection {
            index,
            dst_addr,
            client,
            server_conn,
            client_readiness: Ready::empty(),
            closed: false,
            closing: false,
            client_session: TcpSession::new(index),
            client_recv: 0,
            client_sent: 0,
            client_time: Instant::now(),
        }
    }

    fn closed(&self) -> bool {
        self.closed
    }

    fn setup(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        self.server_conn.reregister(poll);
        let mut request = BytesMut::new();
        self.client_readiness = Ready::readable();
        TrojanRequest::generate(&mut request, CONNECT, &self.dst_addr, opts);
        if !self.server_conn.write_session(request.as_ref()) {
            false
        } else if let Err(err) = poll.register(&self.client, self.client_token(), self.client_readiness, PollOpt::edge()) {
            log::warn!("connection:{} register client failed:{}", self.index(), err);
            false
        } else {
            true
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    fn ready(&mut self, event: &Event, poll: &Poll) {
        match event.token().0 % CHANNEL_CNT {
            CHANNEL_CLIENT => {
                if event.readiness().is_readable() {
                    self.try_read_client();
                }

                if event.readiness().is_writable() {
                    self.try_send_client(&[]);
                }
            }
            CHANNEL_TCP => {
                if event.readiness().is_readable() {
                    self.try_read_server();
                }

                if event.readiness().is_writable() {
                    self.try_send_server();
                }
            }
            _ => {
                log::error!("invalid token found in tcp listener");
                self.closing = true;
                return;
            }
        }


        self.reregister(poll);
        if self.closing {
            self.close_now(poll);
        }
        self.server_conn.check_close(poll);
    }

    fn close_now(&mut self, poll: &Poll) {
        let _ = poll.deregister(&self.client);
        let _ = self.client.shutdown(Shutdown::Both);
        self.closed = true;
        let secs = self.client_time.elapsed().as_secs();
        log::warn!("connection:{} closed, target address {:?}, {} seconds,  {} bytes read, {} bytes sent", self.index(), self.dst_addr, secs,  self.client_recv, self.client_sent);
    }

    fn reregister(&mut self, poll: &Poll) {
        if self.closing {
            return;
        }
        let mut changed = false;
        if self.client_session.wants_write() && !self.client_readiness.is_writable() {
            self.client_readiness.insert(Ready::writable());
            changed = true;
        }
        if !self.client_session.wants_write() && self.client_readiness.is_writable() {
            self.client_readiness.remove(Ready::writable());
            changed = true;
        }

        if changed {
            if let Err(err) = poll.reregister(&self.client, self.client_token(), self.client_readiness, PollOpt::edge()) {
                log::error!("connection:{} reregister client failed:{}", self.index(), err);
                self.closing = true;
                return;
            }
        }

        self.server_conn.reregister(poll)
    }

    fn client_token(&self) -> Token {
        Token(self.index * CHANNEL_CNT + CHANNEL_CLIENT)
    }

    fn try_read_client(&mut self) {
        if let Err(err) = self.client_session.read_backend(&mut self.client) {
            log::warn!("connection:{} read from client failed:{}", self.index(), err);
            self.closing = true;
            return;
        }
        let data = self.client_session.read_all();
        if data.is_empty() {
            return;
        }
        self.client_sent += data.len();
        if !self.server_conn.write_session(data.as_ref()) {
            self.closing = true;
            return;
        }
        self.try_send_server();
    }

    fn try_send_client(&mut self, buffer: &[u8]) {
        if self.client_session.wants_write() {
            if let Err(err) = self.client_session.write_all(buffer) {
                log::error!("connection:{} write to client session failed:{}", self.index(), err);
                self.closing = true;
                return;
            } else {
                match self.client_session.write_backend(&mut self.client) {
                    Err(err) => {
                        log::warn!("connection:{} write to client failed:{}", self.index(), err);
                        self.closing = true;
                        return;
                    }
                    Ok(size) => {
                        log::info!("connection:{} write {} bytes to client done", self.index(), size);
                        self.client_recv += size;
                    }
                }
            }
        } else {
            self.do_send_client(buffer);
        }
    }

    fn do_send_client(&mut self, mut buffer: &[u8]) {
        loop {
            if buffer.len() == 0 {
                break;
            }
            match self.client.write(buffer) {
                Ok(size) => {
                    buffer = &buffer[size..];
                    self.client_recv += size;
                    log::info!("connection:{} send {} bytes to client", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    if let Err(err) = self.client_session.write_all(buffer) {
                        log::error!("connection:{} write data to client session failed:{}", self.index(), err);
                        self.closing = true;
                    }
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} send to client failed:{}", self.index(), err);
                    self.closing = true;
                    return;
                }
            }
        }
    }

    fn try_read_server(&mut self) {
        if let Some(buffer) = self.server_conn.do_read() {
            self.try_send_client(buffer.as_slice());
        }
    }

    fn try_send_server(&mut self) {
        self.server_conn.do_send();
    }
}