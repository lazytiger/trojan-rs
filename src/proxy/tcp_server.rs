use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{Shutdown, SocketAddr},
    time::Instant,
};

use bytes::BytesMut;
use mio::{
    net::{TcpListener, TcpStream},
    Event, Poll, PollOpt, Ready, Token,
};
use rustls::ClientSession;

use crate::{
    config::Opts,
    proto::{TrojanRequest, CONNECT, MAX_BUFFER_SIZE, MAX_PACKET_SIZE},
    proxy::{idle_pool::IdlePool, next_index, CHANNEL_CLIENT, CHANNEL_CNT, CHANNEL_TCP, MIN_INDEX},
    sys, tcp_util,
    tls_conn::{ConnStatus, TlsConn},
};

pub struct TcpServer {
    tcp_listener: TcpListener,
    conns: HashMap<usize, Connection>,
    next_id: usize,
}

struct Connection {
    index: usize,
    dst_addr: SocketAddr,
    client: TcpStream,
    recv_buffer: Vec<u8>,
    send_buffer: BytesMut,
    client_readiness: Ready,
    status: ConnStatus,
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
                                    conn.shutdown(poll);
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
            if conn.destroyed() {
                log::debug!("connection:{} removed from list", index);
                self.conns.remove(&index);
            }
        }
    }
}

impl Connection {
    fn new(
        index: usize,
        server_conn: TlsConn<ClientSession>,
        dst_addr: SocketAddr,
        client: TcpStream,
    ) -> Connection {
        Connection {
            index,
            dst_addr,
            client,
            server_conn,
            client_readiness: Ready::empty(),
            status: ConnStatus::Established,
            send_buffer: BytesMut::new(),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
            client_time: Instant::now(),
        }
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

    fn setup(&mut self, opts: &mut Opts, poll: &Poll) -> bool {
        self.server_conn.setup(poll);
        let mut request = BytesMut::new();
        self.client_readiness = Ready::readable();
        TrojanRequest::generate(&mut request, CONNECT, &self.dst_addr, opts);
        if !self.server_conn.write_session(request.as_ref()) {
            false
        } else if let Err(err) = poll.register(
            &self.client,
            self.client_token(),
            self.client_readiness,
            PollOpt::edge(),
        ) {
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
                self.status = ConnStatus::Closing;
                return;
            }
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

    fn shutdown(&mut self, poll: &Poll) {
        if self.send_buffer.is_empty() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }

        self.client_readiness = Ready::writable();
        if let Err(err) = poll.reregister(
            &self.client,
            self.client_token(),
            self.client_readiness,
            PollOpt::edge(),
        ) {
            log::warn!("connection:{} register client failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
            self.check_close(poll);
        } else {
            self.status = ConnStatus::Shutdown;
        }
    }

    fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            self.close_now(poll);
        }
    }

    fn close_now(&mut self, poll: &Poll) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = poll.deregister(&self.client);
        self.status = ConnStatus::Closed;
        let secs = self.client_time.elapsed().as_secs();
        log::warn!(
            "connection:{} closed, target address {:?}, {} seconds",
            self.index(),
            self.dst_addr,
            secs
        );
    }

    fn reregister(&mut self, poll: &Poll) {
        match self.status {
            ConnStatus::Closing => {
                let _ = poll.deregister(&self.client);
            }
            ConnStatus::Closed => {}
            _ => {
                let mut changed = false;
                if !self.send_buffer.is_empty() && !self.client_readiness.is_writable() {
                    self.client_readiness.insert(Ready::writable());
                    changed = true;
                }
                if self.send_buffer.is_empty() && self.client_readiness.is_writable() {
                    self.client_readiness.remove(Ready::writable());
                    changed = true;
                }
                if self.server_conn.writable() && !self.client_readiness.is_readable() {
                    self.client_readiness.insert(Ready::readable());
                    changed = true;
                }
                if !self.server_conn.writable() && self.client_readiness.is_readable() {
                    self.client_readiness.remove(Ready::readable());
                    changed = true;
                }

                if changed {
                    if let Err(err) = poll.reregister(
                        &self.client,
                        self.client_token(),
                        self.client_readiness,
                        PollOpt::edge(),
                    ) {
                        log::error!(
                            "connection:{} reregister client failed:{}",
                            self.index(),
                            err
                        );
                        self.status = ConnStatus::Closing;
                        return;
                    }
                }
            }
        }
    }

    fn client_token(&self) -> Token {
        Token(self.index * CHANNEL_CNT + CHANNEL_CLIENT)
    }

    fn try_read_client(&mut self) {
        if !tcp_util::tcp_read(
            self.index,
            &self.client,
            &mut self.recv_buffer,
            &mut self.server_conn,
        ) {
            self.status = ConnStatus::Closing;
        }

        self.try_send_server();
    }

    fn try_send_client(&mut self, buffer: &[u8]) {
        if self.send_buffer.is_empty() {
            self.do_send_client(buffer);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send_client(buffer.as_ref());
        }
    }

    fn do_send_client(&mut self, data: &[u8]) {
        if !tcp_util::tcp_send(self.index, &self.client, &mut self.send_buffer, data) {
            self.status = ConnStatus::Closing;
            return;
        }
        if let ConnStatus::Shutdown = self.status {
            if self.send_buffer.is_empty() {
                self.status = ConnStatus::Closing;
                log::debug!("connection:{} is closing for no data to send", self.index());
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
