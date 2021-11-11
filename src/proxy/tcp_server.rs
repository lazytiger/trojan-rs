use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{Shutdown, SocketAddr},
    time::Instant,
};

use bytes::BytesMut;
use mio::{
    event::Event,
    net::{TcpListener, TcpStream},
    Interest, Poll, Token,
};
use rustls::ClientConnection;

use crate::{
    config::Opts,
    proto::{TrojanRequest, CONNECT, MAX_BUFFER_SIZE, MAX_PACKET_SIZE},
    proxy::{
        idle_pool::IdlePool, next_index, CHANNEL_CLIENT, CHANNEL_CNT, CHANNEL_REMOTE, MIN_INDEX,
    },
    resolver::DnsResolver,
    sys, tcp_util,
    tls_conn::{ConnStatus, TlsConn},
};

pub struct TcpServer {
    tcp_listener: TcpListener,
    conns: HashMap<usize, Connection>,
    next_id: usize,
    opts: &'static Opts,
}

struct Connection {
    index: usize,
    dst_addr: SocketAddr,
    client: TcpStream,
    recv_buffer: Vec<u8>,
    send_buffer: BytesMut,
    client_interest: Interest,
    status: ConnStatus,
    client_time: Instant,
    server_conn: TlsConn<ClientConnection>,
    opts: &'static Opts,
    last_active_time: Instant,
}

impl TcpServer {
    pub fn new(tcp_listener: TcpListener, opts: &'static Opts) -> TcpServer {
        TcpServer {
            tcp_listener,
            conns: HashMap::new(),
            next_id: MIN_INDEX,
            opts,
        }
    }

    pub fn accept(
        &mut self,
        _event: &Event,
        poll: &Poll,
        pool: &mut IdlePool,
        resolver: &DnsResolver,
    ) {
        loop {
            match self.tcp_listener.accept() {
                Ok((client, src_addr)) => {
                    if let Err(err) = sys::set_mark(&client, self.opts.marker) {
                        log::error!("set mark failed:{}", err);
                        continue;
                    } else if let Err(err) = client.set_nodelay(true) {
                        log::error!("set nodelay failed:{}", err);
                        continue;
                    }
                    match sys::get_oridst_addr(&client) {
                        Ok(dst_addr) => {
                            log::info!("got new connection from:{} to:{}", src_addr, dst_addr);
                            if let Some(mut conn) = pool.get(poll, resolver) {
                                let index = next_index(&mut self.next_id);
                                conn.reset_index(
                                    index,
                                    Token(index * CHANNEL_CNT + CHANNEL_REMOTE),
                                );
                                let mut conn =
                                    Connection::new(index, conn, dst_addr, client, self.opts);
                                if conn.setup(poll) {
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

    pub fn check_timeout(&mut self, poll: &Poll, now: Instant) {
        for (_, conn) in &mut self.conns {
            if conn.timeout(now) {
                conn.shutdown(poll);
                conn.server_conn.shutdown(poll);
            }
        }
    }
}

impl Connection {
    fn new(
        index: usize,
        server_conn: TlsConn<ClientConnection>,
        dst_addr: SocketAddr,
        client: TcpStream,
        opts: &'static Opts,
    ) -> Connection {
        Connection {
            index,
            dst_addr,
            client,
            server_conn,
            client_interest: Interest::READABLE,
            status: ConnStatus::Established,
            send_buffer: BytesMut::new(),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
            client_time: Instant::now(),
            last_active_time: Instant::now(),
            opts,
        }
    }

    fn timeout(&self, now: Instant) -> bool {
        return now - self.last_active_time > self.opts.tcp_idle_duration;
    }

    fn destroyed(&self) -> bool {
        self.closed() && self.server_conn.closed()
    }

    fn closed(&self) -> bool {
        matches!(self.status, ConnStatus::Closed)
    }

    fn setup(&mut self, poll: &Poll) -> bool {
        self.server_conn.setup(poll);
        let mut request = BytesMut::new();
        self.client_interest = Interest::READABLE;
        TrojanRequest::generate(&mut request, CONNECT, &self.dst_addr, self.opts);
        let token = self.client_token();
        if !self.server_conn.write_session(request.as_ref()) {
            false
        } else if let Err(err) =
            poll.registry()
                .register(&mut self.client, token, self.client_interest)
        {
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
        self.last_active_time = Instant::now();
        match event.token().0 % CHANNEL_CNT {
            CHANNEL_CLIENT => {
                if event.is_readable() {
                    self.try_read_client();
                }
                if event.is_writable() {
                    self.try_send_client(&[]);
                }
            }
            CHANNEL_REMOTE => {
                if event.is_readable() {
                    self.try_read_server();
                }
                if event.is_writable() {
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

        self.client_interest = Interest::WRITABLE;
        let token = self.client_token();
        if let Err(err) = poll
            .registry()
            .reregister(&mut self.client, token, self.client_interest)
        {
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
        let _ = poll.registry().deregister(&mut self.client);
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
                let _ = poll.registry().deregister(&mut self.client);
            }
            ConnStatus::Closed => {}
            _ => {
                let mut changed = false;
                if !self.send_buffer.is_empty() && !self.client_interest.is_writable() {
                    self.client_interest |= Interest::WRITABLE;
                    changed = true;
                }
                if self.send_buffer.is_empty() && self.client_interest.is_writable() {
                    self.client_interest = self
                        .client_interest
                        .remove(Interest::WRITABLE)
                        .unwrap_or(Interest::READABLE);
                    changed = true;
                }
                if self.server_conn.writable() && !self.client_interest.is_readable() {
                    self.client_interest |= Interest::READABLE;
                    changed = true;
                }
                if !self.server_conn.writable() && self.client_interest.is_readable() {
                    self.client_interest = self
                        .client_interest
                        .remove(Interest::READABLE)
                        .unwrap_or(Interest::WRITABLE);
                    changed = true;
                }

                if changed {
                    let token = self.client_token();
                    if let Err(err) =
                        poll.registry()
                            .reregister(&mut self.client, token, self.client_interest)
                    {
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
        if !tcp_util::tcp_read_client(
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
