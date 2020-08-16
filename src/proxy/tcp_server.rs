use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::BytesMut;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::{TcpListener, TcpStream};
use rustls::{ClientConfig, ClientSession, Session};
use webpki::DNSName;

use crate::config::Opts;
use crate::proto::{CONNECT, TrojanRequest};
use crate::proxy::{MAX_INDEX, MIN_INDEX};
use crate::session::TcpSession;
use crate::sys;

pub struct TcpServer {
    tcp_listener: TcpListener,
    conns: HashMap<usize, Connection>,
    pool: HashMap<usize, Connection>,
    config: Arc<ClientConfig>,
    hostname: DNSName,
    next_id: usize,
}

struct Connection {
    index: usize,
    dst_addr: Option<SocketAddr>,
    client: Option<TcpStream>,
    client_session: TcpSession,
    server: TcpStream,
    server_session: ClientSession,
    client_readiness: Ready,
    server_readiness: Ready,
    closed: bool,
    closing: bool,
    client_recv: usize,
    client_sent: usize,
    client_time: Instant,
}

impl TcpServer {
    pub fn new(tcp_listener: TcpListener, config: Arc<ClientConfig>, hostname: DNSName) -> TcpServer {
        TcpServer {
            tcp_listener,
            config,
            hostname,
            conns: HashMap::new(),
            pool: HashMap::new(),
            next_id: MIN_INDEX,
        }
    }


    pub fn accept(&mut self, _event: &Event, opts: &mut Opts, poll: &Poll) {
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
                            if let Some(mut conn) = self.get_conn(opts, poll) {
                                if conn.setup(opts, poll, Some(dst_addr), Some(client)) {
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

    fn alloc_conn(&mut self, opts: &mut Opts, poll: &Poll) {
        for _i in 0..opts.proxy_args().pool_size {
            if let Some(mut conn) = self.new_conn(opts) {
                conn.setup(opts, poll, None, None);
                self.pool.insert(conn.index(), conn);
            }
        }
    }

    fn new_conn(&mut self, opts: &mut Opts) -> Option<Connection> {
        let server = match TcpStream::connect(opts.back_addr.as_ref().unwrap()) {
            Ok(server) => {
                if let Err(err) = sys::set_mark(&server, opts.marker) {
                    log::error!("set mark failed:{}", err);
                    None
                } else if let Err(err) = server.set_nodelay(true) {
                    log::error!("set nodelay:{}", err);
                    None
                } else {
                    Some(server)
                }
            }
            Err(err) => {
                //FIXME should refresh dns now?
                log::error!("connection to server failed:{}", err);
                None
            }
        };
        if let Some(server) = server {
            let session = ClientSession::new(&self.config, self.hostname.as_ref());
            let conn = Connection::new(self.next_index(), session, server);
            Some(conn)
        } else {
            None
        }
    }

    fn get_conn(&mut self, opts: &mut Opts, poll: &Poll) -> Option<Connection> {
        if opts.proxy_args().pool_size == 0 {
            self.new_conn(opts)
        } else {
            if self.pool.is_empty() {
                self.alloc_conn(opts, poll);
            }
            if self.pool.is_empty() {
                None
            } else {
                let key = *self.pool.keys().nth(0).unwrap();
                self.pool.remove(&key)
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
        if let Some(conn) = self.pool.get_mut(&index) {
            conn.ready(event, poll);
            if conn.closed() {
                self.pool.remove(&index);
            }
        }
    }

    pub fn next_index(&mut self) -> usize {
        let index = self.next_id;
        self.next_id += 1;
        if self.next_id >= MAX_INDEX {
            self.next_id = MIN_INDEX;
        }
        index
    }
}

impl Connection {
    fn new(index: usize, session: ClientSession, server: TcpStream) -> Connection {
        Connection {
            index,
            dst_addr: None,
            client: None,
            server,
            server_session: session,
            client_readiness: Ready::empty(),
            server_readiness: Ready::readable() | Ready::writable(),
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

    fn setup(&mut self, opts: &mut Opts, poll: &Poll, dst_addr: Option<SocketAddr>, client: Option<TcpStream>) -> bool {
        if dst_addr.is_some() {
            let mut request = BytesMut::new();
            self.dst_addr = dst_addr;
            self.client = client;
            self.client_readiness = Ready::readable();
            TrojanRequest::generate(&mut request, CONNECT, self.dst_addr.as_ref().unwrap(), opts);
            if let Err(err) = self.server_session.write_all(request.as_ref()) {
                log::warn!("connection:{} write handshake to server session failed:{}", self.index(), err);
                false
            } else if let Err(err) = poll.register(self.client.as_ref().unwrap(), self.client_token(), self.client_readiness, PollOpt::edge()) {
                log::warn!("connection:{} register client failed:{}", self.index(), err);
                false
            } else {
                true
            }
        } else {
            if let Err(err) = poll.register(&self.server, self.server_token(), self.server_readiness, PollOpt::level()) {
                log::warn!("connection:{} register server failed:{}", self.index(), err);
                false
            } else {
                true
            }
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    fn token2index(token: Token) -> usize {
        token.0 / 3
    }

    fn ready(&mut self, event: &Event, poll: &Poll) {
        match event.token().0 % 3 {
            1 => {
                if event.readiness().is_readable() {
                    self.try_read_client();
                }

                if event.readiness().is_writable() {
                    self.try_send_client(&[]);
                }
            }
            2 => {
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
    }

    fn close_now(&mut self, poll: &Poll) {
        if self.client.is_some() {
            let _ = poll.deregister(self.client.as_ref().unwrap());
            let _ = self.client.as_ref().unwrap().shutdown(Shutdown::Both);
        }
        let _ = poll.deregister(&self.server);
        let _ = self.server.shutdown(Shutdown::Both);
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
            if let Err(err) = poll.reregister(self.client.as_ref().unwrap(), self.client_token(), self.client_readiness, PollOpt::edge()) {
                log::error!("connection:{} reregister client failed:{}", self.index(), err);
                self.closing = true;
                return;
            }
        }

        changed = false;
        if self.server_session.wants_write() && self.client_sent > 0 && !self.server_readiness.is_writable() {
            self.server_readiness.insert(Ready::writable());
            changed = true;
        }
        if !self.server_session.wants_write() && self.server_readiness.is_writable() {
            self.server_readiness.remove(Ready::writable());
            changed = true;
        }
        if changed {
            if let Err(err) = poll.reregister(&self.server, self.server_token(), self.server_readiness, PollOpt::level()) {
                log::error!("connection:{} reregister server failed:{}", self.index(), err);
                self.closing = true;
                return;
            }
        }
    }

    fn client_token(&self) -> Token {
        Token(self.index * 3 + 1)
    }

    fn server_token(&self) -> Token {
        Token(self.index * 3 + 2)
    }

    fn try_read_client(&mut self) {
        if let Err(err) = self.client_session.read_backend(self.client.as_mut().unwrap()) {
            log::warn!("connection:{} read from client failed:{}", self.index(), err);
            self.closing = true;
            return;
        }
        let data = self.client_session.read_all();
        if data.is_empty() {
            return;
        }
        self.client_sent += data.len();
        if let Err(err) = self.server_session.write_all(data.as_ref()) {
            log::warn!("connection:{} write to server failed:{}", self.index(), err);
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
                match self.client_session.write_backend(self.client.as_mut().unwrap()) {
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
            match self.client.as_ref().unwrap().write(buffer) {
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
        loop {
            match self.server_session.read_tls(&mut self.server) {
                Ok(size) => {
                    if size == 0 {
                        log::warn!("connection:{} read from server failed with eof", self.index());
                        self.closing = true;
                        return;
                    }
                    log::info!("connection:{} read {} bytes from server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} read from server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} read from server failed:{}", self.index(), err);
                    self.closing = true;
                    return;
                }
            }
        }

        if let Err(err) = self.server_session.process_new_packets() {
            log::error!("connection:{} process new packets failed:{}", self.index(), err);
            self.closing = true;
            return;
        }

        let mut buffer = Vec::new();
        if let Err(err) = self.server_session.read_to_end(&mut buffer) {
            log::error!("connection:{} read from session failed:{}", self.index(), err);
            self.closing = true;
            return;
        }

        if !buffer.is_empty() {
            self.try_send_client(buffer.as_slice());
        }
    }

    fn try_send_server(&mut self) {
        loop {
            if !self.server_session.wants_write() {
                return;
            }
            match self.server_session.write_tls(&mut self.server) {
                Ok(size) => {
                    log::debug!("connection:{} write {} bytes to server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} write to server failed:{}", self.index(), err);
                    self.closing = true;
                    return;
                }
            }
        }
    }
}