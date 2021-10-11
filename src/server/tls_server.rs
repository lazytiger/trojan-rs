use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{event::Event, net::TcpListener, Poll, Token};
use rustls::{Error, ServerConfig, ServerConnection, ServerSession};

use crate::{
    config::Opts,
    resolver::DnsResolver,
    server::{connection::Connection, CHANNEL_CNT, CHANNEL_PROXY, MAX_INDEX, MIN_INDEX},
    sys,
    tls_conn::{ConnStatus, TlsConn},
};

pub enum PollEvent<'a> {
    Network(&'a Event),
    Dns((Token, Option<IpAddr>)),
}

impl<'a> PollEvent<'a> {
    fn token(&self) -> Token {
        match self {
            PollEvent::Network(event) => event.token(),
            PollEvent::Dns((token, _)) => *token,
        }
    }
}

pub struct TlsServer {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    next_id: usize,
    conns: HashMap<usize, Connection>,
    opts: &'static Opts,
}

pub trait Backend {
    fn ready(&mut self, event: &Event, conn: &mut TlsConn<ServerSession>);
    fn dispatch(&mut self, data: &[u8]);
    fn reregister(&mut self, poll: &Poll, readable: bool);
    fn check_close(&mut self, poll: &Poll);
    fn closing(&self) -> bool {
        matches!(self.status(), ConnStatus::Closing)
    }
    fn closed(&self) -> bool {
        matches!(self.status(), ConnStatus::Closed)
    }
    fn timeout(&self, t1: Instant, t2: Instant) -> bool {
        t2 - t1 > self.get_timeout()
    }
    fn get_timeout(&self) -> Duration;
    fn status(&self) -> ConnStatus;
    fn shutdown(&mut self, poll: &Poll);
    fn writable(&self) -> bool;
}

impl TlsServer {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>, opts: &'static Opts) -> TlsServer {
        TlsServer {
            listener,
            config,
            next_id: MIN_INDEX,
            conns: HashMap::new(),
            opts,
        }
    }

    pub fn accept(&mut self, poll: &Poll) {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    log::debug!(
                        "get new connection, token:{}, address:{}",
                        self.next_id,
                        addr
                    );
                    if let Err(err) = sys::set_mark(&stream, self.opts.marker) {
                        log::error!("set mark failed:{}", err);
                        continue;
                    } else if let Err(err) = stream.set_nodelay(true) {
                        log::error!("set nodelay failed:{}", err);
                        continue;
                    }
                    let session = match ServerConnection::new(self.config.clone()) {
                        Ok(session) => session,
                        Err(err) => {
                            log::error!("create server connection failed:{}", err);
                            continue;
                        }
                    };
                    let index = self.next_index();
                    let mut conn = Connection::new(
                        index,
                        TlsConn::<ServerConnection>::new(
                            index,
                            Token(index * CHANNEL_CNT + CHANNEL_PROXY),
                            session,
                            stream,
                        ),
                        self.opts,
                    );
                    if conn.setup(poll) {
                        self.conns.insert(index, conn);
                    } else {
                        conn.close_now(poll);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("no more connection to be accepted");
                    break;
                }
                Err(err) => {
                    log::error!("accept failed with error:{}, exit now", err);
                    std::panic::panic_any(err)
                }
            }
        }
    }

    fn next_index(&mut self) -> usize {
        let index = self.next_id;
        self.next_id += 1;
        if self.next_id > MAX_INDEX {
            self.next_id = MIN_INDEX;
        }
        index
    }

    fn token2index(&mut self, token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub fn do_conn_event(
        &mut self,
        poll: &Poll,
        event: PollEvent,
        resolver: Option<&mut DnsResolver>,
    ) {
        let index = self.token2index(event.token());
        if self.conns.contains_key(&index) {
            let conn = self.conns.get_mut(&index).unwrap();
            conn.ready(poll, event, resolver);
            if conn.destroyed() {
                self.conns.remove(&index);
                log::debug!("connection:{} closed, remove from pool", index);
            }
        } else {
            log::error!("connection:{} not found to do event", index);
        }
    }

    pub fn check_timeout(&mut self, check_active_time: Instant, poll: &Poll) {
        let mut list = Vec::new();
        for (index, conn) in &mut self.conns {
            if conn.timeout(check_active_time) {
                list.push(*index);
                log::warn!("connection:{} timeout, close now", index);
                conn.close_now(poll)
            }
        }

        for index in list {
            self.conns.remove(&index);
        }
    }
}
