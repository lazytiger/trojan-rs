use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{event::Event, net::TcpListener, Poll, Token};
use rustls::{ServerConfig, ServerConnection};

use crate::{
    resolver::DnsResolver,
    server::{
        connection::Connection, stat::Statistics, CHANNEL_CNT, CHANNEL_PROXY, MAX_INDEX, MIN_INDEX,
    },
    status::StatusProvider,
    tls_conn::TlsConn,
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
    removed: Option<Vec<usize>>,
}

pub trait Backend: StatusProvider {
    fn dispatch(&mut self, data: &[u8], stats: &mut Statistics);
    fn timeout(&self, t1: Instant, t2: Instant) -> bool {
        t2 - t1 > self.get_timeout()
    }
    fn get_timeout(&self) -> Duration;
    fn writable(&self) -> bool;
    fn do_read(&mut self, conn: &mut TlsConn, stats: &mut Statistics);
    fn dst_ip(&self) -> Option<IpAddr>;
}

impl TlsServer {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> TlsServer {
        TlsServer {
            listener,
            config,
            removed: Some(Vec::new()),
            next_id: MIN_INDEX,
            conns: HashMap::new(),
        }
    }

    pub(crate) fn poll_ping(&mut self, stats: &mut Statistics) {
        self.conns.iter_mut().for_each(|(_, conn)| {
            conn.poll_ping(stats);
        })
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
                    if let Err(err) = stream.set_nodelay(true) {
                        log::error!("set nodelay failed:{}", err);
                        continue;
                    }
                    let session = ServerConnection::new(self.config.clone()).unwrap();
                    let index = self.next_index();
                    let mut tls_conn = TlsConn::new(
                        index,
                        Token(index * CHANNEL_CNT + CHANNEL_PROXY),
                        rustls::Connection::Server(session),
                        stream,
                    );
                    if tls_conn.register(poll) {
                        let conn = Connection::new(index, tls_conn);
                        self.conns.insert(index, conn);
                    } else {
                        tls_conn.shutdown();
                        tls_conn.check_status(poll);
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
        stats: &mut Statistics,
    ) {
        let index = self.token2index(event.token());
        if self.conns.contains_key(&index) {
            let conn = self.conns.get_mut(&index).unwrap();
            conn.ready(poll, event, resolver, stats);
            if conn.destroyed() {
                self.removed.as_mut().unwrap().push(index);
            }
        } else {
            log::error!("connection:{} not found to do event", index);
        }
    }

    pub fn remove_closed(&mut self) {
        if self.removed.as_ref().unwrap().is_empty() {
            return;
        }
        let removed = self.removed.replace(Vec::new()).unwrap();
        for index in removed {
            self.conns.remove(&index);
            log::debug!("connection:{} closed, remove from pool", index);
        }
    }

    pub fn check_timeout(&mut self, check_active_time: Instant, poll: &Poll) {
        let list: Vec<_> = self
            .conns
            .iter_mut()
            .filter_map(|(index, conn)| {
                if !conn.destroyed() && conn.timeout(check_active_time) {
                    log::warn!("connection:{} timeout, close now", index);
                    conn.destroy(poll);
                }
                if conn.destroyed() {
                    Some(*index)
                } else {
                    None
                }
            })
            .collect();

        for index in list {
            self.conns.remove(&index);
        }
    }
}
