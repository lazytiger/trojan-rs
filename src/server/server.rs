use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use mio::{Event, Poll};
use mio::net::TcpListener;
use rustls::{ServerConfig, ServerSession};

use crate::config::Opts;
use crate::server::connection::Connection;

pub struct TlsServer {
    listener: TcpListener,
    config: Arc<ServerConfig>,
    next_id: usize,
    conns: HashMap<usize, Connection>,
}

impl TlsServer {
    pub fn new(listener: TcpListener, config: Arc<ServerConfig>) -> TlsServer {
        TlsServer {
            listener,
            config,
            next_id: 2,
            conns: HashMap::new(),
        }
    }

    pub fn accept(&mut self, poll: &Poll, opts: &Opts) {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    log::debug!("get new connection, toke:{}, address:{}", self.next_id, addr);
                    let session = ServerSession::new(&self.config);
                    let index = self.next_index();
                    let mut conn = Connection::new(index, stream, session);
                    if conn.setup(poll, opts) {
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
                    panic!(err)
                }
            }
        }
    }

    fn next_index(&mut self) -> usize {
        let index = self.next_id;
        self.next_id += 1;
        if self.next_id == 0 {
            self.next_id = 2;
        }
        index
    }

    pub fn do_conn_event(&mut self, poll: &Poll, event: &Event, opts: &mut Opts) {
        let index = event.token().0 >> 1;
        if self.conns.contains_key(&index) {
            let conn = self.conns.get_mut(&index).unwrap();
            conn.ready(poll, event, opts);
            if conn.is_closed() {
                self.conns.remove(&index);
                log::info!("connection:{} closed, remove from pool", index);
            }
        } else {
            log::error!("connection:{} not found", index);
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