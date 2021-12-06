use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use mio::{event::Event, net::TcpStream, Poll, Token};
use rustls::{ClientConfig, ClientConnection, Connection, ServerName};

use crate::{
    config::OPTIONS, resolver::DnsResolver, status::StatusProvider, tls_conn::TlsConn,
    types::Result,
};

pub struct IdlePool {
    pool: Vec<TlsConn>,
    next_index: usize,
    size: usize,
    addr: SocketAddr,
    domain: String,
    port: u16,
    config: Arc<ClientConfig>,
    hostname: ServerName,
    channel_cnt: usize,
    channel_idle: usize,
    min_index: usize,
    max_index: usize,
}

impl IdlePool {
    pub fn new(
        config: Arc<ClientConfig>,
        hostname: ServerName,
        size: usize,
        port: u16,
        domain: String,
    ) -> IdlePool {
        IdlePool {
            size,
            config,
            hostname,
            port,
            domain,
            channel_cnt: 0,
            channel_idle: 0,
            min_index: 0,
            max_index: 0,
            addr: OPTIONS.back_addr.unwrap(),
            pool: Vec::new(),
            next_index: 0,
        }
    }

    pub fn init_index(
        &mut self,
        channel_cnt: usize,
        channel_idle: usize,
        min_index: usize,
        max_index: usize,
    ) {
        self.channel_cnt = channel_cnt;
        self.channel_idle = channel_idle;
        self.min_index = min_index;
        self.max_index = max_index;
        self.next_index = min_index;
    }

    pub fn init(&mut self, poll: &Poll, resolver: &DnsResolver) {
        if self.size > 1 {
            self.alloc(poll, resolver);
        }
    }

    pub fn get(&mut self, poll: &Poll, resolver: &DnsResolver) -> Option<TlsConn> {
        self.alloc(poll, resolver);
        self.pool.pop()
    }

    fn alloc(&mut self, poll: &Poll, resolver: &DnsResolver) {
        let size = self.pool.len();
        for _ in size..self.size {
            match self.new_conn() {
                Ok(mut conn) => {
                    if conn.register(poll) {
                        self.pool.push(conn);
                    } else {
                        conn.check_status(poll);
                    }
                }
                Err(err) => {
                    log::error!("new connection to remote server failed:{:?}", err);
                    self.update_dns(resolver);
                }
            }
        }
    }

    fn next_index(&mut self) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        if self.next_index >= self.max_index {
            self.next_index = self.min_index;
        }
        index
    }

    fn new_conn(&mut self) -> Result<TlsConn> {
        let server = TcpStream::connect(self.addr)?;
        //sys::set_mark(&server, self.marker)?;
        #[cfg(not(target_os = "windows"))]
        server.set_nodelay(true)?;

        let session = ClientConnection::new(self.config.clone(), self.hostname.clone())?;
        let index = self.next_index();
        let conn = TlsConn::new(
            index,
            Token(index * self.channel_cnt + self.channel_idle),
            Connection::Client(session),
            server,
        );
        Ok(conn)
    }

    fn update_dns(&mut self, resolver: &DnsResolver) {
        resolver.resolve(self.domain.clone(), None);
    }

    pub fn resolve(&mut self, ip: Option<IpAddr>) {
        if let Some(address) = ip {
            log::debug!("idle_pool got resolve result {} = {}", self.domain, address);
            let addr = SocketAddr::new(address, self.port);
            self.addr = addr;
        } else {
            log::error!("idle_pool resolve host:{} failed", self.domain);
        }
    }

    pub fn ready(&mut self, event: &Event, poll: &Poll) {
        let mut found = false;
        for i in 0..self.pool.len() {
            let conn = self.pool.get_mut(i).unwrap();
            if conn.token() == event.token() {
                if event.is_readable() && conn.do_read().is_some() {
                    log::error!("found data in https handshake phase");
                }
                if event.is_writable() {
                    conn.established();
                    conn.do_send();
                }
                conn.check_status(poll);
                if conn.deregistered() {
                    self.pool.remove(i);
                }
                found = true;
                break;
            }
        }
        if !found {
            log::error!("idle token:{} not found", event.token().0);
        }
    }
}
