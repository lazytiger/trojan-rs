use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use mio::{event::Event, net::TcpStream, Poll, Token};
use rustls::{ClientConfig, ClientConnection, Connection, ServerName};

use crate::{
    config::OPTIONS,
    proxy::{next_index, CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, RESOLVER},
    resolver::DnsResolver,
    sys,
    tls_conn::TlsConn,
    types::Result,
};

pub struct IdlePool {
    pool: Vec<TlsConn>,
    next_index: usize,
    size: usize,
    addr: SocketAddr,
    domain: String,
    port: u16,
    marker: u8,
    config: Arc<ClientConfig>,
    hostname: ServerName,
}

impl IdlePool {
    pub fn new(config: Arc<ClientConfig>, hostname: ServerName) -> IdlePool {
        IdlePool {
            size: OPTIONS.proxy_args().pool_size + 1,
            addr: OPTIONS.back_addr.unwrap(),
            marker: OPTIONS.marker,
            port: OPTIONS.proxy_args().port,
            domain: OPTIONS.proxy_args().hostname.clone(),
            pool: Vec::new(),
            next_index: MIN_INDEX,
            config,
            hostname,
        }
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
                    }
                }
                Err(err) => {
                    log::error!("new connection to remote server failed:{}", err);
                    self.update_dns(resolver);
                }
            }
        }
    }

    fn new_conn(&mut self) -> Result<TlsConn> {
        let server = TcpStream::connect(self.addr)?;
        sys::set_mark(&server, self.marker)?;
        server.set_nodelay(true)?;
        let session = ClientConnection::new(self.config.clone(), self.hostname.clone())?;
        let index = next_index(&mut self.next_index);
        let conn = TlsConn::new(
            index,
            Token(index * CHANNEL_CNT + CHANNEL_IDLE),
            Connection::Client(session),
            server,
        );
        Ok(conn)
    }

    fn update_dns(&mut self, resolver: &DnsResolver) {
        resolver.resolve(self.domain.clone(), Token(RESOLVER));
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
                    conn.do_send();
                }
                conn.reregister(poll, true);
                conn.check_close(poll);
                if conn.closed() {
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
