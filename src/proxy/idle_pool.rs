use std::{net::SocketAddr, sync::Arc};

use mio::{event::Event, net::TcpStream, Poll, Token};
use rustls::{ClientConfig, ClientSession};
use webpki::DNSName;

use crate::{
    config::Opts,
    proxy::{next_index, CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, RESOLVER},
    resolver::EventedResolver,
    sys,
    tls_conn::TlsConn,
};
use std::net::IpAddr;

pub struct IdlePool {
    pool: Vec<TlsConn<ClientSession>>,
    next_index: usize,
    size: usize,
    addr: SocketAddr,
    domain: String,
    port: u16,
    marker: u8,
    config: Arc<ClientConfig>,
    hostname: DNSName,
}

impl IdlePool {
    pub fn new(opts: &Opts, config: Arc<ClientConfig>, hostname: DNSName) -> IdlePool {
        IdlePool {
            size: opts.proxy_args().pool_size + 1,
            addr: opts.back_addr.unwrap(),
            marker: opts.marker,
            port: opts.proxy_args().port,
            domain: opts.proxy_args().hostname.clone(),
            pool: Vec::new(),
            next_index: MIN_INDEX,
            config,
            hostname,
        }
    }

    pub fn init(&mut self, poll: &Poll, resolver: &EventedResolver) {
        if self.size > 1 {
            self.alloc(poll, resolver);
        }
    }

    pub fn get(
        &mut self,
        poll: &Poll,
        resolver: &EventedResolver,
    ) -> Option<TlsConn<ClientSession>> {
        self.alloc(poll, resolver);
        self.pool.pop()
    }

    fn alloc(&mut self, poll: &Poll, resolver: &EventedResolver) {
        let size = self.pool.len();
        for _ in size..self.size {
            let conn = self.new_conn();
            if let Some(mut conn) = conn {
                if conn.register(poll) {
                    self.pool.push(conn);
                }
            } else {
                self.update_dns(resolver);
            }
        }
    }

    fn new_conn(&mut self) -> Option<TlsConn<ClientSession>> {
        let server = match TcpStream::connect(self.addr) {
            Ok(server) => {
                if let Err(err) = sys::set_mark(&server, self.marker) {
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
                log::error!("connection to server failed:{}", err);
                None
            }
        };
        if let Some(server) = server {
            let session = ClientSession::new(&self.config, self.hostname.as_ref());
            let index = next_index(&mut self.next_index);
            let conn = TlsConn::new(
                index,
                Token(index * CHANNEL_CNT + CHANNEL_IDLE),
                session,
                server,
            );
            Some(conn)
        } else {
            None
        }
    }

    fn update_dns(&mut self, resolver: &EventedResolver) {
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
