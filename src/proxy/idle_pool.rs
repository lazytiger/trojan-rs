use std::net::SocketAddr;
use std::sync::Arc;

use mio::{Event, Poll, Token};
use mio::net::TcpStream;
use rustls::{ClientConfig, ClientSession};
use webpki::DNSName;

use crate::sys;
use crate::config::Opts;
use crate::proxy::{MIN_INDEX, next_index};
use crate::tls_conn::{Index, TlsConn};

struct IdleIndex(usize);

impl Index for IdleIndex {
    fn token(&self) -> Token {
        Token(self.0 * 4)
    }

    fn index(&self) -> usize {
        self.0
    }
}

pub struct IdlePool {
    pool: Vec<TlsConn<ClientSession>>,
    next_index: usize,
    size: usize,
    addr: SocketAddr,
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
            pool: Vec::new(),
            next_index: MIN_INDEX,
            config,
            hostname,
        }
    }

    pub fn get(&mut self, poll: &Poll) -> Option<TlsConn<ClientSession>> {
        self.alloc(poll);
        self.pool.pop()
    }

    fn alloc(&mut self, poll: &Poll) {
        let size = self.pool.len();
        for _ in size..self.size {
            let conn = self.new_conn();
            if let Some(mut conn) = conn {
                if conn.setup(poll) {
                    self.pool.push(conn);
                }
            }
        }
    }

    fn new_conn(&mut self) -> Option<TlsConn<ClientSession>> {
        let server = match TcpStream::connect(&self.addr) {
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
                //FIXME should refresh dns now?
                log::error!("connection to server failed:{}", err);
                None
            }
        };
        if let Some(server) = server {
            let session = ClientSession::new(&self.config, self.hostname.as_ref());
            let conn = TlsConn::new(Box::new(IdleIndex(next_index(&mut self.next_index))), session, server);
            Some(conn)
        } else {
            None
        }
    }

    pub fn ready(&mut self, event: &Event, poll: &Poll) {
        for conn in &mut self.pool {
            if conn.token() == event.token() {
                if event.readiness().is_readable() {
                    conn.do_read();
                }
                if event.readiness().is_writable() {
                    conn.do_send();
                }
                conn.check_close(poll);
                break;
            }
        }
    }
}