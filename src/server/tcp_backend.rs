use std::io::Write;
use std::net::Shutdown;
use std::time::Duration;
use std::time::Instant;

use bytes::Buf;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::TcpStream;
use rustls::ServerSession;

use crate::config::Opts;
use crate::server::server::Backend;
use crate::session::TcpSession;
use crate::tls_conn::{ConnStatus, TlsConn};

pub struct TcpBackend {
    conn: TcpStream,
    session: TcpSession,
    status: ConnStatus,
    readiness: Ready,
    index: usize,
    token: Token,
    timeout: Duration,
}

impl TcpBackend {
    pub fn new(conn: TcpStream, index: usize, token: Token, timeout: Duration) -> TcpBackend {
        TcpBackend {
            conn,
            timeout,
            session: TcpSession::new(index),
            status: ConnStatus::Established,
            readiness: Ready::readable(),
            index,
            token,
        }
    }
    fn do_read(&mut self, conn: &mut TlsConn<ServerSession>) {
        match self.session.read_backend(&mut self.conn) {
            Err(err) => {
                log::warn!("connection:{} read from target failed:{}", self.index, err);
                self.status = ConnStatus::Closing;
                return;
            }
            Ok(size) => {
                log::debug!("connection:{} read {} bytes from target", self.index, size);
            }
        }

        let buffer = self.session.read_all();
        if !buffer.is_empty() {
            if !conn.write_session(buffer.bytes()) {
                self.status = ConnStatus::Closing;
                return;
            } else {
                conn.do_send();
            }
        }
    }

    fn do_send(&mut self) {
        match self.session.write_backend(&mut self.conn) {
            Err(err) => {
                log::warn!("connection:{} write to target failed:{}", self.index, err);
                self.status = ConnStatus::Closing;
            }
            Ok(size) => {
                log::debug!("connection:{} write {} bytes to target", self.index, size);
            }
        }
        if let ConnStatus::Shutdown = self.status {
            if !self.session.wants_write() {
                log::info!("connection:{} is closing for no data to send", self.index);
                self.status = ConnStatus::Closing;
            }
        }
    }

    fn setup(&mut self, poll: &Poll) {
        if let Err(err) = poll.reregister(&self.conn,
                                          self.token, self.readiness, PollOpt::edge()) {
            log::error!("connection:{} reregister tcp target failed:{}", self.index, err);
            self.status = ConnStatus::Closing;
        }
    }
}

impl Backend for TcpBackend {
    fn ready(&mut self, event: &Event, _: &mut Opts, conn: &mut TlsConn<ServerSession>) {
        if event.readiness().is_readable() {
            self.do_read(conn);
        }

        if event.readiness().is_writable() {
            self.do_send();
        }
    }

    fn dispatch(&mut self, mut buffer: &[u8], _: &mut Opts) {
        // send immediately first
        if self.session.wants_write() {
            if let Err(err) = self.session.write_all(buffer) {
                self.status = ConnStatus::Closing;
                log::error!("connection:{} write to back sesion failed:{}", self.index, err);
                return;
            }
            self.do_send();
            return;
        }

        loop {
            if buffer.len() == 0 {
                break;
            }
            match self.conn.write(buffer) {
                Ok(size) => {
                    buffer = &buffer[size..];
                    log::debug!("connection:{} send {} bytes data to target", self.index, size);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    // if data remains, copy to back session.
                    if let Err(err) = self.session.write_all(buffer) {
                        log::error!("connection:{} send to target session failed:{}", self.index, err);
                        self.status = ConnStatus::Closing;
                    }
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} send to target failed:{}", self.index, err);
                    self.status = ConnStatus::Closing;
                    break;
                }
            }
        }
    }

    fn reregister(&mut self, poll: &Poll) {
        match self.status {
            ConnStatus::Closing => {
                let _ = poll.deregister(&self.conn);
            }
            ConnStatus::Closed => {
                return;
            }
            _ => {
                let mut changed = false;
                if self.session.wants_write() && !self.readiness.is_writable() {
                    self.readiness.insert(Ready::writable());
                    changed = true;
                    log::info!("connection:{} add writable to tcp target", self.index);
                }
                if !self.session.wants_write() && self.readiness.is_writable() {
                    self.readiness.remove(Ready::writable());
                    changed = true;
                    log::info!("connection:{} remove writable from tcp target", self.index);
                }

                if changed {
                    self.setup(poll);
                }
            }
        }
    }

    fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            let _ = poll.deregister(&self.conn);
            let _ = self.conn.shutdown(Shutdown::Both);
            self.status = ConnStatus::Closed;
        }
    }

    fn timeout(&self, _: Instant, _: Instant) -> bool {
        return false;
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn shutdown(&mut self, poll: &Poll) {
        if !self.session.wants_write() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }

        self.readiness = Ready::writable();
        self.status = ConnStatus::Shutdown;
        self.setup(poll);
        self.check_close(poll);
    }
}
