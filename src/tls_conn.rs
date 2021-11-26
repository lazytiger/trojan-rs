use std::{
    io::{ErrorKind, Read, Write},
    net::Shutdown,
};

use crate::status::{ConnStatus, StatusProvider};
use mio::{net::TcpStream, Interest, Poll, Token};
use rustls::Connection;

pub struct TlsConn {
    session: Connection,
    stream: TcpStream,
    index: usize,
    token: Token,
    status: ConnStatus,
    writable: bool,
}

impl TlsConn {
    pub fn new(index: usize, token: Token, mut session: Connection, stream: TcpStream) -> TlsConn {
        session.set_buffer_limit(None);
        TlsConn {
            index,
            token,
            session,
            stream,
            status: ConnStatus::Established,
            writable: true,
        }
    }

    pub fn reset_index(&mut self, index: usize, token: Token, poll: &Poll) -> bool {
        self.index = index;
        self.token = token;
        self.reregister(poll)
    }

    pub fn reregister(&mut self, poll: &Poll) -> bool {
        if let Err(err) = poll.registry().reregister(
            &mut self.stream,
            self.token,
            Interest::READABLE | Interest::WRITABLE,
        ) {
            log::warn!(
                "connection:{} reregister server failed:{}",
                self.index(),
                err
            );
            self.shutdown();
            false
        } else {
            log::trace!(
                "connection:{} reregistered token:{}",
                self.index(),
                self.token.0
            );
            true
        }
    }

    fn index(&self) -> usize {
        self.index
    }

    pub fn token(&self) -> Token {
        self.token
    }

    pub fn do_read(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.session.read_tls(&mut self.stream) {
                Ok(size) => {
                    if size == 0 {
                        log::warn!(
                            "connection:{} read from server failed with eof",
                            self.index()
                        );
                        self.shutdown();
                        break;
                    }
                    log::debug!(
                        "connection:{} read {} bytes from server",
                        self.index(),
                        size
                    );
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} read from server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::warn!(
                        "connection:{} read from server failed:{}",
                        self.index(),
                        err
                    );
                    self.shutdown();
                    break;
                }
            }
        }

        if let Err(err) = self.session.process_new_packets() {
            log::error!(
                "connection:{} process new packets failed:{}",
                self.index(),
                err
            );
            self.shutdown();
            return None;
        }

        let mut buffer = Vec::new();
        if let Err(err) = self.session.reader().read_to_end(&mut buffer) {
            if err.kind() != ErrorKind::WouldBlock {
                log::warn!(
                    "connection:{} read from session failed:{}",
                    self.index(),
                    err
                );
                self.shutdown();
            }
        }
        if buffer.is_empty() {
            None
        } else {
            Some(buffer)
        }
    }

    pub fn do_send(&mut self) {
        loop {
            if !self.session.wants_write() {
                break;
            }
            match self.session.write_tls(&mut self.stream) {
                Ok(size) => {
                    log::debug!("connection:{} write {} bytes to server", self.index(), size);
                    self.writable = true;
                    continue;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} write to server blocked", self.index());
                    self.writable = false;
                }
                Err(err) => {
                    log::warn!("connection:{} write to server failed:{}", self.index(), err);
                    self.shutdown();
                }
            }
            break;
        }
    }

    pub fn write_session(&mut self, data: &[u8]) -> bool {
        match self.session.writer().write_all(data) {
            Ok(_) => true,
            Err(err) => {
                self.shutdown();
                log::warn!(
                    "connection:{} write data to server session failed:{}",
                    self.index(),
                    err
                );
                false
            }
        }
    }

    pub fn register(&mut self, poll: &Poll) -> bool {
        if let Err(err) = poll.registry().register(
            &mut self.stream,
            self.token,
            Interest::READABLE | Interest::WRITABLE,
        ) {
            log::warn!("connection:{} register server failed:{}", self.index(), err);
            self.shutdown();
            false
        } else {
            log::trace!(
                "connection:{} token:{} registered",
                self.index(),
                self.token.0
            );
            true
        }
    }

    pub fn deregistered(&self) -> bool {
        matches!(self.status, ConnStatus::Deregistered)
    }

    pub fn writable(&self) -> bool {
        self.writable && self.alive()
    }
}

impl StatusProvider for TlsConn {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status;
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn deregister(&mut self, poll: &Poll) {
        let _ = poll.registry().deregister(&mut self.stream);
    }

    fn finish_send(&mut self) -> bool {
        !self.session.wants_write()
    }
}
