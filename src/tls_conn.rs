use std::io::ErrorKind;

use mio::{Poll, PollOpt, Ready, Token};
use mio::net::TcpStream;
use mio::tcp::Shutdown;
use rustls::Session;

#[derive(Copy, Clone)]
pub enum ConnStatus {
    Established,
    Shutdown,
    Closing,
    Closed,
}

pub struct TlsConn<T: Session> {
    session: T,
    stream: TcpStream,
    readiness: Ready,
    index: usize,
    token: Token,
    status: ConnStatus,
}

impl<T: Session> TlsConn<T> {
    pub fn new(index: usize, token: Token, session: T, stream: TcpStream) -> TlsConn<T> {
        TlsConn {
            index,
            token,
            session,
            stream,
            readiness: Ready::readable() | Ready::writable(),
            status: ConnStatus::Established,
        }
    }

    pub fn reset_index(&mut self, index: usize, token: Token) {
        self.index = index;
        self.token = token;
    }

    pub fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            self.close_now(poll);
        }
    }

    pub fn shutdown(&mut self, poll: &Poll) {
        if !self.session.wants_write() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }
        self.readiness = Ready::writable();
        self.status = ConnStatus::Shutdown;
        self.setup(poll);
    }

    pub fn close_now(&mut self, poll: &Poll) {
        let _ = poll.deregister(&self.stream);
        let _ = self.stream.shutdown(Shutdown::Both);
        self.status = ConnStatus::Closed
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
                        log::warn!("connection:{} read from server failed with eof", self.index());
                        self.status = ConnStatus::Closing;
                        return None;
                    }
                    log::info!("connection:{} read {} bytes from server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} read from server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} read from server failed:{}", self.index(), err);
                    self.status = ConnStatus::Closing;
                    return None;
                }
            }
        }

        if let Err(err) = self.session.process_new_packets() {
            log::error!("connection:{} process new packets failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
            return None;
        }

        let mut buffer = Vec::new();
        if let Err(err) = self.session.read_to_end(&mut buffer) {
            log::warn!("connection:{} read from session failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
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
                return;
            }
            match self.session.write_tls(&mut self.stream) {
                Ok(size) => {
                    log::debug!("connection:{} write {} bytes to server", self.index(), size);
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} write to server failed:{}", self.index(), err);
                    self.status = ConnStatus::Closing;
                    return;
                }
            }
        }
        if let ConnStatus::Shutdown = self.status {
            if !self.session.wants_write() {
                self.status = ConnStatus::Closing;
                log::info!("connection:{} is closing for no data to send", self.index());
            }
        }
    }

    pub fn write_session(&mut self, data: &[u8]) -> bool {
        if let Err(err) = self.session.write_all(data) {
            self.status = ConnStatus::Closing;
            log::warn!("connection:{} write data to server session failed:{}", self.index(), err);
            false
        } else {
            true
        }
    }

    pub fn reregister(&mut self, poll: &Poll) {
        match self.status {
            ConnStatus::Closing => {
                let _ = poll.deregister(&self.stream);
            }
            ConnStatus::Closed => {
                return;
            }
            _ => {
                let mut changed = false;
                if self.session.wants_write() && !self.readiness.is_writable() {
                    self.readiness.insert(Ready::writable());
                    changed = true;
                }
                if !self.session.wants_write() && self.readiness.is_writable() {
                    self.readiness.remove(Ready::writable());
                    changed = true;
                }
                if changed {
                    self.setup(poll);
                }
            }
        }
    }

    pub fn setup(&mut self, poll: &Poll) -> bool {
        if let Err(err) = poll.register(&self.stream, self.token(), self.readiness, PollOpt::level()) {
            log::warn!("connection:{} register server failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
            false
        } else {
            true
        }
    }

    pub fn closed(&self) -> bool {
        if let ConnStatus::Closed = self.status {
            true
        } else {
            false
        }
    }
}