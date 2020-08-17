use std::io::ErrorKind;

use mio::{Poll, PollOpt, Ready, Token};
use mio::net::TcpStream;
use mio::tcp::Shutdown;
use rustls::Session;

enum ConnStatus {
    Established,
    Closing,
    Closed,
}

pub trait Index {
    fn token(&self) -> Token;
    fn index(&self) -> usize;
}

pub struct TlsConn<T: Session> {
    session: T,
    stream: TcpStream,
    readiness: Ready,
    index: Box<dyn Index>,
    status: ConnStatus,
}

impl<T: Session> TlsConn<T> {
    pub fn new(index: Box<dyn Index>, session: T, stream: TcpStream) -> TlsConn<T> {
        TlsConn {
            index,
            session,
            stream,
            readiness: Ready::readable() | Ready::writable(),
            status: ConnStatus::Established,
        }
    }

    pub fn reset_index(&mut self, index: Box<dyn Index>) {
        self.index = index;
    }

    pub fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            self.close_now(poll);
        }
    }

    pub fn close_now(&mut self, poll: &Poll) {
        let _ = poll.deregister(&self.stream);
        let _ = self.stream.shutdown(Shutdown::Both);
        self.status = ConnStatus::Closed
    }

    fn index(&self) -> usize {
        self.index.index()
    }

    pub fn token(&self) -> Token {
        self.index.token()
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
            log::error!("connection:{} read from session failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
            return None;
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
            if let Err(err) = poll.reregister(&self.stream, self.index.token(), self.readiness, PollOpt::level()) {
                log::error!("connection:{} reregister server failed:{}", self.index(), err);
                self.status = ConnStatus::Closing;
                return;
            }
        }
    }

    pub fn setup(&mut self, poll: &Poll) -> bool {
        if let Err(err) = poll.register(&self.stream, self.index.token(), self.readiness, PollOpt::level()) {
            log::warn!("connection:{} register server failed:{}", self.index(), err);
            self.status = ConnStatus::Closing;
            false
        } else {
            true
        }
    }
}