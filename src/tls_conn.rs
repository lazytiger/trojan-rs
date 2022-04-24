use std::{
    io::{Error, ErrorKind, Read, Write},
    net::Shutdown,
};

use mio::{net::TcpStream, Interest, Poll, Token};
use rustls::Connection;

use crate::status::{ConnStatus, StatusProvider};

pub struct TlsConn {
    session: Connection,
    stream: TcpStream,
    index: usize,
    token: Token,
    status: ConnStatus,
    writable: bool,
}

impl TlsConn {
    pub(crate) fn close(&mut self, poll: &Poll) {
        let _ = self.stream.shutdown(Shutdown::Both);
        let _ = poll.registry().deregister(&mut self.stream);
    }
}

impl Read for TlsConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.session.wants_read() {
            log::info!("read from stream now");
            match self.session.read_tls(&mut self.stream) {
                Ok(0) => Ok(0),
                Ok(n) => {
                    log::info!("read {} byte tls data from stream", n);
                    if let Err(err) = self.session.process_new_packets() {
                        Err(Error::new(ErrorKind::InvalidData, err))
                    } else {
                        log::info!("process new packets success");
                        self.read(buf)
                    }
                }
                Err(err) => Err(err),
            }
        } else {
            log::info!("read from session now");
            self.session.reader().read(buf)
        }
    }
}

impl Write for TlsConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.session.wants_write() {
            log::info!("send data to stream now");
            match self.session.write_tls(&mut self.stream) {
                Ok(0) => Ok(0),
                Ok(n) => {
                    log::info!("send {} bytes tls data to remote stream", n);
                    self.write(buf)
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::info!("remote stream blocked, send data to session");
                    self.session.writer().write(buf)
                }
                Err(err) => Err(err),
            }
        } else {
            log::info!("send data to session now");
            self.session.writer().write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.session.write_tls(&mut self.stream).map(|n| {
            log::info!("flush {} bytes tls data to stream", n);
        })
    }
}

impl TlsConn {
    pub fn new(index: usize, token: Token, mut session: Connection, stream: TcpStream) -> TlsConn {
        session.set_buffer_limit(None);
        TlsConn {
            index,
            token,
            session,
            stream,
            writable: true,
            status: ConnStatus::Connecting,
        }
    }

    pub fn reset_index(&mut self, index: usize, token: Token, poll: &Poll) -> bool {
        self.index = index;
        self.token = token;
        self.reregister(poll)
    }

    pub fn set_token(&mut self, token: Token, poll: &Poll) -> bool {
        self.token = token;
        poll.registry()
            .reregister(
                &mut self.stream,
                self.token,
                Interest::WRITABLE | Interest::READABLE,
            )
            .is_ok()
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
                        log::info!(
                            "connection:{} read from server failed with eof",
                            self.index()
                        );
                        self.shutdown();
                        break;
                    }
                    log::info!(
                        "connection:{} read {} bytes from server",
                        self.index(),
                        size
                    );
                }
                Err(err)
                    if err.kind() == ErrorKind::WouldBlock
                        || err.kind() == ErrorKind::NotConnected =>
                {
                    log::debug!("connection:{} read from server blocked", self.index());
                    break;
                }
                Err(err) => {
                    log::info!(
                        "connection:{} read from server failed:{}-{}",
                        self.index(),
                        err.kind(),
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
                log::info!(
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
        if self.is_connecting() {
            log::info!("connection is not ready");
            return;
        }
        self.writable = true;
        loop {
            if !self.session.wants_write() {
                log::info!("nothing in session");
                break;
            }
            match self.session.write_tls(&mut self.stream) {
                Ok(size) => {
                    log::info!("connection:{} write {} bytes to server", self.index(), size);
                    continue;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::debug!("connection:{} write to server blocked", self.index());
                    self.writable = false;
                }
                Err(err) => {
                    log::info!("connection:{} write to server failed:{}", self.index(), err);
                    self.shutdown();
                }
            }
            break;
        }
    }

    pub fn write_session(&mut self, data: &[u8]) -> bool {
        match self.session.writer().write_all(data) {
            Ok(_) => {
                log::info!("write {} byte to session", data.len());
                true
            }
            Err(err) => {
                self.shutdown();
                log::info!(
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

    fn close_conn(&mut self) -> bool {
        let _ = self.stream.shutdown(Shutdown::Both);
        true
    }

    fn deregister(&mut self, poll: &Poll) -> bool {
        let _ = poll.registry().deregister(&mut self.stream);
        true
    }

    fn finish_send(&mut self) -> bool {
        !self.session.wants_write()
    }
}
