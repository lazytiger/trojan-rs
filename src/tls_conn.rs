use std::{
    io::{Error, ErrorKind, Read, Write},
    net::{IpAddr, Shutdown},
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
    #[allow(dead_code)]
    pub(crate) fn close(&mut self, poll: &Poll) {
        let _ = self.stream.shutdown(Shutdown::Both);
        let _ = poll.registry().deregister(&mut self.stream);
    }
}

impl Read for TlsConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        debug_assert!(!buf.is_empty());
        //1. read from session
        //1.1 session return WouldBlock,
        let ret = self.session.reader().read(buf);
        log::info!("reader.read return {:?}", ret);
        match ret {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                let ret = self.session.read_tls(&mut self.stream);
                log::info!("session.read_tls return {:?}", ret);
                match ret {
                    Ok(n) if n > 0 => {
                        log::info!("read {} byte tls data from stream", n);
                        if let Err(err) = self.session.process_new_packets() {
                            Err(Error::new(ErrorKind::InvalidData, err))
                        } else {
                            log::info!("process new packets success");
                            self.read(buf)
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::NotConnected => {
                        Err(ErrorKind::WouldBlock.into())
                    }
                    ret => ret,
                }
            }
            ret => ret,
        }
    }
}

impl Write for TlsConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        debug_assert!(!buf.is_empty());
        let ret = self.session.writer().write(buf);
        log::info!("writer.write return {:?}", ret);
        match ret {
            Ok(0) => {
                let ret = self.session.write_tls(&mut self.stream);
                log::info!("session.write_tls return {:?}", ret);
                match ret {
                    Err(err) if err.kind() == ErrorKind::NotConnected => {
                        Err(ErrorKind::WouldBlock.into())
                    }
                    Ok(m) if m > 0 => self.write(buf),
                    ret => ret,
                }
            }
            ret => ret,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.session
            .write_tls(&mut self.stream)
            .map(|n| {
                log::info!("flush {} bytes tls data to stream", n);
            })
            .map_err(|err| {
                if err.kind() == ErrorKind::NotConnected {
                    ErrorKind::WouldBlock.into()
                } else {
                    err
                }
            })
    }
}

impl TlsConn {
    pub fn new(index: usize, token: Token, session: Connection, stream: TcpStream) -> TlsConn {
        TlsConn {
            index,
            token,
            session,
            stream,
            writable: true,
            status: ConnStatus::Connecting,
        }
    }

    pub fn source(&self) -> Option<IpAddr> {
        self.stream.peer_addr().map(|addr| addr.ip()).ok()
    }

    pub fn reset_index(&mut self, index: usize, token: Token, poll: &Poll) -> bool {
        self.index = index;
        self.token = token;
        self.reregister(poll)
    }

    #[allow(dead_code)]
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
            log::info!(
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
