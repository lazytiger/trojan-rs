use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::UdpSocket;
use rustls::ServerSession;

use crate::config::Opts;
use crate::proto::{MAX_BUFFER_SIZE, MAX_PACKET_SIZE, UdpAssociate, UdpParseResult};
use crate::server::server::Backend;
use crate::tls_conn::{ConnStatus, TlsConn};

pub struct UdpBackend {
    socket: UdpSocket,
    send_buffer: BytesMut,
    recv_body: Vec<u8>,
    recv_head: BytesMut,
    index: usize,
    token: Token,
    status: ConnStatus,
    readiness: Ready,
    timeout: Duration,
    bytes_read: usize,
    bytes_sent: usize,
    remote_addr: SocketAddr,
}

impl UdpBackend {
    pub fn new(socket: UdpSocket, index: usize, token: Token, timeout: Duration) -> UdpBackend {
        let remote_addr = socket.local_addr().unwrap();
        UdpBackend {
            socket,
            send_buffer: Default::default(),
            recv_body: vec![0u8; MAX_PACKET_SIZE],
            recv_head: Default::default(),
            index,
            token,
            status: ConnStatus::Established,
            readiness: Ready::empty(),
            timeout,
            bytes_read: 0,
            bytes_sent: 0,
            remote_addr,
        }
    }

    fn do_send(&mut self, mut buffer: &[u8], opts: &mut Opts) {
        loop {
            match UdpAssociate::parse(buffer, opts) {
                UdpParseResult::Packet(packet) => {
                    match self.socket.send_to(&packet.payload[..packet.length], &packet.address) {
                        Ok(size) => {
                            self.bytes_sent += size;
                            if size != packet.length {
                                log::error!("connection:{} udp packet is truncated, {}：{}", self.index, packet.length, size);
                                self.status = ConnStatus::Closing;
                                return;
                            }
                            log::debug!("connection:{} write {} bytes to udp target:{}", self.index, size, packet.address);
                            buffer = &packet.payload[packet.length..];
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            log::debug!("connection:{} write to udp target blocked", self.index);
                            self.send_buffer.extend_from_slice(buffer);
                            break;
                        }
                        Err(err) => {
                            log::warn!("connection:{} send_to {} failed:{}", self.index, packet.address, err);
                            self.status = ConnStatus::Closing;
                            return;
                        }
                    }
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid udp protocol", self.index);
                    self.status = ConnStatus::Closing;
                    return;
                }
                UdpParseResult::Continued => {
                    log::trace!("connection:{} got partial request", self.index);
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
            }
        }
        if let ConnStatus::Shutdown = self.status {
            if self.send_buffer.is_empty() {
                log::debug!("connection:{} is closing for no data to send", self.index);
                self.status = ConnStatus::Closing;
            }
        }
    }

    fn do_read(&mut self, conn: &mut TlsConn<ServerSession>) {
        loop {
            match self.socket.recv_from(self.recv_body.as_mut_slice()) {
                Ok((size, addr)) => {
                    self.remote_addr = addr;
                    self.bytes_read += size;
                    if size == MAX_PACKET_SIZE {
                        log::error!("received {} bytes udp data, packet fragmented", size);
                    }
                    log::debug!("connection:{} got {} bytes udp data from:{}", self.index, size, addr);
                    self.recv_head.clear();
                    UdpAssociate::generate(&mut self.recv_head, &addr, size as u16);
                    if !conn.write_session(self.recv_head.as_ref()) {
                        self.status = ConnStatus::Closing;
                        break;
                    }
                    if !conn.write_session(&self.recv_body.as_slice()[..size]) {
                        self.status = ConnStatus::Closing;
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} write to session blocked", self.index);
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} got udp read err:{}", self.index, err);
                    self.status = ConnStatus::Closing;
                    break;
                }
            }
        }
        conn.do_send();
    }

    fn setup(&mut self, poll: &Poll) {
        if let Err(err) = poll.reregister(&self.socket,
                                          self.token, self.readiness, PollOpt::edge()) {
            log::error!("connection:{} reregister udp target failed:{}", self.index, err);
            self.status = ConnStatus::Closing;
        }
    }
}

impl Backend for UdpBackend {
    fn ready(&mut self, event: &Event, opts: &mut Opts, conn: &mut TlsConn<ServerSession>) {
        if event.readiness().is_readable() {
            self.do_read(conn);
        }
        if event.readiness().is_writable() {
            self.dispatch(&[], opts);
        }
    }

    fn dispatch(&mut self, buffer: &[u8], opts: &mut Opts) {
        if self.send_buffer.is_empty() {
            self.do_send(buffer, opts);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send(buffer.as_ref(), opts);
        }
    }

    fn reregister(&mut self, poll: &Poll, readable: bool) {
        match self.status {
            ConnStatus::Closing => {
                let _ = poll.deregister(&self.socket);
            }
            ConnStatus::Closed => {
                return;
            }
            _ => {
                let mut changed = false;
                if !self.send_buffer.is_empty() && !self.readiness.is_writable() {
                    self.readiness.insert(Ready::writable());
                    changed = true;
                    log::debug!("connection:{} add writable to udp target", self.index);
                }
                if self.send_buffer.is_empty() && self.readiness.is_writable() {
                    self.readiness.remove(Ready::writable());
                    changed = true;
                    log::debug!("connection:{} remove writable from udp target", self.index);
                }
                if readable && !self.readiness.is_readable() {
                    self.readiness.insert(Ready::readable());
                    log::debug!("connection:{} add readable to udp target", self.index);
                    changed = true;
                }
                if !readable && self.readiness.is_readable() {
                    self.readiness.remove(Ready::readable());
                    log::debug!("connection:{} remove readable to udp target", self.index);
                    changed = true;
                }

                if changed {
                    self.setup(poll);
                }
            }
        }
    }

    fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            let _ = poll.deregister(&self.socket);
            self.status = ConnStatus::Closed;
            log::info!("connection:{} address:{} closed, read {} bytes, sent {} bytes", self.index, self.remote_addr, self.bytes_read, self.bytes_sent);
        }
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn shutdown(&mut self, poll: &Poll) {
        if self.send_buffer.is_empty() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }
        self.readiness = Ready::writable();
        self.status = ConnStatus::Shutdown;
        self.setup(poll);
        self.check_close(poll);
    }

    fn writable(&self) -> bool {
        self.send_buffer.len() < MAX_BUFFER_SIZE
    }
}