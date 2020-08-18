use std::time::Duration;

use bytes::BytesMut;
use mio::{Event, Poll, PollOpt, Ready, Token};
use mio::net::UdpSocket;
use rustls::ServerSession;

use crate::config::Opts;
use crate::proto::{UdpAssociate, UdpParseResult};
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
}

impl UdpBackend {
    pub fn new(socket: UdpSocket, index: usize, token: Token, timeout: Duration) -> UdpBackend {
        UdpBackend {
            socket,
            send_buffer: Default::default(),
            recv_body: vec![],
            recv_head: Default::default(),
            index,
            token,
            status: ConnStatus::Established,
            readiness: Ready::empty(),
            timeout,
        }
    }

    fn do_send(&mut self, mut buffer: &[u8], opts: &mut Opts) {
        loop {
            match UdpAssociate::parse(buffer, opts) {
                UdpParseResult::Packet(packet) => {
                    match self.socket.send_to(&packet.payload[..packet.length], &packet.address) {
                        Ok(size) => {
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
    }

    fn do_read(&mut self, conn: &mut TlsConn<ServerSession>) {
        loop {
            match self.socket.recv_from(self.recv_body.as_mut_slice()) {
                Ok((size, addr)) => {
                    log::debug!("connection:{} got {} bytes udp data from:{}", self.index, size, addr);
                    self.recv_head.clear();
                    UdpAssociate::generate(&mut self.recv_head, &addr, size as u16);
                    if !conn.write_session(self.recv_head.as_ref()) {
                        self.status = ConnStatus::Closing;
                        return;
                    }
                    if !conn.write_session(&self.recv_body.as_slice()[..size]) {
                        self.status = ConnStatus::Closing;
                        return;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} write to session blocked", self.index);
                    break;
                }
                Err(err) => {
                    log::warn!("connection:{} got udp read err:{}", self.index, err);
                    self.status = ConnStatus::Closing;
                    return;
                }
            }
        }
        conn.do_send();
    }

    fn try_send(&mut self, opts: &mut Opts) {
        if self.send_buffer.is_empty() {
            self.do_send(&[], opts);
        } else {
            let buffer = self.send_buffer.split();
            self.do_send(buffer.as_ref(), opts);
        }
    }



    fn check_close(&mut self, poll: &Poll) {
        let _ = poll.deregister(&self.socket);
        self.status = ConnStatus::Closed;
    }
}

impl Backend for UdpBackend {
    fn ready(&mut self, event: &Event, poll: &Poll, opts: &mut Opts, conn: &mut TlsConn<ServerSession>) {
        if event.readiness().is_readable() {
            self.do_read(conn);
        }

        if event.readiness().is_writable() {
            self.try_send(opts);
        }

        self.reregister(poll);
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

    fn reregister(&mut self, poll: &Poll) {
        let mut changed = false;
        if !self.send_buffer.is_empty() && !self.readiness.is_writable() {
            self.readiness.insert(Ready::writable());
            changed = true;
            log::info!("connection:{} add writable to udp target", self.index);
        }
        if self.send_buffer.is_empty() && self.readiness.is_writable() {
            self.readiness.remove(Ready::writable());
            changed = true;
            log::info!("connection:{} remove writable from udp target", self.index);
        }

        if changed {
            if let Err(err) = poll.reregister(&self.socket,
                                              self.token, self.readiness, PollOpt::edge()) {
                log::error!("connection:{} reregister udp target failed:{}", self.index, err);
                self.status = ConnStatus::Closing;
            }
        }
    }

    fn close_now(&mut self, poll: &Poll) {
        self.status = ConnStatus::Closing;
        self.check_close(poll)
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn status(&self) -> ConnStatus {
        self.status
    }
}