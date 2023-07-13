use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use mio::{net::UdpSocket, Interest, Poll, Token};

use crate::{
    config::OPTIONS,
    proto::{UdpAssociate, UdpParseResult, MAX_PACKET_SIZE},
    server::{stat::Statistics, tls_server::Backend},
    status::{ConnStatus, StatusProvider},
    tls_conn::TlsConn,
    types::Result,
};

pub struct UdpBackend {
    socket: UdpSocket,
    send_buffer: BytesMut,
    recv_body: Vec<u8>,
    recv_head: BytesMut,
    index: usize,
    status: ConnStatus,
    timeout: Duration,
    bytes_read: usize,
    bytes_sent: usize,
    source: Option<IpAddr>,
    sources: HashMap<SocketAddr, Instant>,
}

impl UdpBackend {
    pub fn new(
        mut socket: UdpSocket,
        source: Option<IpAddr>,
        index: usize,
        token: Token,
        poll: &Poll,
    ) -> Result<UdpBackend> {
        poll.registry()
            .register(&mut socket, token, Interest::READABLE | Interest::WRITABLE)?;
        Ok(UdpBackend {
            socket,
            index,
            source,
            send_buffer: Default::default(),
            recv_body: vec![0u8; MAX_PACKET_SIZE],
            recv_head: Default::default(),
            status: ConnStatus::Established,
            timeout: OPTIONS.udp_idle_duration,
            bytes_read: 0,
            bytes_sent: 0,
            sources: HashMap::new(),
        })
    }

    fn do_send(&mut self, mut buffer: &[u8], stats: &mut Statistics) {
        loop {
            match UdpAssociate::parse(buffer) {
                UdpParseResult::Packet(packet) => {
                    if packet.address.as_socket().is_none() {
                        log::error!("only socket address support for now, switch to async version");
                        self.shutdown();
                        return;
                    }
                    if OPTIONS.server_args().disable_udp_hole {
                        self.sources
                            .insert(packet.address.as_socket().unwrap(), Instant::now());
                    }
                    match self.socket.send_to(
                        &packet.payload[..packet.length],
                        packet.address.as_socket().unwrap(),
                    ) {
                        Ok(size) => {
                            stats.add_udp_rx(
                                size,
                                Some(packet.address.as_socket().unwrap().ip()),
                                None,
                            );
                            self.bytes_sent += size;
                            if size != packet.length {
                                log::error!(
                                    "connection:{} udp packet is truncated, {}：{}",
                                    self.index,
                                    packet.length,
                                    size
                                );
                                self.shutdown();
                                return;
                            }
                            log::debug!(
                                "connection:{} write {} bytes to udp target:{:?}",
                                self.index,
                                size,
                                packet.address
                            );
                            buffer = &packet.payload[packet.length..];
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            log::debug!("connection:{} write to udp target blocked", self.index);
                            self.send_buffer.extend_from_slice(buffer);
                            break;
                        }
                        Err(err) => {
                            log::warn!(
                                "connection:{} send_to {:?} failed:{}",
                                self.index,
                                packet.address,
                                err
                            );
                            self.shutdown();
                            return;
                        }
                    }
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!(
                        "connection:{}-{:?} got invalid udp protocol",
                        self.index,
                        self.source
                    );
                    self.shutdown();
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
}

impl Backend for UdpBackend {
    fn dispatch(&mut self, buffer: &[u8], stats: &mut Statistics) {
        if self.send_buffer.is_empty() {
            self.do_send(buffer, stats);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send(buffer.as_ref(), stats);
        }
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn writable(&self) -> bool {
        self.alive()
    }

    fn do_read(&mut self, conn: &mut TlsConn, stats: &mut Statistics) {
        loop {
            match self.socket.recv_from(self.recv_body.as_mut_slice()) {
                Ok((size, addr)) => {
                    stats.add_udp_tx(size, Some(addr.ip()), conn.source());
                    self.bytes_read += size;
                    log::debug!(
                        "connection:{} got {} bytes udp data from:{}",
                        self.index,
                        size,
                        addr
                    );
                    let send = if OPTIONS.server_args().disable_udp_hole {
                        if let Some(t) = self.sources.get(&addr) {
                            if t.elapsed() > Duration::from_secs(60) {
                                log::error!(
                                    "remote:{:?} udp packet from {} discard because timeout",
                                    conn.source(),
                                    addr
                                );
                                false
                            } else {
                                true
                            }
                        } else {
                            log::error!(
                                "remote:{:?}, udp packet from {} discarded because of no udp source",
                                conn.source(),
                                addr
                            );
                            false
                        }
                    } else {
                        true
                    };
                    if send {
                        self.recv_head.clear();
                        UdpAssociate::generate(&mut self.recv_head, &addr, size as u16);
                        if conn.write_session(self.recv_head.as_ref())
                            && conn.write_session(&self.recv_body.as_slice()[..size])
                        {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    log::debug!("connection:{} write to session blocked", self.index);
                }
                Err(err) => {
                    log::warn!("connection:{} got udp read err:{}", self.index, err);
                    self.shutdown();
                }
            }
            break;
        }
        conn.do_send();
    }

    fn dst_ip(&self) -> Option<IpAddr> {
        None
    }
}

impl StatusProvider for UdpBackend {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status;
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&mut self) -> bool {
        true
    }

    fn deregister(&mut self, poll: &Poll) -> bool {
        let _ = poll.registry().deregister(&mut self.socket);
        true
    }

    fn finish_send(&mut self) -> bool {
        !matches!(
            UdpAssociate::parse(self.send_buffer.as_ref()),
            UdpParseResult::Packet(_)
        )
    }
}
