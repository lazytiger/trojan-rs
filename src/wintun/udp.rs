use crate::{
    proto::{UdpAssociate, UdpParseResult},
    proxy::IdlePool,
    resolver::DnsResolver,
    status::StatusProvider,
    tls_conn::TlsConn,
    wintun::{
        ip::{IpPacket, MutableIpPacket},
        CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX,
    },
};
use bytes::BytesMut;
use crossbeam::channel::{Receiver, Sender};
use mio::{Poll, Token};
use pnet::packet::{
    udp::{MutableUdpPacket},
    Packet as _,
};
use std::{
    collections::HashMap,
    net::{SocketAddr},
};

pub struct UdpRequest {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub payload: Vec<u8>,
}

pub type UdpResponse = IpPacket<'static>;

pub struct UdpServer {
    receiver: Receiver<UdpRequest>,
    sender: Sender<UdpResponse>,
    src_map: HashMap<SocketAddr, usize>,
    conns: HashMap<usize, Connection>,
    next_index: usize,
}

impl UdpServer {
    pub fn new(receiver: Receiver<UdpRequest>, sender: Sender<UdpResponse>) -> UdpServer {
        UdpServer {
            receiver,
            sender,
            src_map: Default::default(),
            conns: Default::default(),
            next_index: MIN_INDEX,
        }
    }

    pub fn next_index(&mut self) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        if self.next_index > MAX_INDEX {
            self.next_index = MIN_INDEX;
        }
        index
    }

    pub fn index2token(index: usize) -> Token {
        Token(index * CHANNEL_CNT + CHANNEL_TCP)
    }

    pub fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub fn ready(&mut self, pool: &mut IdlePool, poll: &Poll, resolver: &DnsResolver) {
        self.receiver.clone().try_iter().for_each(|packet| {
            let index = if let Some(index) = self.src_map.get_mut(&packet.source) {
                *index
            } else if let Some(mut conn) = pool.get(poll, resolver) {
                let index = self.next_index();
                if !conn.reset_index(index, UdpServer::index2token(index), poll) {
                    conn.check_status(poll);
                    return;
                }

                let conn = Connection::new(index, conn, packet.source, self.sender.clone());
                let _ = self.src_map.insert(packet.source, index);
                let _ = self.conns.insert(index, conn);
                index
            } else {
                return;
            };
            let conn = self.conns.get_mut(&index).unwrap();
            conn.send_request(packet);
        });
    }
}

struct Connection {
    index: usize,
    conn: TlsConn,
    source: SocketAddr,
    sender: Sender<UdpResponse>,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
}

impl Connection {
    fn new(
        index: usize,
        conn: TlsConn,
        source: SocketAddr,
        sender: Sender<UdpResponse>,
    ) -> Connection {
        Connection {
            index,
            conn,
            source,
            sender,
            send_buffer: Default::default(),
            recv_buffer: Default::default(),
        }
    }
    fn send_request(&mut self, packet: UdpRequest) {
        if !self.conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        self.recv_buffer.clear();
        UdpAssociate::generate(
            &mut self.recv_buffer,
            &packet.target,
            packet.payload.len() as u16,
        );
        if self.conn.write_session(self.recv_buffer.as_ref()) {
            self.conn.write_session(packet.payload.as_slice());
        }
        self.conn.do_send();
    }

    fn send_response(&mut self) {
        if let Some(data) = self.conn.do_read() {
            self.send_tun(data.as_slice());
        }
    }

    fn send_tun(&mut self, buffer: &[u8]) {
        if self.send_buffer.is_empty() {
            self.do_send_tun(buffer);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send_tun(buffer.as_ref());
        }
    }

    fn do_send_tun(&mut self, mut buffer: &[u8]) {
        loop {
            match UdpAssociate::parse(buffer) {
                UdpParseResult::Continued => {
                    self.send_buffer.extend_from_slice(buffer);
                    break;
                }
                UdpParseResult::Packet(packet) => {
                    let payload = &packet.payload[..packet.length];
                    self.do_send_udp(packet.address, payload);
                    buffer = &packet.payload[packet.length..];
                }
                UdpParseResult::InvalidProtocol => {
                    log::error!("connection:{} got invalid protocol", self.index);
                    self.conn.shutdown();
                    break;
                }
            }
        }
    }

    fn do_send_udp(&mut self, dest: SocketAddr, data: &[u8]) {
        let mut packet = MutableUdpPacket::owned(vec![
            0u8;
            data.len()
                + MutableUdpPacket::minimum_packet_size()
        ])
        .unwrap();
        packet.set_payload(data);
        packet.set_source(dest.port());
        packet.set_destination(self.source.port());
        if let Some(packet) = MutableIpPacket::new(packet.packet(), dest.is_ipv6()) {
            if let Err(err) = self.sender.try_send(packet.into_immutable()) {
                log::warn!("socket is full, ignore udp packet:{}", err);
            }
        } else {
            log::error!("invalid udp packet");
        }
    }
}
