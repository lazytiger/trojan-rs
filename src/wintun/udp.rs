use crate::proto::{UdpAssociate, UdpParseResult};
use crate::proxy::IdlePool;
use crate::resolver::DnsResolver;
use crate::status::StatusProvider;
use crate::tls_conn::TlsConn;
use bytes::BytesMut;
use crossbeam::channel::{Receiver, Sender};
use mio::{Poll, Token};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet as _;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

pub struct Packet {
    pub source: Ipv4Addr,
    pub target: Ipv4Addr,
    pub packet: UdpPacket<'static>,
}

pub struct UdpServer {
    receiver: Receiver<Packet>,
    sender: Sender<Packet>,
    conns: HashMap<SocketAddrV4, Connection>,
}

impl UdpServer {
    pub fn new(receiver: Receiver<Packet>, sender: Sender<Packet>) -> UdpServer {
        UdpServer {
            receiver,
            sender,
            conns: Default::default(),
        }
    }

    pub fn ready(&mut self, pool: &mut IdlePool, poll: &Poll, resolver: &DnsResolver) {
        self.receiver.clone().try_iter().for_each(|packet| {
            let addr = SocketAddrV4::new(packet.source, packet.packet.get_source());
            let conn = if let Some(conn) = self.conns.get_mut(&addr) {
                conn
            } else if let Some(conn) = pool.get(poll, resolver) {
                let conn = Connection::new(1, conn, addr, self.sender.clone());
                self.conns.insert(addr, conn);
                self.conns.get_mut(&addr).unwrap()
            } else {
                return;
            };
            conn.send_request(packet);
        });
    }
}

struct Connection {
    index: usize,
    conn: TlsConn,
    source: SocketAddrV4,
    sender: Sender<Packet>,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
}

impl Connection {
    fn new(
        index: usize,
        conn: TlsConn,
        source: SocketAddrV4,
        sender: Sender<Packet>,
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
    fn send_request(&mut self, packet: Packet) {
        if !self.conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        self.recv_buffer.clear();
        UdpAssociate::generate(
            &mut self.recv_buffer,
            &SocketAddr::V4(SocketAddrV4::new(
                packet.target,
                packet.packet.get_destination(),
            )),
            packet.packet.payload().len() as u16,
        );
        if self.conn.write_session(self.recv_buffer.as_ref()) {
            self.conn.write_session(packet.packet.payload());
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
        let dest: SocketAddrV4 = if let SocketAddr::V4(v4) = dest {
            v4
        } else {
            return;
        };
        packet.set_payload(data);
        packet.set_source(dest.port());
        packet.set_destination(self.source.port());
        if let Err(err) = self.sender.try_send(Packet {
            source: *dest.ip(),
            target: *self.source.ip(),
            packet: packet.consume_to_immutable(),
        }) {
            log::warn!("socket is full, ignore udp packet:{}", err);
        }
    }
}
