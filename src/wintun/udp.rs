use crate::{
    proto::{TrojanRequest, UdpAssociate, UdpParseResult, UDP_ASSOCIATE},
    proxy::IdlePool,
    resolver::DnsResolver,
    status::StatusProvider,
    tls_conn::TlsConn,
    wintun::{
        ip::{get_ipv4, get_ipv6},
        CHANNEL_CNT, CHANNEL_UDP, MAX_INDEX, MIN_INDEX,
    },
    OPTIONS,
};
use bytes::BytesMut;
use crossbeam::channel::{Receiver, Sender};
use mio::{event::Event, Events, Poll, Token};
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use wintun::Session;

pub struct UdpRequest {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub payload: Vec<u8>,
}

pub struct UdpServer {
    receiver: Receiver<UdpRequest>,
    src_map: HashMap<SocketAddr, usize>,
    conns: HashMap<usize, Connection>,
    next_index: usize,
    session: Arc<Session>,
}

impl UdpServer {
    pub fn new(receiver: Receiver<UdpRequest>, session: Arc<Session>) -> UdpServer {
        UdpServer {
            receiver,
            session,
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
        Token(index * CHANNEL_CNT + CHANNEL_UDP)
    }

    pub fn token2index(token: Token) -> usize {
        token.0 / CHANNEL_CNT
    }

    pub fn do_local(&mut self, pool: &mut IdlePool, poll: &Poll, resolver: &DnsResolver) {
        self.receiver.clone().try_iter().for_each(|packet| {
            log::info!(
                "[udp][{}->{}]received packet:{}",
                packet.source,
                packet.target,
                packet.payload.len()
            );
            let index = if let Some(index) = self.src_map.get_mut(&packet.source) {
                *index
            } else if let Some(mut conn) = pool.get(poll, resolver) {
                let index = self.next_index();
                if !conn.reset_index(index, UdpServer::index2token(index), poll) {
                    conn.check_status(poll);
                    return;
                }

                let mut conn = Connection::new(index, conn, packet.source, self.session.clone());
                if conn.setup() {
                    let _ = self.src_map.insert(packet.source, index);
                    let _ = self.conns.insert(index, conn);
                    index
                } else {
                    conn.conn.check_status(poll);
                    return;
                }
            } else {
                log::error!("get connection from idle pool failed");
                return;
            };
            let conn = self.conns.get_mut(&index).unwrap();
            conn.send_request(packet);
        });
    }

    pub fn do_remote(&mut self, event: &Event, poll: &Poll) {
        log::debug!("remote event for token:{}", event.token().0);
        let index = Self::token2index(event.token());
        if let Some(conn) = self.conns.get_mut(&index) {
            conn.ready(event, poll);
            if conn.destroyed() {
                let _ = self.src_map.remove(&conn.source);
                let _ = self.conns.remove(&index);
                log::info!("connection:{} removed", index);
            }
        } else {
            log::error!("connection:{} not found in udp server", index);
        }
    }
}

struct Connection {
    index: usize,
    conn: TlsConn,
    source: SocketAddr,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    id: u16,
    session: Arc<Session>,
}

impl Connection {
    fn new(index: usize, conn: TlsConn, source: SocketAddr, session: Arc<Session>) -> Connection {
        Connection {
            index,
            conn,
            source,
            session,
            send_buffer: Default::default(),
            recv_buffer: Default::default(),
            id: 1,
        }
    }

    pub(crate) fn destroyed(&self) -> bool {
        //TODO
        self.conn.deregistered()
    }

    fn send_request(&mut self, packet: UdpRequest) {
        if !self.conn.is_connecting() && !self.conn.writable() {
            log::warn!("udp packet is too fast, ignore now");
            return;
        }
        log::info!("sending request to remote");
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

    fn ready(&mut self, event: &Event, poll: &Poll) {
        if event.is_readable() {
            self.send_response();
        } else {
            self.conn.established();
            self.conn.do_send();
        }
        self.conn.check_status(poll);
    }

    fn setup(&mut self) -> bool {
        self.recv_buffer.clear();
        TrojanRequest::generate(
            &mut self.recv_buffer,
            UDP_ASSOCIATE,
            OPTIONS.empty_addr.as_ref().unwrap(),
        );
        self.conn.write_session(self.recv_buffer.as_ref())
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
                    self.do_send_udp_smoltcp(packet.address, payload);
                    //self.do_send_udp(packet.address, payload);
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

    fn id(&mut self) -> u16 {
        let id = self.id;
        self.id += 1;
        id
    }

    fn do_send_udp_smoltcp(&mut self, dest: SocketAddr, data: &[u8]) {
        let length = 28 + data.len();
        let mut buffer = vec![0u8; length];

        //ip header
        let mut packet = Ipv4Packet::new_unchecked(buffer.as_mut_slice());
        packet.set_version(4);
        packet.set_header_len(20);
        packet.set_dscp(0);
        packet.set_ecn(0);
        packet.set_total_len(length as u16);
        packet.set_ident(self.id());
        packet.set_dont_frag(true);
        packet.set_more_frags(false);
        packet.set_frag_offset(0);
        packet.set_hop_limit(64);
        packet.set_protocol(IpProtocol::Udp);
        packet.set_src_addr(get_ipv4(dest.ip()).into());
        packet.set_dst_addr(get_ipv4(self.source.ip()).into());
        packet.fill_checksum();
        packet.check_len().unwrap();

        //udp header
        let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
        packet.set_len((length - 20) as u16);
        packet.set_src_port(dest.port());
        packet.set_dst_port(self.source.port());
        packet.payload_mut().copy_from_slice(data);
        let source = get_ipv4(dest.ip()).into();
        let target = get_ipv4(self.source.ip()).into();
        packet.fill_checksum(&source, &target);
        packet.check_len().unwrap();

        if let Ok(mut send_packet) = self.session.allocate_send_packet(length as u16) {
            send_packet.bytes_mut().copy_from_slice(buffer.as_slice());
            self.session.send_packet(send_packet);
            log::info!(
                "[{}->{}]send udp packet:{}, data:{}",
                dest,
                self.source,
                buffer.len(),
                data.len()
            );
        } else {
            log::error!("send packet failed");
        }
    }
}
