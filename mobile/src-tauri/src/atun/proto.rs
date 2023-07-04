#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, BytesMut};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};

/// protocol code for CONNECT command
pub const CONNECT: u8 = 0x01;
/// protocol code for PING command
pub const PING: u8 = 0x2;
/// protocol code for UDP_ASSOCIATE command
pub const UDP_ASSOCIATE: u8 = 0x03;
/// max packet size for udp, MTU = 1500 minus IP head size
pub const MAX_PACKET_SIZE: usize = 1450;
/// protocol code for IPV4 type
pub const IPV4: u8 = 0x01;
/// protocol code for DOMAIN type
const DOMAIN: u8 = 0x03;
/// protocol code for IPV6 type
pub const IPV6: u8 = 0x04;

/// Trojan Socks5 address enum
pub enum Sock5Address {
    Endpoint(IpEndpoint),
    Socket(SocketAddr),
    // IP address
    Domain(String, u16),
    // Domain type
    None, // Invalid
}

/// Trojan protocol for a request
pub struct TrojanRequest<'a> {
    pub command: u8,
    pub address: Sock5Address,
    pub payload: &'a [u8],
}

impl<'a> TrojanRequest<'a> {
    pub fn generate(buffer: &mut BytesMut, cmd: u8, pass: &[u8], addr: &SocketAddr) {
        buffer.extend_from_slice(pass);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
        buffer.put_u8(cmd);
        Sock5Address::generate(buffer, addr);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }

    pub fn generate_endpoint(buffer: &mut BytesMut, cmd: u8, pass: &[u8], addr: &IpEndpoint) {
        buffer.extend_from_slice(pass);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
        buffer.put_u8(cmd);
        log::info!("generate endpoint:{}", addr);
        Sock5Address::generate_endpoint(buffer, addr);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }
}

fn parse_address(atyp: u8, buffer: &[u8]) -> Option<(usize, Sock5Address)> {
    match atyp {
        IPV4 => {
            log::debug!("ipv4 address found");
            if buffer.len() < 6 {
                log::error!("unknown protocol, invalid ipv4 address");
                return None;
            }
            let port = to_u16(&buffer[4..]);
            let addr = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(buffer[0], buffer[1], buffer[2], buffer[3]),
                port,
            ));
            Some((6, Sock5Address::Socket(addr)))
        }
        DOMAIN => {
            log::debug!("domain address found");
            let length = buffer[0] as usize;
            if buffer.len() < length + 3 {
                log::error!("unknown protocol, invalid domain address");
                return None;
            }
            let domain: String = String::from_utf8_lossy(&buffer[1..length + 1]).into();
            let port = to_u16(&buffer[length + 1..]);
            if let Ok(ip) = domain.parse::<IpAddr>() {
                Some((length + 3, Sock5Address::Socket(SocketAddr::new(ip, port))))
            } else {
                log::debug!("domain found:{}:{}", domain, port);
                Some((length + 3, Sock5Address::Domain(domain, port)))
            }
        }
        IPV6 => {
            log::debug!("ipv6 address found");
            if buffer.len() < 18 {
                log::error!("unknown protocol, invalid ipv6 address");
                return None;
            }
            let addr = SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(
                    to_u16(buffer),
                    to_u16(&buffer[2..]),
                    to_u16(&buffer[4..]),
                    to_u16(&buffer[6..]),
                    to_u16(&buffer[8..]),
                    to_u16(&buffer[10..]),
                    to_u16(&buffer[12..]),
                    to_u16(&buffer[14..]),
                ),
                to_u16(&buffer[16..]),
                0,
                0,
            ));
            Some((18, Sock5Address::Socket(addr)))
        }
        _ => {
            log::error!("unknown protocol, invalid address type:{}", atyp);
            None
        }
    }
}

fn parse_address_endpoint(atyp: u8, buffer: &[u8]) -> Option<(usize, Sock5Address)> {
    match atyp {
        IPV4 => {
            log::debug!("ipv4 address found");
            if buffer.len() < 6 {
                log::error!("unknown protocol, invalid ipv4 address");
                return None;
            }
            let port = to_u16(&buffer[4..]);
            let addr = Ipv4Address::new(buffer[0], buffer[1], buffer[2], buffer[3]);
            Some((
                6,
                Sock5Address::Endpoint(IpEndpoint::new(IpAddress::Ipv4(addr), port)),
            ))
        }
        DOMAIN => {
            log::debug!("domain address found");
            let length = buffer[0] as usize;
            if buffer.len() < length + 3 {
                log::error!("unknown protocol, invalid domain address");
                return None;
            }
            let domain: String = String::from_utf8_lossy(&buffer[1..length + 1]).into();
            let port = to_u16(&buffer[length + 1..]);
            if let Ok(ip) = domain.parse::<IpAddr>() {
                Some((
                    length + 3,
                    Sock5Address::Endpoint(IpEndpoint::new(IpAddress::from(ip), port)),
                ))
            } else {
                log::debug!("domain found:{}:{}", domain, port);
                Some((length + 3, Sock5Address::Domain(domain, port)))
            }
        }
        IPV6 => {
            log::debug!("ipv6 address found");
            if buffer.len() < 18 {
                log::error!("unknown protocol, invalid ipv6 address");
                return None;
            }
            let addr = Ipv6Address::from_bytes(buffer);
            let endpoint = IpEndpoint::new(IpAddress::Ipv6(addr), to_u16(&buffer[16..]));
            Some((18, Sock5Address::Endpoint(endpoint)))
        }
        _ => {
            log::warn!("unknown protocol, invalid address type:{}", atyp);
            None
        }
    }
}

pub struct UdpAssociate<'a> {
    pub address: SocketAddr,
    pub length: usize,
    pub payload: &'a [u8],
}

pub struct UdpAssociateEndpoint<'a> {
    pub endpoint: IpEndpoint,
    pub length: usize,
    pub payload: &'a [u8],
}

pub enum UdpParseResult<'a> {
    Packet(UdpAssociate<'a>),
    InvalidProtocol,
    Continued,
}

pub enum UdpParseResultEndpoint<'a> {
    Packet(UdpAssociateEndpoint<'a>),
    InvalidProtocol,
    Continued,
}

impl<'a> UdpAssociate<'a> {
    pub fn parse(mut buffer: &'a [u8]) -> UdpParseResult<'a> {
        if buffer.len() < 11 {
            log::debug!("data is too short for UDP_ASSOCIATE");
            return UdpParseResult::Continued;
        }
        let atyp = buffer[0];
        buffer = &buffer[1..];
        if let Some((size, addr)) = parse_address(atyp, buffer) {
            buffer = &buffer[size..];
            if buffer.len() < 4 {
                return UdpParseResult::Continued;
            }
            let length = to_u16(buffer) as usize;
            if length > MAX_PACKET_SIZE {
                log::error!("udp packet size:{} is too long", length);
                return UdpParseResult::InvalidProtocol;
            }
            if buffer.len() < length + 4 {
                return UdpParseResult::Continued;
            }
            if buffer[2] != b'\r' || buffer[3] != b'\n' {
                log::error!("udp packet expected CRLF after length");
                return UdpParseResult::InvalidProtocol;
            }
            match addr {
                Sock5Address::Socket(address) => UdpParseResult::Packet(UdpAssociate {
                    address,
                    length,
                    payload: &buffer[4..],
                }),
                _ => {
                    log::error!("udp packet only accept ip address");
                    UdpParseResult::InvalidProtocol
                }
            }
        } else {
            UdpParseResult::InvalidProtocol
        }
    }

    pub fn parse_endpoint(mut buffer: &'a [u8]) -> UdpParseResultEndpoint<'a> {
        if buffer.len() < 11 {
            log::debug!("data is too short for UDP_ASSOCIATE");
            return UdpParseResultEndpoint::Continued;
        }
        let atyp = buffer[0];
        buffer = &buffer[1..];
        if let Some((size, addr)) = parse_address_endpoint(atyp, buffer) {
            buffer = &buffer[size..];
            if buffer.len() < 4 {
                return UdpParseResultEndpoint::Continued;
            }
            let length = to_u16(buffer) as usize;
            if length > MAX_PACKET_SIZE {
                log::error!("udp packet size:{} is too long", length);
                return UdpParseResultEndpoint::InvalidProtocol;
            }
            if buffer.len() < length + 4 {
                return UdpParseResultEndpoint::Continued;
            }
            if buffer[2] != b'\r' || buffer[3] != b'\n' {
                log::warn!("udp packet expected CRLF after length");
                return UdpParseResultEndpoint::InvalidProtocol;
            }
            match addr {
                Sock5Address::Endpoint(endpoint) => {
                    UdpParseResultEndpoint::Packet(UdpAssociateEndpoint {
                        endpoint,
                        length,
                        payload: &buffer[4..],
                    })
                }
                _ => {
                    log::warn!("udp packet only accept ip address");
                    UdpParseResultEndpoint::InvalidProtocol
                }
            }
        } else {
            UdpParseResultEndpoint::InvalidProtocol
        }
    }

    pub fn generate(buffer: &mut BytesMut, address: &SocketAddr, length: u16) {
        Sock5Address::generate(buffer, address);
        buffer.put_u16(length);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }

    pub fn generate_endpoint(buffer: &mut BytesMut, endpoint: &IpEndpoint, length: u16) {
        log::info!("generate endpoint:{}", endpoint);
        Sock5Address::generate_endpoint(buffer, endpoint);
        buffer.put_u16(length);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }
}

fn to_u16(buffer: &[u8]) -> u16 {
    (buffer[0] as u16) << 8 | buffer[1] as u16
}

impl Sock5Address {
    pub fn generate(buffer: &mut BytesMut, address: &SocketAddr) {
        let port = match address {
            SocketAddr::V4(v4) => {
                buffer.put_u8(IPV4);
                buffer.extend_from_slice(&v4.ip().octets()[..]);
                v4.port()
            }
            SocketAddr::V6(v6) => {
                buffer.put_u8(IPV6);
                buffer.extend_from_slice(&v6.ip().octets()[..]);
                v6.port()
            }
        };
        buffer.put_u16(port);
    }

    pub fn generate_endpoint(buffer: &mut BytesMut, endpoint: &IpEndpoint) {
        match endpoint.addr {
            IpAddress::Ipv4(v4) => {
                buffer.put_u8(IPV4);
                buffer.extend_from_slice(v4.as_bytes());
            }
            IpAddress::Ipv6(v6) => {
                buffer.put_u8(IPV6);
                buffer.extend_from_slice(v6.as_bytes());
            }
        }
        buffer.put_u16(endpoint.port);
    }
}
