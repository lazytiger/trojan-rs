#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, BytesMut};
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address, Ipv6Address};

use crate::config::OPTIONS;

/// protocol code for CONNECT command
pub const CONNECT: u8 = 0x01;
/// protocol code for PING command
pub const PING: u8 = 0x2;
/// protocol code for UDP_ASSOCIATE command
pub const UDP_ASSOCIATE: u8 = 0x03;
/// max packet size for udp, MTU = 1500 minus IP head size
pub const MAX_PACKET_SIZE: usize = 1480;
/// protocol code for IPV4 type
pub const IPV4: u8 = 0x01;
/// protocol code for DOMAIN type
const DOMAIN: u8 = 0x03;
/// protocol code for IPV6 type
pub const IPV6: u8 = 0x04;

/// Trojan Socks5 address enum
#[derive(Debug)]
pub enum Sock5Address {
    Endpoint(IpEndpoint),
    Socket(SocketAddr),
    // IP address
    Domain(String, u16),
    // Domain type
    None, // Invalid
}

impl Sock5Address {
    pub fn as_socket(&self) -> Option<SocketAddr> {
        if let Sock5Address::Socket(addr) = self {
            Some(*addr)
        } else {
            None
        }
    }
}

/// Trojan protocol for a request
pub struct TrojanRequest<'a> {
    pub command: u8,
    pub address: Sock5Address,
    pub payload: &'a [u8],
    pub offset: usize,
}

pub enum RequestParseResult<'a> {
    Request(TrojanRequest<'a>),
    InvalidProtocol,
    PassThrough,
    Continue,
}

impl<'a> TrojanRequest<'a> {
    pub fn parse(mut buffer: &'a [u8]) -> RequestParseResult<'a> {
        if buffer.len() < OPTIONS.pass_len {
            log::debug!(
                "data length:{} is too short for a trojan request",
                buffer.len()
            );
            return if String::from_utf8_lossy(buffer).contains("HTTP") {
                RequestParseResult::PassThrough
            } else {
                RequestParseResult::Continue
            };
        }

        let pass = String::from_utf8_lossy(&buffer[..OPTIONS.pass_len]);
        if let Some(orig) = OPTIONS.check_pass(&pass) {
            log::debug!("request using password:{}", &orig);
        } else {
            log::debug!("request didn't find matched password");
            return RequestParseResult::PassThrough;
        }

        buffer = &buffer[OPTIONS.pass_len..];
        let mut offset = OPTIONS.pass_len;
        if buffer.len() < 2 {
            return RequestParseResult::Continue;
        }
        if buffer[0] != b'\r' || buffer[1] != b'\n' {
            log::error!(
                "unknown protocol, expected CRLF, {:#X}{:#X}",
                buffer[0],
                buffer[1]
            );
            return RequestParseResult::InvalidProtocol;
        }

        buffer = &buffer[2..];
        offset += 2;
        if buffer.len() < 3 {
            log::error!("unknown protocol, invalid size");
            return RequestParseResult::Continue;
        }
        if buffer[0] != CONNECT && buffer[0] != UDP_ASSOCIATE && buffer[0] != PING {
            log::error!(
                "unknown protocol, expected valid command, found:{}",
                buffer[0]
            );
            return RequestParseResult::InvalidProtocol;
        }

        let command = buffer[0];
        let atyp = buffer[1];
        buffer = &buffer[2..];
        offset += 2;
        match parse_address(atyp, buffer) {
            AddressParseResult::Continue => RequestParseResult::Continue,
            AddressParseResult::Address((size, address)) => {
                buffer = &buffer[size..];
                offset += size;
                if buffer[0] != b'\r' || buffer[1] != b'\n' {
                    log::error!("unknown protocol, expected CRLF after address");
                    return RequestParseResult::InvalidProtocol;
                }
                offset += 2;
                RequestParseResult::Request(TrojanRequest {
                    command,
                    offset,
                    address,
                    payload: &buffer[2..],
                })
            }
            AddressParseResult::InvalidProtocol => RequestParseResult::InvalidProtocol,
        }
    }

    pub fn generate(buffer: &mut BytesMut, cmd: u8, addr: &SocketAddr) {
        buffer.extend_from_slice(OPTIONS.get_pass().as_bytes());
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
        buffer.put_u8(cmd);
        Sock5Address::generate(buffer, addr);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }

    pub fn generate_endpoint(buffer: &mut BytesMut, cmd: u8, addr: &IpEndpoint) {
        buffer.extend_from_slice(OPTIONS.get_pass().as_bytes());
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
        buffer.put_u8(cmd);
        log::info!("generate endpoint:{}", addr);
        Sock5Address::generate_endpoint(buffer, addr);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }
}

enum AddressParseResult {
    Address((usize, Sock5Address)),
    InvalidProtocol,
    Continue,
}

fn parse_address(atyp: u8, buffer: &[u8]) -> AddressParseResult {
    match atyp {
        IPV4 => {
            log::debug!("ipv4 address found");
            if buffer.len() < 6 {
                return AddressParseResult::Continue;
            }
            let port = to_u16(&buffer[4..]);
            let addr = SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(buffer[0], buffer[1], buffer[2], buffer[3]),
                port,
            ));
            AddressParseResult::Address((6, Sock5Address::Socket(addr)))
        }
        DOMAIN => {
            log::debug!("domain address found");
            let length = buffer[0] as usize;
            if buffer.len() < length + 3 {
                return AddressParseResult::Continue;
            }
            let domain: String = String::from_utf8_lossy(&buffer[1..length + 1]).into();
            let port = to_u16(&buffer[length + 1..]);
            if let Ok(ip) = domain.parse::<IpAddr>() {
                AddressParseResult::Address((
                    length + 3,
                    Sock5Address::Socket(SocketAddr::new(ip, port)),
                ))
            } else {
                log::debug!("domain found:{}:{}", domain, port);
                AddressParseResult::Address((length + 3, Sock5Address::Domain(domain, port)))
            }
        }
        IPV6 => {
            log::debug!("ipv6 address found");
            if buffer.len() < 18 {
                return AddressParseResult::Continue;
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
            AddressParseResult::Address((18, Sock5Address::Socket(addr)))
        }
        _ => {
            log::error!("unknown protocol, invalid address type:{}", atyp);
            AddressParseResult::InvalidProtocol
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
            log::error!("unknown protocol, invalid address type:{}", atyp);
            None
        }
    }
}

pub struct UdpAssociate<'a> {
    pub address: Sock5Address,
    pub offset: usize,
    pub length: usize,
    pub payload: &'a [u8],
}

pub struct UdpAssociateEndpoint<'a> {
    pub endpoint: IpEndpoint,
    pub length: usize,
    pub offset: usize,
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
        if buffer.len() < 1 {
            log::debug!("data is too short for UDP_ASSOCIATE");
            return UdpParseResult::Continued;
        }
        let atyp = buffer[0];
        buffer = &buffer[1..];
        let mut offset = 1;
        match parse_address(atyp, buffer) {
            AddressParseResult::Address((size, address)) => {
                buffer = &buffer[size..];
                offset += size;
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
                offset += 4 + length;
                UdpParseResult::Packet(UdpAssociate {
                    address,
                    length,
                    offset,
                    payload: &buffer[4..],
                })
            }
            AddressParseResult::InvalidProtocol => UdpParseResult::InvalidProtocol,
            AddressParseResult::Continue => UdpParseResult::Continued,
        }
    }

    pub fn parse_endpoint(mut buffer: &'a [u8]) -> UdpParseResultEndpoint<'a> {
        if buffer.len() < 11 {
            log::debug!("data is too short for UDP_ASSOCIATE");
            return UdpParseResultEndpoint::Continued;
        }
        let atyp = buffer[0];
        buffer = &buffer[1..];
        let mut offset = 1;
        if let Some((size, addr)) = parse_address_endpoint(atyp, buffer) {
            buffer = &buffer[size..];
            offset += size;
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
            offset += length + 4;
            match addr {
                Sock5Address::Endpoint(endpoint) => {
                    UdpParseResultEndpoint::Packet(UdpAssociateEndpoint {
                        endpoint,
                        length,
                        offset,
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
