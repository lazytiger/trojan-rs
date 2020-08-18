use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bytes::{BufMut, BytesMut};

use crate::config::Opts;

pub const CONNECT: u8 = 0x01;
pub const UDP_ASSOCIATE: u8 = 0x03;
pub const MAX_UDP_SIZE: usize = 1400;
const IPV4: u8 = 0x01;
const DOMAIN: u8 = 0x03;
const IPV6: u8 = 0x04;

pub enum Sock5Address {
    Socket(SocketAddr),
    Domain(String, u16),
    None,
}

pub struct TrojanRequest<'a> {
    pub command: u8,
    pub address: Sock5Address,
    pub payload: &'a [u8],
}

impl<'a> TrojanRequest<'a> {
    pub fn parse(mut buffer: &'a [u8], opts: &mut Opts) -> Option<TrojanRequest<'a>> {
        if buffer.len() < opts.pass_len {
            log::debug!(
                "data length:{} is too short for a trojan request",
                buffer.len()
            );
            return None;
        }

        let pass = String::from_utf8_lossy(&buffer[..opts.pass_len]);
        if let Some(orig) = opts.check_pass(&pass) {
            log::debug!("request using password:{}", &orig);
        } else {
            log::debug!("request didn't find matched password");
            return None;
        }

        buffer = &buffer[opts.pass_len..];
        if buffer.len() < 2 || buffer[0] != b'\r' || buffer[1] != b'\n' {
            log::error!(
                "unknown protocol, expected CRLF, {:#X}{:#X}",
                buffer[0],
                buffer[1]
            );
            return None;
        }

        buffer = &buffer[2..];
        if buffer.len() < 3 {
            log::error!("unknown protocol, invalid size");
            return None;
        }
        if buffer[0] != CONNECT && buffer[0] != UDP_ASSOCIATE {
            log::error!(
                "unknown protocol, expected valid command, found:{}",
                buffer[0]
            );
            return None;
        }

        let command = buffer[0];
        let atyp = buffer[1];
        buffer = &buffer[2..];
        if let Some((size, address)) = parse_address(atyp, buffer, opts) {
            buffer = &buffer[size..];
            if buffer[0] != b'\r' || buffer[1] != b'\n' {
                log::error!("unknown protocol, expected CRLF after address");
                return None;
            }
            Some(TrojanRequest {
                command,
                address,
                payload: &buffer[2..],
            })
        } else {
            None
        }
    }

    pub fn generate(buffer: &mut BytesMut, cmd: u8, addr: &SocketAddr, opts: &Opts) {
        buffer.extend_from_slice(opts.get_pass().as_bytes());
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
        buffer.put_u8(cmd);
        Sock5Address::generate(buffer, addr);
        buffer.put_u8(b'\r');
        buffer.put_u8(b'\n');
    }
}

fn parse_address(atyp: u8, buffer: &[u8], opts: &mut Opts) -> Option<(usize, Sock5Address)> {
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
            } else if let Some(ip) = opts.query_dns(&domain) {
                Some((length + 3, Sock5Address::Socket(SocketAddr::new(ip, port))))
            } else {
                log::info!("domain found:{}:{}", domain, port);
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
            log::warn!("unknown protocol, invalid address type:{}", atyp);
            return None;
        }
    }
}

pub struct UdpAssociate<'a> {
    pub address: SocketAddr,
    pub length: usize,
    pub payload: &'a [u8],
}

pub enum UdpParseResult<'a> {
    Packet(UdpAssociate<'a>),
    InvalidProtocol,
    Continued,
}

impl<'a> UdpAssociate<'a> {
    pub fn parse(mut buffer: &'a [u8], opts: &mut Opts) -> UdpParseResult<'a> {
        if buffer.len() < 11 {
            log::debug!("data is too short for UDP_ASSOCIATE");
            return UdpParseResult::Continued;
        }
        let atyp = buffer[0];
        buffer = &buffer[1..];
        if let Some((size, addr)) = parse_address(atyp, buffer, opts) {
            buffer = &buffer[size..];
            if buffer.len() < 4 {
                return UdpParseResult::Continued;
            }
            let length = to_u16(buffer) as usize;
            if length > MAX_UDP_SIZE {
                log::error!("udp packet size:{} is too long", length);
                return UdpParseResult::InvalidProtocol;
            }
            if buffer.len() < length + 4 {
                return UdpParseResult::Continued;
            }
            if buffer[2] != b'\r' || buffer[3] != b'\n' {
                log::warn!("udp packet expected CRLF after length");
                return UdpParseResult::InvalidProtocol;
            }
            match addr {
                Sock5Address::Socket(address) => UdpParseResult::Packet(UdpAssociate {
                    address,
                    length,
                    payload: &buffer[4..],
                }),
                _ => {
                    log::warn!("udp packet only accept ip address");
                    UdpParseResult::InvalidProtocol
                }
            }
        } else {
            UdpParseResult::InvalidProtocol
        }
    }

    pub fn generate(buffer: &mut BytesMut, address: &SocketAddr, length: u16) {
        Sock5Address::generate(buffer, address);
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
}
