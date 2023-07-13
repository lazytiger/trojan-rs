use std::{
    fs::File,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use bytes::{Buf, BytesMut};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::UdpSocket;
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::BinDecodable,
};

use crate::{
    types,
    types::{
        CopyResult,
        CopyResult::{RxBlock, TxBlock},
        Result, TrojanError,
    },
};

#[allow(dead_code)]
pub fn copy_stream(
    from: &mut impl Read,
    to: &mut impl Write,
    buffer: &mut BytesMut,
) -> Result<CopyResult> {
    loop {
        if !send_all(to, buffer)? {
            return Ok(TxBlock);
        }
        if !read_once(from, buffer)? {
            return Ok(RxBlock);
        }
    }
}

#[allow(dead_code)]
pub fn send_all(writer: &mut impl Write, buffer: &mut BytesMut) -> Result<bool> {
    if buffer.is_empty() {
        return Ok(true);
    }
    log::debug!("start sending {} bytes data", buffer.len());
    let mut data = buffer.as_ref();
    let mut offset = 0;
    let mut ret = Ok(true);
    while !data.is_empty() {
        ret = match writer.write(data) {
            Ok(0) => Err(TrojanError::TxBreak(None)),
            Ok(n) => {
                log::debug!("sent {} bytes", n);
                offset += n;
                data = &data[n..];
                continue;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(false),
            Err(err) => Err(TrojanError::TxBreak(Some(err))),
        };
        break;
    }
    if ret.is_err() {
        buffer.clear();
    } else if offset != 0 {
        buffer.advance(offset);
    }
    ret
}

/// This function reads data from a stream and stores it in a buffer.
#[allow(dead_code)]
pub fn read_once(reader: &mut impl Read, buffer: &mut BytesMut) -> Result<bool> {
    buffer.reserve(1500);
    let mut nb = buffer.split_off(buffer.len());
    unsafe {
        nb.set_len(nb.capacity());
    }
    assert!(!nb.as_mut().is_empty());
    let ret = match reader.read(nb.as_mut()) {
        Ok(0) => Err(TrojanError::RxBreak(None)),
        Ok(n) => {
            log::debug!("read {} bytes", n);
            unsafe {
                nb.set_len(n);
            }
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(false),
        Err(err) => Err(TrojanError::RxBreak(Some(err))),
    };
    if !matches!(ret, Ok(true)) {
        nb.clear();
    }
    buffer.unsplit(nb);
    ret
}

/// This function resolves a domain name to a list of IP addresses.
pub fn resolve(name: &str, dns_server_addr: &str) -> Result<Vec<IpAddr>> {
    let dns_server_addr: SocketAddr = dns_server_addr.parse()?;
    let dns_server_addr: SockAddr = dns_server_addr.into();
    let mut socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    let addr: SockAddr = addr.into();
    socket.bind(&addr)?;
    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.set_id(1);
    let mut query = Query::new();
    let name = Name::from_str(name)?;
    query.set_name(name);
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    let request = message.to_vec()?;
    if request.len() != socket.send_to(request.as_slice(), &dns_server_addr)? {
        return Err(TrojanError::Dummy(()));
    }
    let mut response = vec![0u8; 1024];
    socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
    let length = socket.read(response.as_mut_slice())?;
    let message = Message::from_bytes(&response.as_slice()[..length])?;
    if message.id() != 1 {
        Err(TrojanError::Dummy(()))
    } else {
        Ok(message
            .answers()
            .iter()
            .filter_map(|record| record.data().and_then(|data| data.to_ip_addr()))
            .collect())
    }
}

pub async fn aresolve(name: &str, dns_server_addr: &str) -> Result<Vec<IpAddr>> {
    let dns_server_addr: SocketAddr = dns_server_addr.parse()?;
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.set_id(1);
    let mut query = Query::new();
    let name = Name::from_str(name)?;
    query.set_name(name);
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    let request = message.to_vec()?;
    if request.len() != socket.send_to(request.as_slice(), &dns_server_addr).await? {
        return Err(TrojanError::Dummy(()));
    }
    let mut response = vec![0u8; 1024];
    let length = tokio::time::timeout(Duration::from_secs(3), socket.recv(response.as_mut_slice()))
        .await??;
    let message = Message::from_bytes(&response.as_slice()[..length])?;
    if message.id() != 1 {
        Err(TrojanError::Dummy(()))
    } else {
        Ok(message
            .answers()
            .iter()
            .filter_map(|record| record.data().and_then(|data| data.to_ip_addr()))
            .collect())
    }
}

pub fn get_system_dns() -> types::Result<String> {
    let file = File::open("/etc/resolv.conf")?;
    let mut data = String::new();
    let mut reader = BufReader::new(file);
    let key = "nameserver";
    while let Ok(n) = reader.read_line(&mut data) {
        if n == 0 {
            break;
        }
        let line = data.trim();
        if line.starts_with(key) {
            return Ok(line[key.len()..].trim().to_string());
        }
    }
    Ok("127.0.0.1".to_string())
}

mod test {
    #[test]
    fn test_resolve() {
        let result = crate::utils::resolve("www.baidu.com", "192.168.3.1:53");
        println!("{:?}", result);
    }
}
