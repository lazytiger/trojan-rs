use std::io::{Read, Write};

use bytes::BytesMut;
use mio::net::TcpStream;

use crate::tls_conn::TlsConn;

pub fn tcp_read(
    index: usize,
    mut conn: &TcpStream,
    recv_buf: &mut Vec<u8>,
    server_conn: &mut TlsConn,
) -> (bool, usize) {
    let mut total = 0usize;
    loop {
        match conn.read(recv_buf.as_mut_slice()) {
            Ok(size) => {
                log::debug!("connection:{} read {} bytes from backend", index, size);
                total += size;
                if size == 0 {
                    log::warn!("connection:{} meets end of file", index);
                    return (false, total);
                } else if !server_conn.write_session(&recv_buf.as_slice()[..size]) {
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                log::debug!("connection:{} read from backend blocked", index);
                break;
            }
            Err(err) => {
                log::warn!("connection:{} read from backend failed:{}", index, err);
                return (false, total);
            }
        }
    }
    (true, total)
}

pub fn tcp_send(
    index: usize,
    mut conn: &TcpStream,
    send_buffer: &mut BytesMut,
    mut data: &[u8],
) -> bool {
    loop {
        if data.is_empty() {
            return true;
        }
        match conn.write(data) {
            Ok(size) => {
                if size == 0 {
                    log::warn!("send failed, tcp stream closed");
                    return false;
                }
                data = &data[size..];
                log::debug!(
                    "connection:{} session write {} byte to backend",
                    index,
                    size
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                log::debug!(
                    "connection:{} session write blocked, remaining:{}",
                    index,
                    data.len()
                );
                send_buffer.extend_from_slice(data);
                break;
            }
            Err(err) => {
                log::warn!("connection:{} send failed:{}", index, err);
                return false;
            }
        }
    }
    true
}
