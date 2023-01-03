use std::{
    net::{IpAddr, Shutdown},
    time::Duration,
};

use bytes::BytesMut;
use mio::{net::TcpStream, Interest, Poll, Token};

use crate::{
    config::OPTIONS,
    proto::MAX_PACKET_SIZE,
    server::{stat::Statistics, tls_server::Backend},
    status::{ConnStatus, StatusProvider},
    tcp_util,
    tls_conn::TlsConn,
    types::Result,
};

pub struct TcpBackend {
    conn: TcpStream,
    status: ConnStatus,
    index: usize,
    timeout: Duration,
    send_buffer: BytesMut,
    recv_buffer: Vec<u8>,
    dst_ip: Option<IpAddr>,
}

impl TcpBackend {
    pub fn new(
        mut conn: TcpStream,
        dst_ip: Option<IpAddr>,
        index: usize,
        token: Token,
        poll: &Poll,
    ) -> Result<TcpBackend> {
        poll.registry()
            .register(&mut conn, token, Interest::READABLE | Interest::WRITABLE)?;
        conn.set_nodelay(true)?;
        Ok(TcpBackend {
            dst_ip,
            conn,
            index,
            timeout: OPTIONS.tcp_idle_duration,
            status: ConnStatus::Established,
            send_buffer: BytesMut::new(),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
        })
    }

    fn do_send(&mut self, data: &[u8]) {
        if !tcp_util::tcp_send(self.index, &self.conn, &mut self.send_buffer, data) {
            self.shutdown();
        }
    }
}

impl Backend for TcpBackend {
    fn dispatch(&mut self, buffer: &[u8], stats: &mut Statistics) {
        stats.add_tcp_rx(buffer.len(), self.dst_ip(), None);
        // send immediately first
        if self.send_buffer.is_empty() {
            self.do_send(buffer);
        } else {
            self.send_buffer.extend_from_slice(buffer);
            let buffer = self.send_buffer.split();
            self.do_send(buffer.as_ref());
        }
    }
    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn writable(&self) -> bool {
        self.send_buffer.is_empty() && self.alive()
    }

    fn do_read(&mut self, conn: &mut TlsConn, stats: &mut Statistics) {
        let (ret, total) = tcp_util::tcp_read(self.index, &self.conn, &mut self.recv_buffer, conn);
        if !ret {
            self.shutdown();
        }
        stats.add_tcp_tx(total, self.dst_ip(), None);

        conn.do_send();
    }

    fn dst_ip(&self) -> Option<IpAddr> {
        self.dst_ip.clone()
    }
}

impl StatusProvider for TcpBackend {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&mut self) -> bool {
        let _ = self.conn.shutdown(Shutdown::Both);
        true
    }

    fn deregister(&mut self, poll: &Poll) -> bool {
        let _ = poll.registry().deregister(&mut self.conn);
        true
    }

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
