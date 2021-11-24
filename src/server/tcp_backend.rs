use std::{net::Shutdown, time::Duration};

use bytes::BytesMut;
use mio::{event::Event, net::TcpStream, Interest, Poll, Token};

use crate::{
    config::OPTIONS,
    proto::MAX_PACKET_SIZE,
    server::tls_server::Backend,
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
}

impl TcpBackend {
    pub fn new(mut conn: TcpStream, index: usize, token: Token, poll: &Poll) -> Result<TcpBackend> {
        poll.registry()
            .register(&mut conn, token, Interest::READABLE | Interest::WRITABLE)?;
        conn.set_nodelay(true)?;
        Ok(TcpBackend {
            conn,
            timeout: OPTIONS.tcp_idle_duration,
            status: ConnStatus::Established,
            send_buffer: BytesMut::new(),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
            index,
        })
    }
    fn do_read(&mut self, conn: &mut TlsConn) {
        if !tcp_util::tcp_read(self.index, &self.conn, &mut self.recv_buffer, conn) {
            self.shutdown();
            return;
        }

        conn.do_send();
    }

    fn do_send(&mut self, data: &[u8]) {
        if !tcp_util::tcp_send(self.index, &self.conn, &mut self.send_buffer, data) {
            self.shutdown();
        }
    }

    fn shutdown(&mut self) {}
}

impl Backend for TcpBackend {
    fn ready(&mut self, event: &Event, conn: &mut TlsConn) {
        if event.is_readable() {
            self.do_read(conn);
        }
        if event.is_writable() {
            self.dispatch(&[]);
        }
    }

    fn dispatch(&mut self, buffer: &[u8]) {
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
}

impl StatusProvider for TcpBackend {
    fn set_status(&mut self, status: ConnStatus) {
        self.status = status
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&self) {
        let _ = self.conn.shutdown(Shutdown::Both);
    }

    fn deregister(&mut self, poll: &Poll) {
        let _ = poll.registry().deregister(&mut self.conn);
    }

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
