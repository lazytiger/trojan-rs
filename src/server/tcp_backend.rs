use std::{net::Shutdown, time::Duration};

use bytes::BytesMut;
use mio::{event::Event, net::TcpStream, Poll};

use crate::{
    config::OPTIONS,
    proto::{MAX_BUFFER_SIZE, MAX_PACKET_SIZE},
    server::tls_server::Backend,
    tcp_util,
    tls_conn::{ConnStatus, TlsConn},
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
    pub fn new(conn: TcpStream, index: usize) -> TcpBackend {
        TcpBackend {
            conn,
            timeout: OPTIONS.tcp_idle_duration,
            status: ConnStatus::Established,
            send_buffer: BytesMut::new(),
            recv_buffer: vec![0u8; MAX_PACKET_SIZE],
            index,
        }
    }
    fn do_read(&mut self, conn: &mut TlsConn) {
        if !tcp_util::tcp_read(self.index, &self.conn, &mut self.recv_buffer, conn) {
            self.status = ConnStatus::Closing;
        }

        conn.do_send();
    }

    fn do_send(&mut self, data: &[u8]) {
        if !tcp_util::tcp_send(self.index, &self.conn, &mut self.send_buffer, data) {
            self.status = ConnStatus::Closing;
            return;
        }

        if let ConnStatus::Shutdown = self.status {
            if self.send_buffer.is_empty() {
                log::debug!("connection:{} is closing for no data to send", self.index);
                self.status = ConnStatus::Closing;
            }
        }
    }
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

    fn check_close(&mut self, poll: &Poll) {
        if let ConnStatus::Closing = self.status {
            let _ = poll.registry().deregister(&mut self.conn);
            let _ = self.conn.shutdown(Shutdown::Both);
            self.status = ConnStatus::Closed;
        }
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn status(&self) -> ConnStatus {
        self.status
    }

    fn shutdown(&mut self, poll: &Poll) {
        if self.send_buffer.is_empty() {
            self.status = ConnStatus::Closing;
            self.check_close(poll);
            return;
        }

        self.status = ConnStatus::Shutdown;
    }

    fn writable(&self) -> bool {
        self.send_buffer.len() < MAX_BUFFER_SIZE
    }
}
