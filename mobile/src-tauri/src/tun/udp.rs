use std::{
    collections::{HashMap, HashSet},
    io::{ErrorKind, Write},
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{
    iface::SocketHandle,
    socket::udp::{RecvError, SendError, Socket},
    wire::IpEndpoint,
};

use crate::tun::{
    device::VpnDevice,
    idle_pool::IdlePool,
    proto::{TrojanRequest, UdpAssociate, UdpParseResultEndpoint, UDP_ASSOCIATE},
    resolver::DnsResolver,
    tls_conn::TlsConn,
    utils::{read_once, send_all},
    waker::WakerMode,
    CHANNEL_CNT, CHANNEL_UDP, MAX_INDEX, MIN_INDEX,
};

fn next_token() -> Token {
    static mut NEXT_INDEX: usize = MIN_INDEX;
    unsafe {
        let index = NEXT_INDEX;
        NEXT_INDEX += 1;
        if NEXT_INDEX >= MAX_INDEX {
            NEXT_INDEX = MIN_INDEX;
        }
        Token(index * CHANNEL_CNT + CHANNEL_UDP)
    }
}

pub struct UdpSocketRef<'a, 'b> {
    pub(crate) socket: &'a mut Socket<'b>,
    pub(crate) endpoint: Option<IpEndpoint>,
}

impl<'a, 'b> std::io::Read for UdpSocketRef<'a, 'b> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.socket.recv_slice(buf) {
            Ok((n, endpoint)) => {
                log::info!(
                    "udp {:?} - {:?} read {} bytes",
                    endpoint,
                    self.socket.endpoint(),
                    n
                );
                self.endpoint.replace(endpoint.endpoint);
                Ok(n)
            }
            Err(RecvError::Exhausted) => Err(ErrorKind::WouldBlock.into()),
        }
    }
}

impl<'a, 'b> std::io::Write for UdpSocketRef<'a, 'b> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let endpoint = self.endpoint.unwrap();
        match self.socket.send_slice(buf, endpoint) {
            Ok(()) => {
                log::info!(
                    "udp {:?} - {:?} write {} bytes",
                    endpoint,
                    self.socket.endpoint(),
                    buf.len()
                );
                Ok(buf.len())
            }
            Err(SendError::BufferFull) => Err(ErrorKind::WouldBlock.into()),
            Err(SendError::Unaddressable) => Err(std::io::Error::new(
                ErrorKind::AddrNotAvailable,
                std::io::Error::last_os_error(),
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct Connection {
    token: Token,
    local: SocketHandle,
    remote: TlsConn,
    rclosed: bool,
    rbuffer: BytesMut,
    lbuffer: BytesMut,
    endpoint: IpEndpoint,
    established: bool,
    last_remote: Instant,
    pass: String,
    empty_addr: SocketAddr,
}

impl Connection {
    fn do_local(&mut self, poll: &Poll, header: &[u8], body: &[u8]) {
        if self.last_remote.elapsed().as_secs() > 120 {
            self.close_remote(poll);
            return;
        }
        if !self.rbuffer.is_empty() {
            log::info!("send is blocked, discard udp packet");
            return;
        }
        if !self.established {
            log::info!("connection is not ready, cache request");
            self.rbuffer.extend_from_slice(header);
            self.rbuffer.extend_from_slice(body);
            return;
        }
        self.local_to_remote(poll, header, body);
    }

    fn do_remote(&mut self, poll: &Poll, socket: &mut Socket, event: &Event) {
        self.last_remote = Instant::now();
        if event.is_writable() {
            if !self.established {
                let mut buffer = BytesMut::new();
                TrojanRequest::generate(
                    &mut buffer,
                    UDP_ASSOCIATE,
                    self.pass.as_bytes(),
                    &self.empty_addr,
                );
                log::info!(
                    "{:?} {:?} sending {} bytes handshake data",
                    self.endpoint,
                    self.remote.destination(),
                    buffer.len()
                );
                if self.remote.write(buffer.as_ref()).is_ok() {
                    self.established = true;
                    log::info!("{:?} connection is ready now", self.endpoint);
                } else {
                    self.close_remote(poll);
                    return;
                }
            }
            self.local_to_remote(poll, &[], &[]);
        }
        if event.is_readable() {
            self.remote_to_local(socket, poll);
            self.flush_remote(poll);
        }
    }

    fn is_closed(&self) -> bool {
        self.rclosed
    }

    fn flush_remote(&mut self, poll: &Poll) {
        match self.remote.flush() {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                log::info!("remote connection send blocked");
            }
            Err(err) => {
                log::info!("flush data to remote failed:{}", err);
                self.close_remote(poll);
            }
            Ok(()) => log::info!("flush data successfully"),
        }
    }

    fn local_to_remote(&mut self, poll: &Poll, header: &[u8], body: &[u8]) {
        if !self.rbuffer.is_empty() {
            log::info!(
                "{} send cached {:?} raw bytes to remote tls",
                self.endpoint,
                self.rbuffer.len()
            );
            match send_all(&mut self.remote, &mut self.rbuffer) {
                Ok(true) => {
                    log::info!("send all completed");
                }
                Ok(false) => {
                    log::info!("last request not finished, discard new request");
                    self.flush_remote(poll);
                    return;
                }
                Err(err) => {
                    log::info!("remote connection break:{:?}", err);
                    self.close_remote(poll);
                    return;
                }
            }
        }
        let mut data = header;
        let mut offset = 0;
        while !data.is_empty() {
            log::info!(
                "{:?} send {} bytes raw data to remote now",
                self.endpoint,
                data.len()
            );
            match self.remote.write(data) {
                Ok(0) => {
                    log::info!("remote connection break with 0 bytes");
                    self.close_remote(poll);
                    return;
                }
                Ok(n) => {
                    log::info!("send {} byte raw data", n);
                    offset += n;
                    data = &data[n..];
                    if data.is_empty() && offset == header.len() {
                        data = body;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    log::info!("write to remote blocked");
                    break;
                }
                Err(err) => {
                    log::info!("remote connection break:{:?}", err);
                    self.close_remote(poll);
                    return;
                }
            }
        }
        let remaining = header.len() + body.len() - offset;
        if remaining != 0 {
            log::info!(
                "{:?} sending data {} bytes left, cache now",
                self.endpoint,
                remaining
            );
            self.rbuffer.extend_from_slice(data);
            if data.len() < header.len() {
                self.rbuffer.extend_from_slice(body);
            }
        }
        self.flush_remote(poll);
    }

    fn remote_to_local(&mut self, socket: &mut Socket, poll: &Poll) {
        let mut socket = UdpSocketRef {
            socket,
            endpoint: Some(self.endpoint),
        };

        loop {
            let mut closed = false;
            match read_once(&mut self.remote, &mut self.lbuffer) {
                Ok(true) => {}
                Ok(false) => return,
                Err(err) => {
                    log::info!("remote closed with error:{:?}", err);
                    closed = true;
                }
            }

            if closed {
                self.close_remote(poll);
                return;
            }

            let mut buffer = self.lbuffer.as_ref();
            loop {
                match UdpAssociate::parse_endpoint(buffer) {
                    UdpParseResultEndpoint::Continued => {
                        let offset = self.lbuffer.len() - buffer.len();
                        if buffer.is_empty() {
                            self.lbuffer.clear();
                        } else {
                            let len = buffer.len();
                            self.lbuffer.copy_within(offset.., 0);
                            unsafe {
                                self.lbuffer.set_len(len);
                            }
                        }
                        log::info!("continue parsing with {} bytes left", self.lbuffer.len());
                        break;
                    }
                    UdpParseResultEndpoint::Packet(packet) => {
                        let payload = &packet.payload[..packet.length];
                        let _ = socket.write(payload);
                        log::info!(
                            "{} - {} get one packet with size:{}",
                            packet.endpoint,
                            self.endpoint,
                            payload.len()
                        );
                        buffer = &packet.payload[packet.length..];
                    }
                    UdpParseResultEndpoint::InvalidProtocol => {
                        log::info!("invalid protocol close now");
                        self.close_remote(poll);
                        return;
                    }
                }
            }
        }
    }

    fn close_remote(&mut self, poll: &Poll) {
        if self.rclosed {
            return;
        }
        self.remote.close(poll);
        self.rclosed = true;
    }
}

pub struct UdpServer {
    token2conns: HashMap<Token, Arc<Connection>>,
    addr2conns: HashMap<IpEndpoint, Arc<Connection>>,
    handles: HashMap<SocketHandle, (Instant, usize)>,
    buffer: BytesMut,
    removed: HashSet<Token>,
    pass: String,
}

impl UdpServer {
    pub fn new(pass: String) -> Self {
        Self {
            pass,
            token2conns: Default::default(),
            addr2conns: Default::default(),
            buffer: BytesMut::with_capacity(1500),
            removed: Default::default(),
            handles: Default::default(),
        }
    }

    pub fn check_timeout(&mut self, now: Instant, device: &mut VpnDevice) {
        let conns: Vec<_> = self
            .handles
            .iter()
            .filter_map(|(handle, (last_active, ref_count))| {
                if *ref_count > 0 {
                    return None;
                }
                let elapsed = now - *last_active;
                if elapsed > Duration::from_secs(600) {
                    Some(*handle)
                } else {
                    None
                }
            })
            .collect();

        for handle in conns {
            device.remove_socket(handle);
            self.handles.remove(&handle);
        }
    }

    pub fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        device: &mut VpnDevice,
    ) {
        for (handle, _) in device.get_udp_events().iter() {
            let socket = device.get_udp_socket_mut(*handle, WakerMode::Recv);
            let dst_endpoint = socket.endpoint();
            let info = self
                .handles
                .entry(*handle)
                .or_insert_with(|| (Instant::now(), 0));
            info.0 = Instant::now();
            while let Ok((data, src_endpoint)) = socket.recv() {
                let src_endpoint = src_endpoint.endpoint;
                self.buffer.clear();
                UdpAssociate::generate_endpoint(
                    &mut self.buffer,
                    &IpEndpoint::new(dst_endpoint.addr.unwrap(), dst_endpoint.port),
                    data.len() as u16,
                );
                //self.buffer.extend_from_slice(data);
                log::info!(
                    "got udp request from {} to {} with {} bytes",
                    src_endpoint,
                    dst_endpoint,
                    data.len()
                );
                let conn = self.addr2conns.entry(src_endpoint).or_insert_with(|| {
                    info.1 += 1;
                    log::info!(
                        "new udp connection:{} is {} -> {}",
                        handle,
                        src_endpoint,
                        dst_endpoint
                    );
                    let mut tls = pool.get(poll, resolver).unwrap();
                    tls.set_token(next_token(), poll);
                    let conn = Connection {
                        token: tls.token(),
                        local: *handle,
                        remote: tls,
                        rclosed: false,
                        rbuffer: BytesMut::with_capacity(1500), //TODO mtu
                        lbuffer: BytesMut::with_capacity(1500),
                        established: false,
                        endpoint: src_endpoint,
                        last_remote: Instant::now(),
                        pass: self.pass.clone(),
                        empty_addr: SocketAddr::V4(SocketAddrV4::new(0.into(), 0)),
                    };
                    Arc::new(conn)
                });
                self.token2conns
                    .entry(conn.token)
                    .or_insert_with(|| conn.clone());
                unsafe {
                    crate::get_mut_unchecked(conn).do_local(poll, self.buffer.as_ref(), data);
                }
                if conn.is_closed() {
                    self.removed.insert(conn.token);
                }
            }
        }
    }

    pub fn do_remote(&mut self, event: &Event, poll: &Poll, device: &mut VpnDevice) {
        if let Some(conn) = self.token2conns.get_mut(&event.token()) {
            log::debug!(
                "remote event for token:{} - handle:{}",
                event.token().0,
                conn.local
            );
            let socket = device.get_udp_socket_mut(conn.local, WakerMode::None);
            unsafe {
                crate::get_mut_unchecked(conn).do_remote(poll, socket, event);
            }
            if conn.is_closed() {
                self.removed.insert(conn.token);
            }
        } else {
            log::warn!("token:{} not found", event.token().0);
        }
    }

    pub fn remove_closed(&mut self) {
        for token in &self.removed {
            if let Some(conn) = self.token2conns.get(token) {
                let conn = conn.clone();
                self.handles.get_mut(&conn.local).unwrap().1 -= 1;
                self.token2conns.remove(&conn.token);
                self.addr2conns.remove(&conn.endpoint);
                log::info!(
                    "connection:{} - {} is closed, remove from server",
                    conn.token.0,
                    conn.endpoint
                );
            } else {
                log::warn!("connection:{} not found", token.0);
            }
        }
        self.removed.clear();
    }
}
