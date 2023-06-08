use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{iface::SocketHandle, socket::tcp::Socket};

use crate::{
    tun::{
        device::VpnDevice,
        idle_pool::IdlePool,
        proto::{TrojanRequest, CONNECT},
        resolver::DnsResolver,
        tls_conn::TlsConn,
        utils::copy_stream,
        waker::WakerMode,
        CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX,
    },
    types::{CopyResult, VpnError},
};

pub struct TcpStreamRef<'a, 'b> {
    socket: &'a mut Socket<'b>,
}

impl<'a, 'b> std::io::Read for TcpStreamRef<'a, 'b> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.socket.may_recv() {
            match self.socket.recv_slice(buf) {
                Ok(0) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) => {
                    log::info!(
                        "tcp {:?} - {:?} reading {} bytes",
                        self.socket.local_endpoint(),
                        self.socket.remote_endpoint(),
                        n
                    );
                    Ok(n)
                }
                Err(_) => Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    std::io::Error::last_os_error(),
                )),
            }
        } else if self.socket.is_active() {
            Err(ErrorKind::WouldBlock.into())
        } else {
            Err(ErrorKind::UnexpectedEof.into())
        }
    }
}

impl<'a, 'b> std::io::Write for TcpStreamRef<'a, 'b> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.socket.may_send() {
            match self.socket.send_slice(buf) {
                Ok(0) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) => {
                    log::info!(
                        "tcp {:?} - {:?} sending {} bytes",
                        self.socket.local_endpoint(),
                        self.socket.remote_endpoint(),
                        n,
                    );
                    Ok(n)
                }
                Err(_) => Err(Error::new(ErrorKind::UnexpectedEof, Error::last_os_error())),
            }
        } else if self.socket.is_active() {
            Err(ErrorKind::WouldBlock.into())
        } else {
            Err(ErrorKind::UnexpectedEof.into())
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
    lbuffer: BytesMut,
    rbuffer: BytesMut,
    lclosed: bool,
    rclosed: bool,
    established: bool,
    last_active: Instant,
    pass: String,
}

impl Connection {
    pub fn new(token: Token, local: SocketHandle, remote: TlsConn, pass: String) -> Self {
        Self {
            token,
            local,
            remote,
            pass,
            lbuffer: BytesMut::with_capacity(1500),
            rbuffer: BytesMut::with_capacity(1500),
            lclosed: false,
            rclosed: false,
            established: false,
            last_active: Instant::now(),
        }
    }

    fn close_stream(&mut self, is_local: bool, device: &mut VpnDevice, poll: &Poll) {
        if is_local && !self.lclosed {
            let socket = device.get_tcp_socket_mut(self.local, WakerMode::Dummy);
            socket.close();
            self.lclosed = true;
        } else if !is_local && !self.rclosed {
            self.remote.close(poll);
            self.rclosed = true;
        } else {
            log::info!(
                "connection {} stream already closed",
                if is_local { "local" } else { "remote" }
            );
        }
    }

    pub fn do_local(
        &mut self,
        device: &mut VpnDevice,
        poll: &Poll,
        event: &crate::tun::waker::Event,
    ) {
        self.last_active = Instant::now();
        if event.is_readable() {
            log::info!("local readable now");
            self.local_to_remote(device, poll);
        }
        if event.is_writable() {
            log::info!("local writable now");
            self.remote_to_local(device, poll);
        }
        self.check_half_close(device, poll);
        self.reregister_local(device);
    }

    fn reregister_local(&mut self, device: &mut VpnDevice) {
        if self.lclosed {
            return;
        }
        let mode = match (
            !self.lbuffer.is_empty(),
            self.rbuffer.is_empty() && !self.rclosed,
        ) {
            (true, true) => WakerMode::Both,
            (true, false) => WakerMode::Send,
            (false, true) => WakerMode::Recv,
            (false, false) => WakerMode::None,
        };
        device.get_tcp_socket_mut(self.local, mode);
    }

    fn flush_remote(&mut self, device: &mut VpnDevice, poll: &Poll) {
        match self.remote.flush() {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                log::info!("remote connection flush blocked");
            }
            Err(err) => {
                log::info!("flush data to remote failed:{}", err);
                self.close_stream(false, device, poll);
            }
            Ok(()) => log::info!("flush data successfully"),
        }
    }

    fn local_to_remote(&mut self, device: &mut VpnDevice, poll: &Poll) {
        log::info!("copy local request to remote");
        let socket = device.get_tcp_socket_mut(self.local, WakerMode::None);
        if !self.established {
            if !socket.is_active() {
                self.close_stream(true, device, poll);
            }
            return;
        }
        let mut local = TcpStreamRef { socket };
        match copy_stream(&mut local, &mut self.remote, &mut self.rbuffer) {
            Ok(CopyResult::TxBlock) => log::info!("remote sending blocked"),
            Ok(CopyResult::RxBlock) => log::info!("local reading blocked"),
            Err(VpnError::RxBreak(err)) => {
                log::info!("local break with error:{:?}", err);
                self.close_stream(true, device, poll)
            }
            Err(VpnError::TxBreak(err)) => {
                log::info!("remote break with err:{:?}", err);
                self.close_stream(false, device, poll)
            }
            _ => unreachable!(),
        }
        if !self.rclosed {
            self.flush_remote(device, poll);
        }
    }

    pub fn do_remote(&mut self, device: &mut VpnDevice, poll: &Poll, event: &Event) {
        self.last_active = Instant::now();
        if event.is_writable() {
            log::info!("remote writable");
            if !self.established {
                if self.lclosed {
                    self.close_stream(false, device, poll);
                    return;
                } else {
                    let mut request = BytesMut::new();
                    let socket = device.get_tcp_socket_mut(self.local, WakerMode::None);
                    if let Some(endpoint) = socket.local_endpoint() {
                        TrojanRequest::generate_endpoint(
                            &mut request,
                            CONNECT,
                            self.pass.as_bytes(),
                            &endpoint,
                        );
                        log::info!("send trojan request {} bytes", request.len());
                        if self.remote.write(request.as_ref()).is_ok() {
                            self.established = true;
                            log::info!("connection is ready now");
                        } else {
                            log::warn!("send trojan request failed");
                            self.close(device, poll);
                            return;
                        }
                    } else {
                        self.close(device, poll);
                        return;
                    }
                }
            }
            self.local_to_remote(device, poll);
        }

        if event.is_readable() {
            log::info!("remote readable");
            self.remote_to_local(device, poll);
            self.flush_remote(device, poll);
        }

        self.check_half_close(device, poll);
        self.reregister_local(device);
    }

    fn remote_to_local(&mut self, device: &mut VpnDevice, poll: &Poll) {
        log::info!("copy remote data to local");
        let socket = device.get_tcp_socket_mut(self.local, WakerMode::None);
        let mut local = TcpStreamRef { socket };
        let ret = copy_stream(&mut self.remote, &mut local, &mut self.lbuffer);
        let send_size = socket.send_queue();
        match ret {
            Ok(CopyResult::RxBlock) => log::info!("remote reading blocked"),
            Ok(CopyResult::TxBlock) => log::info!("local sending blocked"),
            Err(VpnError::RxBreak(err)) => {
                log::info!("remote connection break with:{:?}", err);
                self.close_stream(false, device, poll);
            }
            Err(VpnError::TxBreak(err)) => {
                log::info!("local connection break with:{:?}", err);
                self.close_stream(true, device, poll)
            }
            _ => unreachable!(),
        }
        //smoltcp sending is asynchronous, so send queue should be checked.
        if self.rclosed && !self.lclosed && self.lbuffer.is_empty() && send_size == 0 {
            log::info!("connection remote closed and nothing to send, close local now",);
            self.close_stream(true, device, poll);
        }
    }

    pub fn is_closed(&self, device: &mut VpnDevice) -> bool {
        let socket = device.get_tcp_socket_mut(self.local, WakerMode::None);
        self.rclosed && matches!(socket.state(), smoltcp::socket::tcp::State::Closed)
    }

    pub fn abort_local(&self, device: &mut VpnDevice) {
        let socket = device.get_tcp_socket_mut(self.local, WakerMode::None);
        socket.abort();
    }

    pub fn close(&mut self, device: &mut VpnDevice, poll: &Poll) {
        self.close_stream(true, device, poll);
        self.close_stream(false, device, poll);
    }

    fn check_half_close(&mut self, device: &mut VpnDevice, poll: &Poll) {
        if self.lclosed && !self.rclosed && self.rbuffer.is_empty() {
            log::info!(
                "connection:{} local closed and nothing to send, close remote now",
                self.local
            );
            self.close_stream(false, device, poll);
        }
        if self.rclosed && !self.lclosed && self.lbuffer.is_empty() {
            log::info!(
                "connection:{} remote closed and nothing to send, close local now",
                self.local
            );
            self.close_stream(true, device, poll);
        }
    }
}

fn next_token() -> Token {
    static mut NEXT_INDEX: usize = MIN_INDEX;
    unsafe {
        let index = NEXT_INDEX;
        NEXT_INDEX += 1;
        if NEXT_INDEX >= MAX_INDEX {
            NEXT_INDEX = MIN_INDEX;
        }
        Token(index * CHANNEL_CNT + CHANNEL_TCP)
    }
}

pub struct TcpServer {
    token2conns: HashMap<Token, Arc<Connection>>,
    handle2conns: HashMap<SocketHandle, Arc<Connection>>,
    removed: HashSet<SocketHandle>,
    pass: String,
}

impl TcpServer {
    pub fn new(pass: String) -> Self {
        Self {
            pass,
            token2conns: Default::default(),
            handle2conns: Default::default(),
            removed: HashSet::new(),
        }
    }

    pub(crate) fn do_local(
        &mut self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        device: &mut VpnDevice,
    ) {
        for (handle, event) in device.get_tcp_events().iter() {
            let handle = *handle;
            log::info!("new request, handle:{}, event:{:?}", handle, event);
            let socket = device.get_tcp_socket_mut(handle, WakerMode::None);
            if socket.is_listening() {
                if let Some(conn) = self.handle2conns.get_mut(&handle) {
                    unsafe { crate::get_mut_unchecked(conn) }.close(device, poll);
                }
                self.removed.insert(handle);
                continue;
            }
            let conn = self.handle2conns.entry(handle).or_insert_with(|| {
                log::info!("found new tcp connection");
                let token = next_token();
                let mut remote = pool.get(poll, resolver).unwrap();
                remote.set_token(token, poll);
                let conn = Connection::new(token, handle, remote, self.pass.clone());
                Arc::new(conn)
            });
            self.token2conns
                .entry(conn.token)
                .or_insert_with(|| conn.clone());
            unsafe { crate::get_mut_unchecked(conn).do_local(device, poll, event) };
            if conn.is_closed(device) {
                self.removed.insert(conn.local);
            }
            log::info!("handle:{} is done", handle);
        }
    }

    pub(crate) fn do_remote(&mut self, event: &Event, poll: &Poll, device: &mut VpnDevice) {
        if let Some(conn) = self.token2conns.get_mut(&event.token()) {
            unsafe { crate::get_mut_unchecked(conn).do_remote(device, poll, event) };
            if conn.is_closed(device) {
                self.removed.insert(conn.local);
            }
        } else {
            log::warn!("connection:{} not found in tcp sockets", event.token().0);
        }
    }

    pub fn remove_closed(&mut self, device: &mut VpnDevice) {
        for handle in &self.removed {
            if let Some(conn) = self.handle2conns.get(handle) {
                let conn = conn.clone();
                self.handle2conns.remove(handle);
                self.token2conns.remove(&conn.token);
                log::info!("handle:{} removed", handle);
            } else {
                log::info!("handle:{} not found in tcp server", handle);
            }
            device.remove_socket(*handle);
        }
        self.removed.clear();
    }

    pub(crate) fn check_timeout(&mut self, poll: &Poll, now: Instant, device: &mut VpnDevice) {
        log::info!("tcp server check timeout");
        let conns: Vec<_> = self
            .token2conns
            .iter()
            .filter_map(|(_, conn)| {
                let elapsed = now - conn.last_active;
                if conn.lclosed && elapsed > Duration::from_secs(120) {
                    conn.abort_local(device);
                    Some(conn.clone())
                } else if elapsed > Duration::from_secs(3600) {
                    Some(conn.clone())
                } else {
                    None
                }
            })
            .collect();
        for mut conn in conns {
            unsafe {
                crate::get_mut_unchecked(&mut conn).close(device, poll);
            }
            self.removed.insert(conn.local);
        }

        self.remove_closed(device);
    }
}
