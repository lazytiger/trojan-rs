use std::{
    collections::{HashMap, HashSet},
    io::{Error, ErrorKind, Write},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use mio::{event::Event, Poll, Token};
use smoltcp::{iface::SocketHandle, socket::TcpSocket};

use crate::{
    idle_pool::IdlePool,
    proto::{TrojanRequest, CONNECT},
    resolver::DnsResolver,
    tls_conn::TlsConn,
    types::{CopyResult, TrojanError},
    utils::copy_stream,
    wintun::{waker::Wakers, SocketSet, CHANNEL_CNT, CHANNEL_TCP, MAX_INDEX, MIN_INDEX},
};

pub struct TcpStreamRef<'a, 'b> {
    socket: &'a mut TcpSocket<'b>,
}

impl<'a, 'b> std::io::Read for TcpStreamRef<'a, 'b> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        log::info!("reading {} bytes", buf.len());
        if self.socket.may_recv() {
            match self.socket.recv_slice(buf) {
                Ok(0) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) => Ok(n),
                Err(err) => Err(Error::new(ErrorKind::UnexpectedEof, err)),
            }
        } else {
            Err(ErrorKind::WouldBlock.into())
        }
    }
}

impl<'a, 'b> std::io::Write for TcpStreamRef<'a, 'b> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        log::info!("sending {} bytes", buf.len());
        if self.socket.may_send() {
            match self.socket.send_slice(buf) {
                Ok(0) => Err(ErrorKind::WouldBlock.into()),
                Ok(n) => Ok(n),
                Err(err) => Err(Error::new(ErrorKind::UnexpectedEof, err)),
            }
        } else {
            Err(ErrorKind::WouldBlock.into())
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
}

impl Connection {
    pub fn new(token: Token, local: SocketHandle, remote: TlsConn) -> Self {
        Self {
            token,
            local,
            remote,
            lbuffer: BytesMut::with_capacity(1500),
            rbuffer: BytesMut::with_capacity(1500),
            lclosed: false,
            rclosed: false,
            established: false,
            last_active: Instant::now(),
        }
    }

    fn close_stream(&mut self, is_local: bool, sockets: &mut SocketSet, poll: &Poll) {
        if is_local && !self.lclosed {
            sockets.get_socket::<TcpSocket>(self.local).close();
            self.lclosed = true;
        } else if !is_local && !self.rclosed {
            let _ = self.remote.close(poll);
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
        sockets: &mut SocketSet,
        poll: &Poll,
        event: &crate::wintun::waker::Event,
        wakers: &mut Wakers,
    ) {
        self.last_active = Instant::now();
        if event.is_readable() {
            log::info!("local readable now");
            self.local_to_remote(sockets, poll);
        }
        if event.is_writable() {
            log::info!("local writable now");
            self.remote_to_local(sockets, poll);
        }
        self.reregister_local(wakers, sockets);
        self.check_half_close(sockets, poll);
    }

    fn reregister_local(&mut self, wakers: &mut Wakers, sockets: &mut SocketSet) {
        if self.lclosed {
            return;
        }
        let (rx, tx) = wakers.get_wakers(self.local);
        let socket = sockets.get_socket::<TcpSocket>(self.local);
        if !self.lbuffer.is_empty() {
            socket.register_send_waker(tx);
        }
        if self.rbuffer.is_empty() {
            socket.register_recv_waker(rx);
        }
    }

    fn flush_remote(&mut self, sockets: &mut SocketSet, poll: &Poll) {
        match self.remote.flush() {
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                log::info!("remote connection flush blocked");
            }
            Err(err) => {
                log::info!("flush data to remote failed:{}", err);
                self.close_stream(false, sockets, poll);
            }
            Ok(()) => log::info!("flush data successfully"),
        }
    }

    fn local_to_remote(&mut self, sockets: &mut SocketSet, poll: &Poll) {
        log::info!("copy local request to remote");
        let socket = sockets.get_socket::<TcpSocket>(self.local);
        let mut local = TcpStreamRef { socket };
        match copy_stream(&mut local, &mut self.remote, &mut self.rbuffer) {
            Ok(CopyResult::TxBlock) => log::info!("remote sending blocked"),
            Ok(CopyResult::RxBlock) => log::info!("local reading blocked"),
            Err(TrojanError::RxBreak(err)) => {
                log::info!("local break with error:{:?}", err);
                self.close_stream(true, sockets, poll)
            }
            Err(TrojanError::TxBreak(err)) => {
                log::info!("remote break with err:{:?}", err);
                self.close_stream(false, sockets, poll)
            }
            _ => unreachable!(),
        }
        if !self.rclosed {
            self.flush_remote(sockets, poll);
        }
    }

    pub fn do_remote(
        &mut self,
        sockets: &mut SocketSet,
        poll: &Poll,
        event: &Event,
        wakers: &mut Wakers,
    ) {
        self.last_active = Instant::now();
        if event.is_writable() {
            log::info!("remote writable");
            if !self.established {
                let mut request = BytesMut::new();
                let endpoint = sockets.get_socket::<TcpSocket>(self.local).local_endpoint();
                TrojanRequest::generate_endpoint(&mut request, CONNECT, &endpoint);
                log::info!("send trojan request {} bytes", request.len());
                if self.remote.write(request.as_ref()).is_ok() {
                    self.established = true;
                    log::info!("connection is ready now");
                } else {
                    self.close(sockets, poll);
                    return;
                }
            }
            self.local_to_remote(sockets, poll);
        }

        if event.is_readable() {
            log::info!("remote readable");
            self.remote_to_local(sockets, poll);
        }
        self.reregister_local(wakers, sockets);
        self.check_half_close(sockets, poll);
    }

    fn remote_to_local(&mut self, sockets: &mut SocketSet, poll: &Poll) {
        log::info!("copy remote data to local");
        let socket = sockets.get_socket::<TcpSocket>(self.local);
        let mut local = TcpStreamRef { socket };
        match copy_stream(&mut self.remote, &mut local, &mut self.lbuffer) {
            Ok(CopyResult::RxBlock) => log::info!("remote reading blocked"),
            Ok(CopyResult::TxBlock) => log::info!("local sending blocked"),
            Err(TrojanError::RxBreak(err)) => {
                log::info!("remote connection break with:{:?}", err);
                self.close_stream(false, sockets, poll);
            }
            Err(TrojanError::TxBreak(err)) => {
                log::info!("local connection break with:{:?}", err);
                self.close_stream(true, sockets, poll)
            }
            _ => unreachable!(),
        }
        if self.rclosed && !self.lclosed && self.lbuffer.is_empty() {
            log::info!("connection remote closed and nothing to send, close local now",);
            self.close_stream(true, sockets, poll);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.rclosed && self.lclosed
    }

    pub fn close(&mut self, sockets: &mut SocketSet, poll: &Poll) {
        self.close_stream(true, sockets, poll);
        self.close_stream(false, sockets, poll);
    }

    fn check_half_close(&mut self, sockets: &mut SocketSet, poll: &Poll) {
        if self.lclosed && !self.rclosed && self.rbuffer.is_empty() {
            log::info!(
                "connection:{} local closed and nothing to send, close remote now",
                self.local
            );
            self.close_stream(false, sockets, poll);
        }
        if self.rclosed && !self.lclosed && self.lbuffer.is_empty() {
            log::info!(
                "connection:{} remote closed and nothing to send, close local now",
                self.local
            );
            self.close_stream(true, sockets, poll);
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
}

impl TcpServer {
    pub fn new() -> Self {
        Self {
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
        wakers: &mut Wakers,
        sockets: &mut SocketSet,
    ) {
        for (handle, event) in wakers.get_events().iter() {
            let handle = *handle;
            log::info!("new request, handle:{}, event:{:?}", handle, event);
            let socket = sockets.get_socket::<TcpSocket>(handle);
            let endpoint = socket.local_endpoint();
            if !socket.is_active() {
                log::info!("socket:{} {} is not active, remove now", handle, endpoint,);
                self.removed.insert(handle);
                continue; // Filter unused syn packet
            }
            let conn = self.handle2conns.entry(handle).or_insert_with(|| {
                log::info!("found new tcp connection");
                let token = next_token();
                let mut remote = pool.get(poll, resolver).unwrap();
                remote.set_token(token, poll);
                let conn = Connection::new(token, handle, remote);
                Arc::new(conn)
            });
            self.token2conns
                .entry(conn.token)
                .or_insert_with(|| conn.clone());
            unsafe { Arc::get_mut_unchecked(conn).do_local(sockets, poll, event, wakers) };
            if conn.is_closed() {
                self.removed.insert(conn.local);
            }
            log::info!("handle:{} is done", handle);
        }
    }

    pub(crate) fn do_remote(
        &mut self,
        event: &Event,
        poll: &Poll,
        sockets: &mut SocketSet,
        wakers: &mut Wakers,
    ) {
        if let Some(conn) = self.token2conns.get_mut(&event.token()) {
            unsafe { Arc::get_mut_unchecked(conn).do_remote(sockets, poll, event, wakers) };
            if conn.is_closed() {
                self.removed.insert(conn.local);
            }
        } else {
            log::warn!("connection:{} not found in tcp sockets", event.token().0);
        }
    }

    pub fn remove_closed(&mut self, sockets: &mut SocketSet) {
        for handle in &self.removed {
            if let Some(conn) = self.handle2conns.get(handle) {
                let conn = conn.clone();
                self.handle2conns.remove(handle);
                self.token2conns.remove(&conn.token);
                log::info!("handle:{} removed", handle);
            } else {
                log::info!("handle:{} not found", handle);
            }
            sockets.remove_socket(*handle);
        }
        self.removed.clear();
    }

    pub(crate) fn check_timeout(&mut self, poll: &Poll, now: Instant, sockets: &mut SocketSet) {
        log::info!("tcp server check timeout");
        let conns: Vec<_> = self
            .token2conns
            .iter()
            .filter_map(|(_, conn)| {
                let elapsed = now - conn.last_active;
                if elapsed > Duration::from_secs(3600) {
                    Some(conn.clone())
                } else {
                    None
                }
            })
            .collect();
        for mut conn in conns {
            unsafe {
                Arc::get_mut_unchecked(&mut conn).close(sockets, poll);
            }
            self.removed.insert(conn.local);
        }

        self.remove_closed(sockets);
    }
}
