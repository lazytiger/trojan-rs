use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    io::{Error, ErrorKind},
    ops::{Deref, DerefMut},
    pin::{pin, Pin},
    rc::Rc,
    sync::{Arc, Mutex},
    task::{ready, Context, Poll},
    time::Duration,
};

use rustls::internal::msgs::handshake::SessionId;
use smoltcp::{
    iface::{Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium},
    socket::{
        icmp::Endpoint,
        tcp::{RecvError, Socket as TcpSocket, SocketBuffer, State},
        udp::{PacketBuffer, PacketMetadata, SendError, Socket as UdpSocket},
        Socket,
    },
    time::Instant,
    wire::{
        IpAddress, IpEndpoint, IpListenEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet,
        TcpPacket, UdpPacket,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    time::Sleep,
};

use crate::{
    get_mut_unchecked,
    platform::{Packet, Session},
};

fn is_private(endpoint: IpEndpoint) -> bool {
    if let IpAddress::Ipv4(ip) = endpoint.addr {
        endpoint.port == 0
            || ip.is_unspecified() //0.0.0.0/8
            || ip.0[0] == 10 //10.0.0.0/8
            || ip.is_loopback() //127.0.0.0/8
            || ip.is_link_local() //169.254.0.0/16
            || ip.0[0] == 172 && ip.0[1] & 0xf0 == 16 //172.16.0.0/12
            || ip.0[0] == 192 && ip.0[1] == 168 //192.168.0.0/16
            || ip.is_multicast() //224.0.0.0/4
            || ip.0[0] & 0xf0 == 240 // 240.0.0.0/4
            || ip.is_broadcast() //255.255.255.255/32
    } else {
        true
    }
}

fn preprocess_packet(packet: &Packet, device: &mut VpnDevice) {
    let (dst_addr, src_addr, payload, protocol) =
        match IpVersion::of_packet(packet.bytes()).unwrap() {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_checked(packet.bytes()).unwrap();
                let dst_addr = packet.dst_addr();
                let src_addr = packet.src_addr();
                (
                    IpAddress::Ipv4(dst_addr),
                    IpAddress::Ipv4(src_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_checked(packet.bytes()).unwrap();
                let dst_addr = packet.dst_addr();
                let src_addr = packet.src_addr();
                (
                    IpAddress::Ipv6(dst_addr),
                    IpAddress::Ipv6(src_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
        };
    let (dst_port, src_port, connect) = match protocol {
        IpProtocol::Udp => {
            let packet = UdpPacket::new_checked(payload).unwrap();
            (packet.dst_port(), packet.src_port(), None)
        }
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).unwrap();
            (
                packet.dst_port(),
                packet.src_port(),
                Some(packet.syn() && !packet.ack()),
            )
        }
        _ => return,
    };

    let dst_endpoint = IpEndpoint::new(dst_addr, dst_port);
    let src_endpoint = IpEndpoint::new(src_addr, src_port);
    if device.dns_addr != dst_endpoint
        && (is_private(dst_endpoint) || device.is_server(dst_endpoint))
    {
        return;
    }

    match connect {
        Some(true) => {
            device.ensure_tcp_socket(dst_endpoint, src_endpoint);
        }
        None => {
            device.ensure_udp_socket(dst_endpoint);
        }
        _ => {}
    }
}

pub struct Traffic {
    rx_bytes: usize,
    tx_bytes: usize,
    begin_traffic: std::time::Instant,
}

impl Traffic {
    fn new() -> Traffic {
        Self {
            rx_bytes: 0,
            tx_bytes: 0,
            begin_traffic: std::time::Instant::now(),
        }
    }
}

pub struct VpnDevice {
    session: Arc<Session>,
    sockets: Arc<SocketSet<'static>>,
    udp_set: HashSet<IpEndpoint>,
    tcp_ip2handle: HashMap<IpEndpoint, (SocketHandle, IpEndpoint)>,
    mtu: usize,
    server_addr: IpEndpoint,
    dns_addr: IpEndpoint,
    traffic: Traffic,
    new_tcp: Vec<IpEndpoint>,
    new_udp: Vec<SocketHandle>,
}

unsafe impl Send for VpnDevice {}

impl VpnDevice {
    pub fn new(
        session: Arc<Session>,
        sockets: SocketSet<'static>,
        mtu: usize,
        server_addr: IpEndpoint,
        dns_addr: IpEndpoint,
    ) -> Self {
        Self {
            session,
            sockets: Arc::new(sockets),
            udp_set: HashSet::new(),
            tcp_ip2handle: HashMap::new(),
            mtu,
            server_addr,
            dns_addr,
            traffic: Traffic::new(),
            new_tcp: Vec::new(),
            new_udp: Vec::new(),
        }
    }

    pub fn sockets_mut(mut sockets: Arc<SocketSet>) -> &'static mut SocketSet {
        unsafe { std::mem::transmute(get_mut_unchecked(&mut sockets)) }
    }

    pub fn poll(&mut self, interface: &mut Interface) -> bool {
        let sockets = Self::sockets_mut(self.sockets.clone());
        interface.poll(Instant::now(), self, sockets)
    }

    pub fn poll_delay(&mut self, interface: &mut Interface) -> Option<smoltcp::time::Duration> {
        let sockets = Self::sockets_mut(self.sockets.clone());
        interface.poll_delay(Instant::now(), sockets)
    }
    pub fn ensure_tcp_socket(&mut self, dst_endpoint: IpEndpoint, src_endpoint: IpEndpoint) {
        if self.tcp_ip2handle.contains_key(&src_endpoint) {
            return;
        }
        let socket = TcpSocket::new(
            SocketBuffer::new(vec![0; 102400]),
            SocketBuffer::new(vec![0; 102400]),
        );
        let sockets = Self::sockets_mut(self.sockets.clone());
        let handle = sockets.add(socket);
        let socket = sockets.get_mut::<TcpSocket>(handle);
        socket.listen(dst_endpoint).unwrap();
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.tcp_ip2handle
            .insert(src_endpoint, (handle, dst_endpoint));
        self.new_tcp.push(src_endpoint);
    }

    pub fn ensure_udp_socket(&mut self, endpoint: IpEndpoint) {
        if self.dns_addr == endpoint || self.udp_set.contains(&endpoint) {
            return;
        }
        let handle = self.create_udp_socket(endpoint);
        self.udp_set.insert(endpoint);
        self.new_udp.push(handle);
    }

    pub async fn new_udp(
        vpn: &Arc<Mutex<VpnDevice>>,
        handle: SocketHandle,
        target: IpEndpoint,
    ) -> UdpStream {
        UdpStream {
            device: vpn.clone(),
            handle,
            target,
        }
    }

    pub async fn accept_tcp(vpn: &Arc<Mutex<VpnDevice>>) -> Vec<TcpStream> {
        let mut device = vpn.lock().unwrap();
        let handles = std::mem::take(&mut device.new_tcp);
        handles
            .into_iter()
            .map(|endpoint| {
                let (handle, dst_endpoint) = device.tcp_ip2handle.get(&endpoint).unwrap().clone();
                TcpStream::new(handle, vpn.clone(), endpoint, dst_endpoint)
            })
            .collect()
    }

    pub async fn accept_udp(vpn: &Arc<Mutex<VpnDevice>>) -> Vec<UdpStream> {
        let mut device = vpn.lock().unwrap();
        let handles = std::mem::take(&mut device.new_udp);
        handles
            .into_iter()
            .map(|handle| {
                UdpStream::new(
                    handle,
                    vpn.clone(),
                    device.get_udp_socket_mut(handle).endpoint(),
                )
            })
            .collect()
    }

    pub fn create_udp_socket(&mut self, endpoint: IpEndpoint) -> SocketHandle {
        let mut socket = UdpSocket::new(
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 200], vec![0; 10240]),
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 10000], vec![0; 1024000]),
        );
        socket.bind(endpoint).unwrap();
        let sockets = Self::sockets_mut(self.sockets.clone());
        sockets.add(socket)
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        let sockets = Self::sockets_mut(self.sockets.clone());
        if let None = sockets
            .iter_mut()
            .find(|(h, _)| *h == handle)
            .map(|(_, socket)| match socket {
                Socket::Udp(socket) => {
                    let endpoint =
                        IpEndpoint::new(socket.endpoint().addr.unwrap(), socket.endpoint().port);
                    socket.close();
                    self.udp_set.remove(&endpoint);
                }
                Socket::Tcp(socket) => {
                    socket.close();
                }
                _ => {
                    log::error!("unexpected socket type:{:?}", socket);
                }
            })
        {
            log::error!("socket:{} not found", handle);
        }

        sockets.remove(handle);
    }

    pub fn get_tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut TcpSocket {
        let sockets = Self::sockets_mut(self.sockets.clone());
        let socket: &mut TcpSocket = sockets.get_mut(handle);
        unsafe { std::mem::transmute(socket) }
    }

    pub fn get_udp_socket_mut(&mut self, handle: SocketHandle) -> &mut UdpSocket {
        let sockets = Self::sockets_mut(self.sockets.clone());
        let socket: &mut UdpSocket = sockets.get_mut(handle);
        unsafe { std::mem::transmute(socket) }
    }

    pub fn calculate_speed(&mut self) -> (f64, f64) {
        let time = self.traffic.begin_traffic.elapsed().as_secs_f64();
        let rx_speed = self.traffic.rx_bytes as f64 / time / 1024.0;
        let tx_speed = self.traffic.tx_bytes as f64 / time / 1024.0;
        self.traffic.rx_bytes = 0;
        self.traffic.tx_bytes = 0;
        self.traffic.begin_traffic = std::time::Instant::now();
        (rx_speed, tx_speed)
    }

    pub fn is_server(&self, ip: IpEndpoint) -> bool {
        self.server_addr.addr == ip.addr
    }
}

impl Device for VpnDevice {
    type RxToken<'a> = RxToken where Self: 'a;
    type TxToken<'a> = TxToken<'a> where Self: 'a;

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.session
            .try_receive()
            .ok()
            .map(|packet| {
                packet.map(|packet| {
                    self.traffic.rx_bytes += packet.bytes().len();
                    preprocess_packet(&packet, self);
                    let rx = RxToken { packet };
                    let tx = TxToken {
                        session: self.session.clone(),
                        traffic: &mut self.traffic,
                    };
                    (rx, tx)
                })
            })
            .unwrap_or(None)
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            session: self.session.clone(),
            traffic: &mut self.traffic,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut dc = DeviceCapabilities::default();
        dc.medium = Medium::Ip;
        dc.max_transmission_unit = self.mtu;
        dc
    }
}

pub struct TxToken<'a> {
    session: Arc<Session>,
    traffic: &'a mut Traffic,
}

pub struct RxToken {
    packet: Packet,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.packet.bytes_mut())
    }
}

impl<'a> smoltcp::phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.traffic.tx_bytes += len;
        self.session
            .allocate_send_packet(len as u16)
            .map(|mut packet| {
                let r = f(packet.bytes_mut());
                self.session.send_packet(packet);
                r
            })
            .unwrap()
    }
}

pub struct TcpStream {
    handle: SocketHandle,
    device: Arc<Mutex<VpnDevice>>,
    pub src_addr: IpEndpoint,
    pub dst_addr: IpEndpoint,
    close_timer: Option<Sleep>,
    reader: bool,
}

impl Clone for TcpStream {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            device: self.device.clone(),
            src_addr: self.src_addr.clone(),
            dst_addr: self.dst_addr.clone(),
            close_timer: None,
            reader: true,
        }
    }
}

impl Unpin for TcpStream {}

async fn remove_tcp_stream(device: Arc<Mutex<VpnDevice>>, endpoint: IpEndpoint) {
    let mut device = device.lock().unwrap();
    let sockets = VpnDevice::sockets_mut(device.sockets.clone());
    if let Some((handle, _)) = device.tcp_ip2handle.get(&endpoint) {
        sockets.remove(*handle);
        device.tcp_ip2handle.remove(&endpoint);
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if self.reader {
            return;
        }
        tokio::task::spawn(remove_tcp_stream(self.device.clone(), self.src_addr));
    }
}

impl TcpStream {
    pub fn new(
        handle: SocketHandle,
        device: Arc<Mutex<VpnDevice>>,
        src_addr: IpEndpoint,
        dst_addr: IpEndpoint,
    ) -> TcpStream {
        Self {
            handle,
            device,
            src_addr,
            dst_addr,
            close_timer: None,
            reader: false,
        }
    }

    pub fn close(&self) {
        let mut lock = self.device.lock().unwrap();
        let socket = lock.get_tcp_socket_mut(self.handle);
        log::info!("close socket, current state:{}", socket.state());
        socket.close();
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut lock = self.device.lock().unwrap();
        let socket = lock.get_tcp_socket_mut(self.handle);
        if socket.may_recv() {
            if let Ok(n) = socket.recv_slice(buf.initialize_unfilled()) {
                if n > 0 {
                    buf.set_filled(n + buf.filled().len());
                    Poll::Ready(Ok(()))
                } else {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            } else {
                Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
            }
        } else if let State::Established = socket.state() {
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut lock = self.device.lock().unwrap();
        let socket = lock.get_tcp_socket_mut(self.handle);
        if socket.may_send() {
            if let Ok(n) = socket.send_slice(buf) {
                if n == 0 {
                    socket.register_send_waker(cx.waker());
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(n))
                }
            } else {
                Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
            }
        } else if socket.is_active() {
            socket.register_send_waker(cx.waker());
            Poll::Pending
        } else {
            Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
pub struct UdpStream {
    device: Arc<Mutex<VpnDevice>>,
    handle: SocketHandle,
    pub(crate) target: IpEndpoint,
}

impl UdpStream {
    fn new(handle: SocketHandle, device: Arc<Mutex<VpnDevice>>, lep: IpListenEndpoint) -> Self {
        let target = IpEndpoint::new(lep.addr.unwrap(), lep.port);
        Self {
            device,
            handle,
            target,
        }
    }

    pub async fn recv(&mut self, buffer: &mut [u8]) -> Result<(usize, IpEndpoint), Error> {
        self.read(buffer).await.map(|n| (n, self.target))
    }

    pub async fn send(&mut self, buffer: &[u8], target: IpEndpoint) -> std::io::Result<()> {
        self.target = target;
        self.write_all(buffer).await
    }
}

impl AsyncRead for UdpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pin = self.get_mut();
        let mut lock = pin.device.lock().unwrap();
        let socket = lock.get_udp_socket_mut(pin.handle);
        if socket.can_recv() {
            match socket.recv_slice(buf.initialize_unfilled()) {
                Ok((n, ep)) => {
                    buf.set_filled(n + buf.filled().len());
                    pin.target = ep.endpoint;
                    Poll::Ready(Ok(()))
                }
                Err(err) => Poll::Ready(Err(ErrorKind::BrokenPipe.into())),
            }
        } else {
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        }
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut lock = self.device.lock().unwrap();
        let socket = lock.get_udp_socket_mut(self.handle);
        match socket.send_slice(buf, self.target) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(SendError::BufferFull) => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(ErrorKind::AddrNotAvailable.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut lock = self.device.lock().unwrap();
        lock.remove_socket(self.handle);
        Poll::Ready(Ok(()))
    }
}
