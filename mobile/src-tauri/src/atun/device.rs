use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    future::Future,
    io::{Error, ErrorKind},
    ops::DerefMut,
    pin::{pin, Pin},
    rc::Rc,
    sync::Arc,
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
    sync::Mutex,
    time::Sleep,
};

use crate::platform::{Packet, Session};

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
    let (dst_addr, payload, protocol) = match IpVersion::of_packet(packet.bytes()).unwrap() {
        IpVersion::Ipv4 => {
            let packet = Ipv4Packet::new_checked(packet.bytes()).unwrap();
            let dst_addr = packet.dst_addr();
            (
                IpAddress::Ipv4(dst_addr),
                packet.payload(),
                packet.next_header(),
            )
        }
        IpVersion::Ipv6 => {
            let packet = Ipv6Packet::new_checked(packet.bytes()).unwrap();
            let dst_addr = packet.dst_addr();
            (
                IpAddress::Ipv6(dst_addr),
                packet.payload(),
                packet.next_header(),
            )
        }
    };
    let (dst_port, connect) = match protocol {
        IpProtocol::Udp => {
            let packet = UdpPacket::new_checked(payload).unwrap();
            (packet.dst_port(), None)
        }
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).unwrap();
            (packet.dst_port(), Some(packet.syn() && !packet.ack()))
        }
        _ => return,
    };

    let dst_endpoint = IpEndpoint::new(dst_addr, dst_port);
    if is_private(dst_endpoint) || device.is_server(dst_endpoint) {
        log::info!("ignore private packets:{}", dst_endpoint);
        return;
    }

    match connect {
        Some(true) => {
            device.ensure_tcp_socket(dst_endpoint);
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
    sockets: Arc<RefCell<SocketSet<'static>>>,
    udp_set: HashSet<IpEndpoint>,
    tcp_ip2handle: HashMap<IpEndpoint, SocketHandle>,
    tcp_handle2ip: HashMap<SocketHandle, IpEndpoint>,
    mtu: usize,
    server_addr: IpEndpoint,
    dns_addr: IpEndpoint,
    traffic: Traffic,
    new_tcp: Vec<SocketHandle>,
    new_udp: Vec<SocketHandle>,
}

unsafe impl Send for VpnDevice {}

impl VpnDevice {
    pub fn new(
        session: Arc<Session>,
        sockets: Arc<RefCell<SocketSet<'static>>>,
        mtu: usize,
        server_addr: IpEndpoint,
        dns_addr: IpEndpoint,
    ) -> Self {
        Self {
            session,
            sockets,
            udp_set: HashSet::new(),
            tcp_ip2handle: HashMap::new(),
            tcp_handle2ip: HashMap::new(),
            mtu,
            server_addr,
            dns_addr,
            traffic: Traffic::new(),
            new_tcp: Vec::new(),
            new_udp: Vec::new(),
        }
    }

    pub fn poll(&mut self, interface: &mut Interface) -> bool {
        let sockets = self.sockets.clone();
        let mut sockets = sockets.borrow_mut();
        interface.poll(Instant::now(), self, &mut sockets)
    }

    pub fn poll_delay(&mut self, interface: &mut Interface) -> Option<smoltcp::time::Duration> {
        let mut sockets = self.sockets.borrow_mut();
        interface.poll_delay(Instant::now(), &mut sockets)
    }
    pub fn ensure_tcp_socket(&mut self, endpoint: IpEndpoint) {
        if self.tcp_ip2handle.contains_key(&endpoint) {
            return;
        }
        let socket = TcpSocket::new(
            SocketBuffer::new(vec![0; 102400]),
            SocketBuffer::new(vec![0; 102400]),
        );
        let mut sockets = self.sockets.borrow_mut();
        let handle = sockets.add(socket);
        let socket = sockets.get_mut::<TcpSocket>(handle);
        socket.listen(endpoint).unwrap();
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.tcp_ip2handle.insert(endpoint, handle);
        self.tcp_handle2ip.insert(handle, endpoint);
        self.new_tcp.push(handle);
    }

    pub fn ensure_udp_socket(&mut self, endpoint: IpEndpoint) {
        if self.udp_set.contains(&endpoint) {
            return;
        }
        let handle = self.create_udp_socket(endpoint);
        log::info!("udp handle:{} is {}", handle, endpoint);
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
        let mut device = vpn.lock().await;
        let handles = std::mem::take(&mut device.new_tcp);
        handles
            .into_iter()
            .map(|handle| {
                TcpStream::new(
                    handle,
                    vpn.clone(),
                    device.tcp_handle2ip.get(&handle).unwrap().clone(),
                )
            })
            .collect()
    }

    pub async fn accept_udp(vpn: &Arc<Mutex<VpnDevice>>) -> Vec<UdpStream> {
        let mut device = vpn.lock().await;
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
        self.sockets.borrow_mut().add(socket)
    }

    pub fn remove_socket(&mut self, handle: SocketHandle) {
        if let None = self
            .sockets
            .borrow_mut()
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

        let mut sockets = self.sockets.borrow_mut();
        sockets.remove(handle);
    }

    pub fn get_tcp_socket_mut(&mut self, handle: SocketHandle) -> &mut TcpSocket {
        let mut sockets = self.sockets.borrow_mut();
        let socket: &mut TcpSocket = sockets.get_mut(handle);
        unsafe { std::mem::transmute(socket) }
    }

    pub fn get_udp_socket_mut(&mut self, handle: SocketHandle) -> &mut UdpSocket {
        let mut sockets = self.sockets.borrow_mut();
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

impl VpnDevice {}

pub struct TcpStream {
    handle: SocketHandle,
    device: Arc<Mutex<VpnDevice>>,
    pub(crate) target: IpEndpoint,
    close_timer: Option<Sleep>,
}

impl Clone for TcpStream {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            device: self.device.clone(),
            target: self.target.clone(),
            close_timer: None,
        }
    }
}

impl Unpin for TcpStream {}

async fn remove_tcp_stream(device: Arc<Mutex<VpnDevice>>, handle: SocketHandle) {
    let mut device = device.lock().await;
    let sockets = device.sockets.clone();
    let mut sockets = sockets.borrow_mut();
    sockets.remove(handle);
    if let Some(endpoint) = device.tcp_handle2ip.get(&handle) {
        let endpoint = endpoint.clone();
        device.tcp_ip2handle.remove(&endpoint);
    }
    device.tcp_handle2ip.remove(&handle);
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        tokio::task::spawn(remove_tcp_stream(self.device.clone(), self.handle));
    }
}

impl TcpStream {
    pub fn new(
        handle: SocketHandle,
        device: Arc<Mutex<VpnDevice>>,
        target: IpEndpoint,
    ) -> TcpStream {
        Self {
            handle,
            device,
            target,
            close_timer: None,
        }
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut lock = self.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        let socket = lock.get_tcp_socket_mut(self.handle);
        if socket.may_recv() {
            if let Ok(n) = socket.recv_slice(buf.initialize_unfilled()) {
                if n > 0 {
                    buf.set_filled(n);
                    Poll::Ready(Ok(()))
                } else {
                    socket.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            } else {
                Poll::Ready(Err(ErrorKind::BrokenPipe.into()))
            }
        } else if socket.is_active() {
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
        let mut lock = self.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
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
        let pin = self.get_mut();
        let mut lock = pin.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        let socket = lock.get_tcp_socket_mut(pin.handle);
        if let State::Closed = socket.state() {
            Poll::Ready(Ok(()))
        } else {
            socket.register_recv_waker(cx.waker());
            if pin.close_timer.is_some() {
                let timer = pin.close_timer.take().unwrap();
                let deadline = timer.deadline();
                tokio::pin!(timer);
                let ret = timer.poll(cx).map(|_| Ok(()));
                if ret.is_pending() {
                    pin.close_timer.replace(tokio::time::sleep_until(deadline));
                }
                ret
            } else {
                socket.close();
                pin.close_timer
                    .replace(tokio::time::sleep(Duration::from_secs(60)));
                Poll::Pending
            }
        }
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
        let mut lock = pin.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        let socket = lock.get_udp_socket_mut(pin.handle);
        match socket.recv_slice(buf.initialize_unfilled()) {
            Ok((n, ep)) => {
                buf.set_filled(n + buf.filled().len());
                pin.target = ep;
                Poll::Ready(Ok(()))
            }
            Err(_) => Poll::Pending,
        }
    }
}

impl AsyncWrite for UdpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut lock = self.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        let socket = lock.get_udp_socket_mut(self.handle);
        match socket.send_slice(buf, self.target) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(SendError::BufferFull) => Poll::Pending,
            Err(_) => Poll::Ready(Err(ErrorKind::AddrNotAvailable.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let mut lock = self.device.lock();
        let mut lock = ready!(pin!(lock).poll(cx));
        lock.remove_socket(self.handle);
        Poll::Ready(Ok(()))
    }
}
