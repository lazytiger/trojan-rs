use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
    time::SystemTime,
};

use bytes::{Buf, BytesMut};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium},
    socket::{
        tcp::{Socket as TcpSocket, SocketBuffer, State},
        udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket},
        Socket,
    },
    time::Instant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Address,
        Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
    },
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{tcp::TcpStream, Packet, Tun, TypeConverter};

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

pub struct TunDevice<'a, T: Tun> {
    tun: T,
    traffic: Traffic,
    mtu: usize,
    sockets: SocketSet<'a>,
    tcp_ip2handle: HashMap<IpEndpoint, (SocketHandle, IpEndpoint)>,
    tcp_handle2ip: HashMap<SocketHandle, IpEndpoint>,
    udp_ip2handle: HashMap<IpEndpoint, SocketHandle>,
    new_tcp: Vec<IpEndpoint>,
    new_udp: Vec<IpEndpoint>,
    white_ip_list: HashSet<IpAddress>,
    black_ip_list: HashSet<IpAddress>,
    allow_private: bool,
    /// (source address, data)
    tcp_receiver: Receiver<(IpEndpoint, BytesMut)>,
    tcp_sender: Sender<(IpEndpoint, BytesMut)>,
    /// (source address, sender)
    tcp_req_senders: HashMap<IpEndpoint, Sender<BytesMut>>,

    /// (source address, target address, data)
    udp_receiver: Receiver<(IpEndpoint, IpEndpoint, BytesMut)>,
    udp_sender: Sender<(IpEndpoint, IpEndpoint, BytesMut)>,
    /// (source address, sender)
    udp_req_senders: HashMap<IpEndpoint, Sender<(IpEndpoint, BytesMut)>>,

    interface: Option<Interface>,
    channel_buffer_size: usize,
    tcp_tx_bufffer_size: usize,
    tcp_rx_buffer_size: usize,
    udp_tx_buffer_size: usize,
    udp_rx_buffer_size: usize,

    last_shrink: std::time::Instant,

    tcp_response: HashMap<IpEndpoint, VecDeque<BytesMut>>,
}

fn is_private_v4(addr: IpAddress) -> bool {
    if let IpAddress::Ipv4(ip) = addr {
        ip.is_unspecified() //0.0.0.0/8
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

impl<'a, T: Tun + Clone> TunDevice<'a, T> {
    pub fn new(mtu: usize, tun: T) -> Self {
        let channel_buffer = 1024;
        let (tcp_sender, tcp_receiver) = channel(channel_buffer);
        let (udp_sender, udp_receiver) = channel(channel_buffer);
        let mut device = Self {
            tun,
            traffic: Traffic::new(),
            mtu,
            sockets: SocketSet::new([]),
            tcp_ip2handle: Default::default(),
            tcp_handle2ip: Default::default(),
            udp_ip2handle: Default::default(),
            new_tcp: vec![],
            new_udp: vec![],
            white_ip_list: Default::default(),
            black_ip_list: Default::default(),
            allow_private: false,
            tcp_receiver,
            tcp_sender,
            tcp_req_senders: Default::default(),
            udp_receiver,
            udp_sender,
            udp_req_senders: Default::default(),
            interface: None,
            channel_buffer_size: channel_buffer,
            tcp_tx_bufffer_size: mtu * channel_buffer,
            tcp_rx_buffer_size: mtu * 128,
            udp_tx_buffer_size: mtu * channel_buffer,
            udp_rx_buffer_size: mtu * 128,
            last_shrink: std::time::Instant::now(),

            tcp_response: Default::default(),
        };
        let interface = device.create_interface();
        device.interface.replace(interface);
        device
    }

    pub fn add_black_ip(&mut self, server_addr: impl Into<IpAddr>) {
        self.black_ip_list.insert(server_addr.into().into());
    }

    pub fn allow_private(&mut self, allow: bool) {
        self.allow_private = allow;
    }

    pub fn add_white_ip(&mut self, addr: impl Into<IpAddress>) {
        self.white_ip_list.insert(addr.into());
    }

    pub fn set_tcp_buffer_size(&mut self, rx: usize, tx: usize) {
        self.tcp_rx_buffer_size = rx.max(self.mtu * 128);
        self.tcp_tx_bufffer_size = tx.max(self.mtu * self.channel_buffer_size);
    }

    pub fn set_channel_buffer_size(&mut self, channel: usize) {
        self.channel_buffer_size = channel.max(self.channel_buffer_size);
        self.set_tcp_buffer_size(self.tcp_rx_buffer_size, self.tcp_tx_bufffer_size);
        self.set_udp_buffer_size(self.udp_rx_buffer_size, self.udp_tx_buffer_size);
    }

    pub fn set_udp_buffer_size(&mut self, rx: usize, tx: usize) {
        self.udp_rx_buffer_size = rx.max(self.mtu * 128);
        self.udp_tx_buffer_size = tx.max(self.mtu * self.channel_buffer_size);
    }

    fn allowed(&self, endpoint: impl Into<IpEndpoint>) -> bool {
        let endpoint = endpoint.into();
        if endpoint.port == 0 {
            false
        } else if self.black_ip_list.contains(&endpoint.addr) {
            false
        } else if self.white_ip_list.contains(&endpoint.addr) {
            true
        } else {
            self.allow_private || !is_private_v4(endpoint.addr)
        }
    }

    fn ensure_tcp_socket(&mut self, dst_endpoint: IpEndpoint, src_endpoint: IpEndpoint) {
        if self.tcp_ip2handle.contains_key(&src_endpoint) {
            return;
        }
        let socket = TcpSocket::new(
            SocketBuffer::new(vec![0; self.tcp_rx_buffer_size]),
            SocketBuffer::new(vec![0; self.tcp_tx_bufffer_size]),
        );
        let handle = self.sockets.add(socket);
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.listen(dst_endpoint).unwrap();
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.tcp_ip2handle
            .insert(src_endpoint, (handle, dst_endpoint));
        self.tcp_handle2ip.insert(handle, src_endpoint);
        self.new_tcp.push(src_endpoint);
        log::info!("found new tcp:{}", src_endpoint);
    }

    fn ensure_udp_socket(&mut self, _src_endpoint: IpEndpoint, dst_endpoint: IpEndpoint) {
        if self.udp_ip2handle.contains_key(&dst_endpoint) {
            return;
        }
        let mut socket = UdpSocket::new(
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; self.udp_rx_buffer_size / self.mtu],
                vec![0; self.udp_rx_buffer_size],
            ),
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; self.udp_tx_buffer_size / self.mtu],
                vec![0; self.udp_tx_buffer_size],
            ),
        );
        socket.bind(dst_endpoint).unwrap();
        let handle = self.sockets.add(socket);
        self.udp_ip2handle.insert(dst_endpoint, handle);
        self.new_udp.push(dst_endpoint);
    }

    pub fn accept_tcp(&mut self) -> Vec<TcpStream> {
        let mut streams = Vec::new();
        for source in std::mem::take(&mut self.new_tcp) {
            let (sender, receiver) = channel(self.channel_buffer_size);
            self.tcp_req_senders.insert(source, sender);
            log::info!("accept tcp {}", source);
            let stream = TcpStream::new(
                receiver,
                self.tcp_sender.clone(),
                source,
                self.tcp_ip2handle.get(&source).unwrap().1,
            );
            streams.push(stream);
        }
        streams
    }

    pub fn accept_udp(&mut self) -> Vec<crate::udp::UdpSocket> {
        let mut sockets = Vec::new();
        for target in std::mem::take(&mut self.new_udp) {
            let (sender, receiver) = channel(self.channel_buffer_size);
            self.udp_req_senders.insert(target, sender);
            let socket = crate::udp::UdpSocket::new(target, receiver, self.udp_sender.clone());
            sockets.push(socket);
        }
        sockets
    }

    fn create_interface(&mut self) -> Interface {
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut interface = Interface::new(config, self, smoltcp::time::Instant::now());
        interface.set_any_ip(true);
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .unwrap();

        interface.update_ip_addrs(|ips| {
            ips.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 32))
                .unwrap();
        });
        interface
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

    fn shrink_maps(&mut self) {
        self.tcp_response.shrink_to_fit();
        self.tcp_ip2handle.shrink_to_fit();
        self.tcp_handle2ip.shrink_to_fit();
        self.udp_ip2handle.shrink_to_fit();
        self.tcp_req_senders.shrink_to_fit();
        self.udp_req_senders.shrink_to_fit();
        log::info!("tcp_response:{}, tcp_ip2handle:{}, udp_ip2handle:{}, tcp_req_senders:{}, udp_req_senders:{}",
            self.tcp_response.len(), self.tcp_ip2handle.len(),
            self.udp_ip2handle.len(), self.tcp_req_senders.len(), self.udp_req_senders.len());
    }

    pub fn poll(&mut self) -> (Vec<TcpStream>, Vec<crate::udp::UdpSocket>) {
        let mut interface = self.interface.take().unwrap();
        let sockets = &mut self.sockets as *mut SocketSet;
        interface.poll(smoltcp::time::Instant::now(), self, unsafe {
            &mut *sockets
        });
        self.interface.replace(interface);
        let tcp = self.accept_tcp();
        let udp = self.accept_udp();
        self.process_ingress();
        self.process_egress();
        if self.last_shrink.elapsed().as_secs() > 1 {
            self.shrink_maps();
            self.last_shrink = std::time::Instant::now();
        }
        (tcp, udp)
    }

    fn process_ingress(&mut self) {
        let mut handles = Vec::new();
        let mut tcp_endpoints = Vec::new();
        let mut udp_endpoints = Vec::new();
        self.sockets
            .iter_mut()
            .for_each(|(handle, socket)| match socket {
                Socket::Tcp(socket) => {
                    if let Some(source) = socket.remote_endpoint() {
                        let sender = self
                            .tcp_req_senders
                            .get(&source)
                            .unwrap();
                        while socket.can_recv() && sender.capacity() > 0 {
                            log::info!("dispatch ingress tcp {} {}", source, socket.state());
                            let mut buffer = BytesMut::with_capacity(socket.recv_queue());
                            unsafe {
                                buffer.set_len(socket.recv_queue());
                            }
                            if let Ok(n) = socket.recv_slice(buffer.as_mut()) {
                                log::info!("receive {} bytes from {}", n, source);
                                if n != buffer.len() {
                                    log::error!("tcp recv_slice do not drain the buffer");
                                    unsafe {
                                        buffer.set_len(n);
                                    }
                                }
                                if sender.try_send(buffer)
                                    .is_err()
                                {
                                    log::error!("tcp send request failed, trying to adjust request channel buffer size");
                                    socket.close();
                                    break;
                                }
                            } else {
                                socket.close();
                                break;
                            }
                        }
                        if socket.state() == State::CloseWait && socket.send_queue() == 0 {
                            let _ = self
                                .tcp_req_senders
                                .get(&source)
                                .unwrap()
                                .try_send(BytesMut::with_capacity(0));
                            socket.close();
                        }
                        if !socket.is_active() {
                            log::info!("socket is not active now");
                            tcp_endpoints.push(source);
                        }
                    } else {
                        log::info!("remove socket handle:{} state:{}", handle, socket.state());
                        handles.push(handle);
                    }
                }
                Socket::Udp(socket) => {
                    let target: IpEndpoint = socket.endpoint().convert();
                    let sender = self
                        .udp_req_senders
                        .get(&target)
                        .unwrap();
                    while socket.can_recv() && sender.capacity() > 0 {
                        log::info!("dispatch udp {}", target);
                        let mut buffer = BytesMut::with_capacity(self.mtu);
                        unsafe {
                            buffer.set_len(self.mtu);
                        }
                        if let Ok((n, source)) = socket.recv_slice(buffer.as_mut()) {
                            unsafe {
                                buffer.set_len(n);
                            }
                            if sender.try_send((source.endpoint, buffer)).is_err()
                            {
                                log::error!("send udp request failed, trying to adjust udp request channel buffer size");
                                udp_endpoints.push(target);
                                break;
                            }
                        } else {
                            udp_endpoints.push(target);
                            break;
                        }
                    }
                    if !socket.is_open() {
                        udp_endpoints.push(target);
                    }
                }
                _ => {}
            });
        for endpoint in tcp_endpoints {
            self.remove_tcp(endpoint);
        }
        for endpoint in udp_endpoints {
            self.remove_udp(endpoint);
        }
        for handle in handles {
            self.remove_tcp_handle(handle);
        }
    }

    fn process_egress(&mut self) {
        let mut response = std::mem::take(&mut self.tcp_response);
        while let Ok((source, data)) = self.tcp_receiver.try_recv() {
            response.entry(source).or_default().push_back(data);
        }
        let mut to_be_removed = Vec::new();
        for (source, packets) in &mut response {
            if !self.tcp_ip2handle.contains_key(source) {
                to_be_removed.push(*source);
                continue;
            }
            log::info!("get tcp socket:{}", source);
            let socket = self.get_tcp_socket(*source);
            while let Some(mut data) = packets.pop_front() {
                if !data.is_empty() {
                    if let Ok(n) = socket.send_slice(data.as_ref()) {
                        data.advance(n);
                        if data.is_empty() {
                            continue;
                        } else {
                            log::error!(
                                "tcp socket is full {}, trying to adjust socket buffer size",
                                socket.send_queue()
                            );
                            packets.push_front(data);
                            break;
                        }
                    }
                }
                socket.close();
            }
            if packets.is_empty() {
                packets.shrink_to_fit();
            }
        }
        for source in to_be_removed {
            response.remove(&source);
        }
        self.tcp_response = response;

        let mut response: HashMap<IpEndpoint, Vec<(IpEndpoint, BytesMut)>> = HashMap::new();
        while let Ok((source, target, data)) = self.udp_receiver.try_recv() {
            response.entry(target).or_default().push((source, data));
        }
        for (target, packets) in response {
            if !self.udp_ip2handle.contains_key(&target) {
                continue;
            }
            log::info!("get udp socket:{}", target);
            let socket = self.get_udp_socket(target);
            let mut remove = false;
            for (source, data) in packets {
                if data.is_empty() || socket.send_slice(data.as_ref(), source).is_err() {
                    remove = true;
                    break;
                }
            }
            if remove {
                self.remove_udp(target);
            }
        }
    }

    fn remove_tcp_handle(&mut self, handle: SocketHandle) {
        if let Some(source) = self.tcp_handle2ip.get(&handle) {
            let source = *source;
            self.remove_tcp(source);
            self.tcp_handle2ip.remove(&handle);
        }
    }

    fn remove_tcp(&mut self, source: IpEndpoint) {
        log::info!("remove tcp {}", source);
        if let Some((handle, _)) = self.tcp_ip2handle.get(&source) {
            let handle = *handle;
            self.sockets.remove(handle);
            self.tcp_ip2handle.remove(&source);
        }
        self.tcp_req_senders.remove(&source);
        self.tcp_response.remove(&source);
    }

    fn remove_udp(&mut self, target: IpEndpoint) {
        log::info!("remove udp {}", target);
        if let Some(handle) = self.udp_ip2handle.get(&target) {
            let handle = *handle;
            self.sockets.remove(handle);
            self.udp_ip2handle.remove(&target);
        }
        self.udp_req_senders.remove(&target);
    }

    fn get_tcp_socket(&mut self, source: IpEndpoint) -> &mut TcpSocket {
        let handle = self.tcp_ip2handle.get(&source).unwrap().0;
        let socket: &mut TcpSocket = self.sockets.get_mut(handle);
        unsafe { std::mem::transmute(socket) }
    }

    fn get_udp_socket(&mut self, source: IpEndpoint) -> &mut UdpSocket {
        let handle = *self.udp_ip2handle.get(&source).unwrap();
        let socket: &mut UdpSocket = self.sockets.get_mut(handle);
        unsafe { std::mem::transmute(socket) }
    }

    fn preprocess_packet(&mut self, packet: &T::Packet) {
        let (dst_addr, src_addr, payload, protocol) =
            match IpVersion::of_packet(packet.as_ref()).unwrap() {
                IpVersion::Ipv4 => {
                    let packet = Ipv4Packet::new_checked(packet.as_ref()).unwrap();
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
                    let packet = Ipv6Packet::new_checked(packet.as_ref()).unwrap();
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
        if !self.allowed(dst_endpoint) {
            log::info!("ignore packet to {}", dst_endpoint);
            return;
        }

        log::info!("got packet from {} to {}", src_endpoint, dst_endpoint);
        match connect {
            Some(true) => {
                self.ensure_tcp_socket(dst_endpoint, src_endpoint);
            }
            None => {
                self.ensure_udp_socket(src_endpoint, dst_endpoint);
            }
            _ => {}
        }
    }
}

pub struct TxToken<'a, T: Tun> {
    tun: T,
    traffic: &'a mut Traffic,
}

pub struct RxToken<T: Tun> {
    packet: T::Packet,
}

impl<T: Tun> smoltcp::phy::RxToken for RxToken<T> {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.packet.as_mut())
    }
}

impl<'a, T: Tun> smoltcp::phy::TxToken for TxToken<'a, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.traffic.tx_bytes += len;
        self.tun
            .allocate_packet(len)
            .map(|mut packet| {
                let r = f(packet.as_mut());
                self.tun.send(packet).unwrap();
                r
            })
            .unwrap()
    }
}

impl<'b, T: Tun + Clone> Device for TunDevice<'b, T> {
    type RxToken<'a> = RxToken<T> where Self: 'a;
    type TxToken<'a> = TxToken<'a, T> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.tun.receive().unwrap().map(|packet| {
            self.traffic.rx_bytes += packet.len();
            self.preprocess_packet(&packet);
            let rx = RxToken { packet };
            let tx = TxToken {
                tun: self.tun.clone(),
                traffic: &mut self.traffic,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            tun: self.tun.clone(),
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
