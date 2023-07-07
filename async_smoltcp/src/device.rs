use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use bytes::{BufMut, BytesMut};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium},
    socket::{
        tcp::{RecvError, Socket as TcpSocket, SocketBuffer, State},
        udp::{PacketBuffer, PacketMetadata, SendError, Socket as UdpSocket},
        Socket,
    },
    time::Instant,
    wire::{
        IpAddress, IpEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
    },
};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use crate::{tcp::TcpStream, Packet, Tun};

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
    udp_set: HashSet<IpEndpoint>,
    sockets: SocketSet<'a>,
    tcp_ip2handle: HashMap<IpEndpoint, (SocketHandle, IpEndpoint)>,
    new_tcp: Vec<IpEndpoint>,
    new_udp: Vec<SocketHandle>,
    white_ip_list: HashSet<IpAddress>,
    allow_private: bool,
    /// (source address, data)
    tcp_receiver: Receiver<(SocketAddr, Vec<u8>)>,
    tcp_sender: Sender<(SocketAddr, Vec<u8>)>,
    /// (source address, sender)
    tcp_req_senders: HashMap<IpEndpoint, Sender<Vec<u8>>>,

    /// (source address, target address, data)
    udp_receiver: Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    udp_sender: Sender<(SocketAddr, SocketAddr, Vec<u8>)>,
    /// (source address, sender)
    udp_req_senders: HashMap<IpEndpoint, Sender<(SocketAddr, Vec<u8>)>>,
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

impl<'a, T: Tun> TunDevice<'a, T> {
    pub fn add_white_ip(&mut self, addr: IpAddress) {
        self.white_ip_list.insert(addr);
    }

    pub fn allowed(&self, endpoint: IpEndpoint) -> bool {
        if endpoint.port == 0 {
            false
        } else if self.white_ip_list.contains(&endpoint.addr) {
            true
        } else if !self.allow_private && is_private_v4(endpoint.addr) {
            false
        } else {
            true
        }
    }

    pub fn ensure_tcp_socket(&mut self, dst_endpoint: IpEndpoint, src_endpoint: IpEndpoint) {
        if self.tcp_ip2handle.contains_key(&src_endpoint) {
            return;
        }
        let socket = TcpSocket::new(
            SocketBuffer::new(vec![0; 102400]),
            SocketBuffer::new(vec![0; 102400]),
        );
        let handle = self.sockets.add(socket);
        let socket = self.sockets.get_mut::<TcpSocket>(handle);
        socket.listen(dst_endpoint).unwrap();
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        self.tcp_ip2handle
            .insert(src_endpoint, (handle, dst_endpoint));
        self.new_tcp.push(src_endpoint);
    }

    pub fn ensure_udp_socket(&mut self, endpoint: IpEndpoint) {
        if self.udp_set.contains(&endpoint) {
            return;
        }
        let mut socket = UdpSocket::new(
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 200], vec![0; 10240]),
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 10000], vec![0; 1024000]),
        );
        socket.bind(endpoint).unwrap();
        let handle = self.sockets.add(socket);
        self.udp_set.insert(endpoint);
        self.new_udp.push(handle);
    }

    pub fn accept_tcp(&mut self) -> Vec<TcpStream> {
        let mut streams = Vec::new();
        for source in std::mem::take(&mut self.new_tcp) {
            let (sender, receiver) = channel(1024);
            let stream = TcpStream::new(
                receiver,
                self.tcp_sender.clone(),
                source.into(),
                self.tcp_ip2handle.get(&source).unwrap().1,
            );
        }
    }

    pub fn accept_udp(&mut self) -> Vec<crate::udp::UdpSocket> {
        let mut sockets = Vec::new();
        sockets
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

impl<'b, T: Tun> Device for TunDevice<'b, T> {
    type RxToken<'a> = RxToken<T> where Self: 'a;
    type TxToken<'a> = TxToken<'a, T> where Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.tun.receive().unwrap().map(|packet| {
            self.traffic.rx_bytes += packet.len();
            preprocess_packet(&packet, self);
            let rx = RxToken { packet };
            let tx = TxToken {
                tun: self.tun.clone(),
                traffic: &mut self.traffic,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
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

fn preprocess_packet<T: Tun>(packet: &T::Packet, device: &mut TunDevice<T>) {
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
    if !device.allowed(dst_endpoint) {
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
