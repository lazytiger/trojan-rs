use std::{ptr, sync::Arc};

use smoltcp::{
    iface::Interface,
    phy::{Device, DeviceCapabilities, Medium},
    socket::{Socket, TcpSocket, TcpSocketBuffer, UdpPacketMetadata, UdpSocket, UdpSocketBuffer},
    time::Instant,
    wire::{
        IpAddress, IpEndpoint, IpProtocol, IpVersion, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket,
    },
};
use wintun::{Packet, Session};

use crate::{
    wintun::{ipset::is_private, waker::Wakers},
    OPTIONS,
};

pub struct WintunInterface {
    session: Arc<Session>,
    interface: *mut Interface<'static, WintunInterface>,
    tcp_wakers: *mut Wakers,
    udp_wakers: *mut Wakers,
    mtu: usize,
}

impl WintunInterface {
    pub fn new(session: Arc<Session>, mtu: usize) -> Self {
        Self {
            session,
            mtu,
            interface: ptr::null_mut(),
            tcp_wakers: ptr::null_mut(),
            udp_wakers: ptr::null_mut(),
        }
    }

    pub fn init(
        &mut self,
        interface: *mut Interface<WintunInterface>,
        tcp_wakers: &mut Wakers,
        udp_wakers: &mut Wakers,
    ) {
        unsafe {
            self.interface = std::mem::transmute(interface);
            self.tcp_wakers = tcp_wakers as *mut Wakers;
            self.udp_wakers = udp_wakers as *mut Wakers;
        }
    }
}

impl<'d> Device<'d> for WintunInterface {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn receive(&'d mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.session
            .try_receive()
            .ok()
            .map(|packet| {
                packet.map(|packet| {
                    unsafe {
                        let interface = &mut *self.interface;
                        let tcp_wakers = &mut *self.tcp_wakers;
                        let udp_wakers = &mut *self.udp_wakers;
                        preprocess_packet(&packet, interface, tcp_wakers, udp_wakers);
                    }
                    let rx = RxToken { packet };
                    let tx = TxToken {
                        session: self.session.clone(),
                    };
                    (rx, tx)
                })
            })
            .unwrap_or(None)
    }

    fn transmit(&'d mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            session: self.session.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut dc = DeviceCapabilities::default();
        dc.medium = Medium::Ip;
        dc.max_transmission_unit = self.mtu;
        dc
    }
}

fn preprocess_packet(
    packet: &Packet,
    sockets: &mut Interface<WintunInterface>,
    tcp_wakers: &mut Wakers,
    udp_wakers: &mut Wakers,
) {
    let (src_addr, dst_addr, payload, protocol) =
        match IpVersion::of_packet(packet.bytes()).unwrap() {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_checked(packet.bytes()).unwrap();
                let src_addr = packet.src_addr();
                let dst_addr = packet.dst_addr();
                (
                    IpAddress::Ipv4(src_addr),
                    IpAddress::Ipv4(dst_addr),
                    packet.payload(),
                    packet.protocol(),
                )
            }
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_checked(packet.bytes()).unwrap();
                let src_addr = packet.src_addr();
                let dst_addr = packet.dst_addr();
                (
                    IpAddress::Ipv6(src_addr),
                    IpAddress::Ipv6(dst_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
            _ => return,
        };
    let (src_port, dst_port, connect) = match protocol {
        IpProtocol::Udp => {
            let packet = UdpPacket::new_checked(payload).unwrap();
            (packet.src_port(), packet.dst_port(), None)
        }
        IpProtocol::Tcp => {
            let packet = TcpPacket::new_checked(payload).unwrap();
            (
                packet.src_port(),
                packet.dst_port(),
                Some(packet.syn() && !packet.ack()),
            )
        }
        _ => return,
    };

    let src_endpoint = IpEndpoint::new(src_addr, src_port);
    let dst_endpoint = IpEndpoint::new(dst_addr, dst_port);
    if is_private(dst_endpoint) {
        return;
    }

    match connect {
        Some(true) => {
            let socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0; OPTIONS.wintun_args().tcp_rx_buffer_size]),
                TcpSocketBuffer::new(vec![0; OPTIONS.wintun_args().tcp_tx_buffer_size]),
            );
            let handle = sockets.add_socket(socket);
            let socket = sockets.get_socket::<TcpSocket>(handle);
            let (_, tx) = tcp_wakers.get_wakers(handle);
            socket.register_send_waker(tx);
            socket.listen(dst_endpoint).unwrap();
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(None);
            //timeout could cause performance problem
            //socket.set_timeout(Some(Duration::from_secs(120)));
            //socket.set_keep_alive(Some(Duration::from_secs(60)));

            log::info!(
                "tcp handle:{} is {} -> {}",
                handle,
                src_endpoint,
                dst_endpoint
            );
        }
        None if !sockets
            .sockets()
            .filter_map(|(_, socket)| {
                if let Socket::Udp(socket) = socket {
                    Some(socket)
                } else {
                    None
                }
            })
            .any(|socket| socket.endpoint() == dst_endpoint) =>
        {
            let mut socket = UdpSocket::new(
                UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; OPTIONS.wintun_args().udp_rx_meta_size],
                    vec![0; OPTIONS.wintun_args().udp_rx_buffer_size],
                ),
                UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; OPTIONS.wintun_args().udp_rx_meta_size],
                    vec![0; OPTIONS.wintun_args().udp_tx_buffer_size],
                ),
            );
            socket.bind(dst_endpoint).unwrap();
            let handle = sockets.add_socket(socket);
            log::info!("udp handle:{} is {}", handle, dst_endpoint);
            let socket = sockets.get_socket::<UdpSocket>(handle);
            let (rx, tx) = udp_wakers.get_wakers(handle);
            socket.register_recv_waker(rx);
            socket.register_send_waker(tx);
        }
        _ => {}
    }
}

pub struct TxToken {
    session: Arc<Session>,
}

pub struct RxToken {
    packet: Packet,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(self.packet.bytes_mut())
    }
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        self.session
            .allocate_send_packet(len as u16)
            .map(|mut packet| {
                let r = f(packet.bytes_mut());
                self.session.send_packet(packet);
                r
            })
            .unwrap_or_else(|_| Err(smoltcp::Error::Exhausted))
    }
}
