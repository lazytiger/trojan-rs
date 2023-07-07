use std::{
    io::{Read, Write},
    net::SocketAddr,
};

use smoltcp::wire::IpEndpoint;

mod device;
mod tcp;
mod udp;

pub trait Tun: Clone {
    type Packet: Packet;

    /// Receive data from tun device, if nothing to read WouldBlock will be return.
    fn receive(&self) -> std::io::Result<Option<Self::Packet>>;

    /// Send data to tun device
    fn send(&self, packet: Self::Packet) -> std::io::Result<()>;

    /// Allocate a packet which can hold len bytes data.
    fn allocate_packet(&self, len: usize) -> std::io::Result<Self::Packet>;
}

pub trait Packet {
    fn as_mut(&mut self) -> &mut [u8];
    fn as_ref(&self) -> &[u8];
    fn len(&self) -> usize;
}

trait SocketAddrConverter {
    fn to_std(self) -> SocketAddr;
}

impl SocketAddrConverter for IpEndpoint {
    fn to_std(self) -> SocketAddr {
        match self {}
    }
}
