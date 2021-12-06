use pnet::packet::tcp::TcpPacket;
use std::net::SocketAddr;

pub struct TcpRequest {
    pub source: SocketAddr,
    pub target: SocketAddr,
    pub packet: TcpPacket<'static>,
}
