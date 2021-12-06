use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    Packet,
};
use smoltcp::wire::Ipv4Address;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn get_ipv4(ip: IpAddr) -> Ipv4Addr {
    if let IpAddr::V4(ip) = ip {
        ip
    } else {
        panic!("invalid ip type, v4 required")
    }
}

pub fn get_ipv6(ip: IpAddr) -> Ipv6Addr {
    if let IpAddr::V6(ip) = ip {
        ip
    } else {
        panic!("invalid ip type, v6 required")
    }
}

pub fn is_private(ip: Ipv4Address) -> bool {
    ip.is_broadcast() //255.255.255.255/32
        || ip.is_loopback() //127.0.0.0/8
        || ip.is_link_local() //169.254.0.0/16
        || ip.is_unspecified() //0.0.0.0/8
        || ip.is_multicast() //224.0.0.0/4
}
