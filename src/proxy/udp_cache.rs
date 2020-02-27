use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use mio::net::UdpSocket;

use crate::proxy::new_socket;

pub struct UdpSvrCache {
    conns: HashMap<SocketAddr, CacheEntry>,
}

struct CacheEntry {
    socket: UdpSocket,
    last_active_time: Instant,
}

impl UdpSvrCache {
    pub fn new() -> UdpSvrCache {
        UdpSvrCache {
            conns: HashMap::new(),
        }
    }

    pub fn send_to(&mut self, src_addr: SocketAddr, dst_addr: SocketAddr, payload: &[u8]) {
        let last_active_time = Instant::now();
        if !self.conns.contains_key(&dst_addr) {
            log::info!("socket:{} not found, create a new one", dst_addr);
            let socket = new_socket(dst_addr, true);
            let socket = UdpSocket::from_socket(socket.into_udp_socket()).unwrap();
            self.conns.insert(dst_addr, CacheEntry { socket, last_active_time });
        }

        log::info!("socket is ready, sending {} bytes from {} to {}", payload.len(), dst_addr, src_addr);
        let entry = self.conns.get_mut(&dst_addr).unwrap();
        entry.last_active_time = last_active_time;
        if let Err(err) = entry.socket.send_to(payload, &src_addr) {
            log::error!("send udp data from {} to {} failed {}", dst_addr, src_addr, err);
            return;
        }
    }

    pub fn check_timeout(&mut self, recent_active_time: Instant) {
        let mut list = Vec::new();
        for (addr, entry) in &mut self.conns {
            if entry.last_active_time < recent_active_time {
                list.push(*addr);
            }
        }

        for addr in list {
            self.conns.remove(&addr);
        }
    }
}