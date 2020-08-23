use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;

use mio::net::UdpSocket;

use crate::proxy::new_socket;

pub struct UdpSvrCache {
    conns: HashMap<SocketAddr, Rc<UdpSocket>>,
}

impl UdpSvrCache {
    pub fn new() -> UdpSvrCache {
        UdpSvrCache {
            conns: HashMap::new(),
        }
    }

    pub fn get_socket(&mut self, addr: SocketAddr) -> Rc<UdpSocket> {
        if let Some(socket) = self.conns.get(&addr) {
            socket.clone()
        } else {
            log::info!("socket:{} not found, create a new one", addr);
            let socket = new_socket(addr, true);
            let socket = UdpSocket::from_socket(socket.into_udp_socket()).unwrap();
            let socket = Rc::new(socket);
            self.conns.insert(
                addr,
                socket.clone(),
            );
            socket
        }
    }

    pub fn check_timeout(&mut self) {
        let mut list = Vec::new();
        for (addr, socket) in &self.conns {
            if Rc::strong_count(socket) == 1 {
                list.push(*addr);
            }
        }

        for addr in list {
            self.conns.remove(&addr);
        }
    }
}
