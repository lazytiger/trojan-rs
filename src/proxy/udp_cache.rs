use std::{collections::HashMap, net::SocketAddr, rc::Rc};

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

    pub fn get_socket(&mut self, addr: SocketAddr) -> Option<Rc<UdpSocket>> {
        if let Some(socket) = self.conns.get(&addr) {
            Some(socket.clone())
        } else {
            log::debug!("socket:{} not found, create a new one", addr);
            match new_socket(addr, true) {
                Ok(socket) => {
                    let socket = UdpSocket::from_std(socket.into());
                    let socket = Rc::new(socket);
                    self.conns.insert(addr, socket.clone());
                    Some(socket)
                }
                Err(err) => {
                    log::error!("new socket:{} failed:{:?}", addr, err);
                    None
                }
            }
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
