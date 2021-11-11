use std::collections::HashMap;
use std::net::SocketAddr;

use async_std::net::UdpSocket;
use async_std::task;

use crate::aproxy::remote::RemoteClient;
use crate::config::OPTIONS;
use crate::proto::MAX_PACKET_SIZE;
use crate::proxy::new_socket;
use crate::sys;

mod remote;

pub async fn run() {
    let addr: SocketAddr = OPTIONS.local_addr.parse().unwrap();
    let socket: std::net::UdpSocket = new_socket(addr, true).unwrap().into();
    let socket: UdpSocket = socket.into();
    let mut buffer: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
    let (sender, receiver) = async_std::channel::bounded(OPTIONS.max_channel_buffer);
    let mut clients = HashMap::new();
    loop {
        let size = socket.peek(&mut buffer[..1]).await;
        if let Err(err) = size {
            log::error!("read from udp listener failed:{}", err);
            break;
        }
        let result = sys::recv_from_with_destination(&socket, &mut buffer[..]);
        if let Err(err) = result {
            log::error!("read from udp listener failed:{}", err);
            break;
        }
        let (size, src_addr, dst_addr) = result.unwrap();
        if size == MAX_PACKET_SIZE {
            log::warn!(
                "received packet size:{} exceeds limit:{}",
                size,
                MAX_PACKET_SIZE
            );
        }
        let client = if let Some(client) = clients.get(&src_addr) {
            client
        } else {
            let client = RemoteClient::new(src_addr, sender.clone());
            //task::spawn(client.start())
            clients.insert(src_addr, client);
            clients.get(&src_addr).unwrap()
        };
        if !client.send_data((size, buffer, dst_addr)) {}
    }
}
