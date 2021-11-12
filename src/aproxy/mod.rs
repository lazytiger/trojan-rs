use async_std::channel::bounded;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::aproxy::udp::start_proxy;
use async_std::net::UdpSocket;
use async_std::task;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore};

use crate::config::OPTIONS;
use crate::proto::MAX_PACKET_SIZE;
use crate::proxy::new_socket;
use crate::sys;

mod udp;

pub async fn run_udp() {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = ClientConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);

    let addr: SocketAddr = OPTIONS.local_addr.parse().unwrap();
    let socket: std::net::UdpSocket = new_socket(addr, true).unwrap().into();
    let socket: UdpSocket = socket.into();
    let mut buffer: [u8; MAX_PACKET_SIZE] = [0; MAX_PACKET_SIZE];
    let mut clients = HashMap::new();
    let (response_sender, response_receiver) =
        async_std::channel::bounded(OPTIONS.max_channel_buffer);

    task::spawn(start_proxy(response_receiver));
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

        let sender = if let Some(sender) = clients.get(&src_addr) {
            sender
        } else {
            let (sender, receiver) = bounded(OPTIONS.max_channel_buffer);
            let hostname = OPTIONS.proxy_args().hostname.as_str().try_into().unwrap();
            let client = ClientConnection::new(config.clone(), hostname);
            if let Err(err) = client {
                log::error!("new client connection with tls failed:{}", err);
                continue;
            }
            task::spawn(udp::start(
                src_addr,
                receiver,
                response_sender.clone(),
                client.unwrap(),
            ));
            clients.insert(src_addr, sender.clone());
            clients.get(&src_addr).unwrap()
        };
        if let Err(err) = sender.try_send((size, buffer, dst_addr)) {
            if err.is_closed() {
                clients.remove(&src_addr);
            }
            log::warn!(
                "send data from:{} to:{} err:{}",
                src_addr,
                dst_addr,
                err.to_string()
            );
        }
    }
}
