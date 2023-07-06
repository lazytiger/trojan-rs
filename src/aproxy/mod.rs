use std::{net::SocketAddr, sync::Arc};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
};

use crate::{
    aproxy::{tcp::run_tcp, udp::run_udp},
    config::OPTIONS,
    sys,
    types::Result,
};

mod tcp;
mod udp;

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

pub fn new_socket(addr: SocketAddr, is_udp: bool) -> Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let (typ, protocol) = if is_udp {
        (Type::DGRAM, Protocol::UDP)
    } else {
        (Type::STREAM, Protocol::TCP)
    };
    let socket = Socket::new(domain, typ, Some(protocol))?;
    sys::set_socket_opts(addr.is_ipv4(), is_udp, &socket)?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&SockAddr::from(addr))?;
    if !is_udp {
        socket.listen(1024)?;
    }
    Ok(socket)
}

fn prepare_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

async fn async_run() -> Result<()> {
    let addr: SocketAddr = OPTIONS.local_addr.parse()?;
    let tcp_listener = TcpListener::from_std(new_socket(addr, false)?.into())?;
    let udp_listener = UdpSocket::from_std(new_socket(addr, true)?.into())?;
    let server_name: ServerName = OPTIONS.proxy_args().hostname.as_str().try_into()?;
    let config = prepare_tls_config();
    tokio::select! {
        ret = run_tcp(tcp_listener, server_name.clone(), config.clone()) => {
            log::error!("tcp routine exit with:{:?}", ret);
        },
        ret = run_udp(udp_listener, server_name, config) => {
            log::error!("udp routine exit with:{:?}", ret);
        }
    }
    Ok(())
}
