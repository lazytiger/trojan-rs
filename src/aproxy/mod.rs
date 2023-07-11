use std::{net::SocketAddr, sync::Arc};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio::{
    net::{TcpListener, UdpSocket},
    runtime::Runtime,
    sync::mpsc::unbounded_channel,
};

use crate::{
    aproxy::{
        profiler::{run_profiler, start_check_server},
        tcp::run_tcp,
        udp::run_udp,
    },
    config::OPTIONS,
    proxy::new_socket,
    types::Result,
};

mod profiler;
mod tcp;
mod udp;

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
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
    start_check_server(
        OPTIONS.proxy_args().hostname.clone(),
        150,
        OPTIONS.proxy_args().bypass_timeout,
    );

    let (sender, receiver) = if OPTIONS.proxy_args().enable_bypass {
        let (sender, receiver) = unbounded_channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };

    if sender.is_none() {
        tokio::select! {
            ret = run_tcp(tcp_listener, server_name.clone(), config.clone(), sender.clone()) => {
                log::error!("tcp routine exit with:{:?}", ret);
            },
            ret = run_udp(udp_listener, server_name.clone(), config.clone(), sender.clone()) => {
                log::error!("udp routine exit with:{:?}", ret);
            }
        }
    } else {
        tokio::select! {
            ret = run_tcp(tcp_listener, server_name.clone(), config.clone(), sender.clone()) => {
                log::error!("tcp routine exit with:{:?}", ret);
            },
            ret = run_udp(udp_listener, server_name.clone(), config.clone(), sender.clone()) => {
                log::error!("udp routine exit with:{:?}", ret);
            }
            ret = run_profiler(receiver, sender, server_name.clone(), config) => {
                log::error!("profiler routine exit with:{:?}", ret);
            }
        }
    }
    Ok(())
}
