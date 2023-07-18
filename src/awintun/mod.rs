use std::{
    fs::OpenOptions,
    io::Write,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rustls::{ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName};
use tokio::{runtime::Runtime, spawn, sync::mpsc::channel};
use wintun::Adapter;

use async_smoltcp::TunDevice;
use tokio_rustls::TlsClientStream;
use types::Result;
use wintool::adapter::get_main_adapter_gwif;

use crate::{
    awintun::{
        tcp::start_tcp,
        tun::Wintun,
        udp::{run_udp_dispatch, start_udp},
    },
    config::OPTIONS,
    proto::{TrojanRequest, UDP_ASSOCIATE},
    types,
    types::TrojanError,
    wintun::{apply_ipset, route_add_with_if},
};

mod tcp;
mod tun;
mod udp;

pub async fn init_tls_conn(
    config: Arc<ClientConfig>,
    server_addr: SocketAddr,
    server_name: ServerName,
) -> types::Result<TlsClientStream> {
    let stream = tokio::net::TcpStream::connect(server_addr).await?;
    let session = ClientConnection::new(config, server_name)?;
    Ok(TlsClientStream::new(stream, session))
}

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

async fn async_run() -> Result<()> {
    log::info!("dll:{}", OPTIONS.wintun_args().wintun);
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = Adapter::create(&wintun, "trojan", OPTIONS.wintun_args().name.as_str(), None)?;
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    if let Some((main_gw, main_index)) = get_main_adapter_gwif() {
        log::warn!(
            "main adapter gateway is {}, main adapter index is :{}",
            main_gw,
            main_index
        );
        let gw: Ipv4Addr = main_gw.parse()?;
        if let Some(SocketAddr::V4(v4)) = &OPTIONS.back_addr {
            let index: u32 = (*v4.ip()).into();
            route_add_with_if(index, !0, gw.into(), main_index)?;
        }
    } else {
        log::error!("main adapter gateway not found");
        return Err(TrojanError::MainAdapterNotFound);
    }
    let index = adapter.get_adapter_index()?;
    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        apply_ipset(file, index, OPTIONS.wintun_args().inverse_route)?;
    }

    let server_name: ServerName = OPTIONS.wintun_args().hostname.as_str().try_into()?;

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let server_addr = *OPTIONS.back_addr.as_ref().unwrap();
    let mtu = OPTIONS.wintun_args().mtu;
    let mut device = TunDevice::new(mtu, Wintun::new(session));
    device.add_black_ip(server_addr.ip());

    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, &empty);
    let udp_header = Arc::new(header);

    let (data_sender, data_receiver) = channel(128);
    let (socket_sender, socket_receiver) = channel(128);
    let (close_sender, close_receiver) = channel(128);
    spawn(run_udp_dispatch(
        data_receiver,
        socket_receiver,
        server_addr,
        server_name.clone(),
        config.clone(),
        mtu,
        udp_header.clone(),
        close_receiver,
        close_sender.clone(),
    ));
    let mut last_speed_time = Instant::now();

    loop {
        let (tcp_streams, udp_sockets) = device.poll();
        for stream in tcp_streams {
            log::info!(
                "accept tcp {} - {}",
                stream.local_addr(),
                stream.peer_addr()
            );
            spawn(start_tcp(
                stream,
                config.clone(),
                server_addr,
                server_name.clone(),
            ));
        }
        for socket in udp_sockets {
            log::info!("accept udp to:{}", socket.peer_addr());
            let writer = Arc::new(socket.writer());
            let _ = socket_sender.send(writer).await;
            spawn(start_udp(socket, data_sender.clone(), close_sender.clone()));
        }
        if last_speed_time.elapsed().as_millis() > 1000 {
            let (rx_speed, tx_speed) = device.calculate_speed();
            log::info!(
                "current speed - rx:{:.4}KB/s, tx:{:.4}/KB/s",
                rx_speed,
                tx_speed
            );
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(OPTIONS.wintun_args().status_file.as_str())?;
            write!(&mut file, "{:.4} {:.4}", rx_speed, tx_speed)?;
            last_speed_time = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
