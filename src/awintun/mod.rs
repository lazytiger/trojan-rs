use std::{
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use async_smoltcp::{Tun, TunDevice};
use bytes::BytesMut;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::{net::TcpStream, runtime::Runtime, spawn, sync::mpsc::channel};
use tokio_rustls::{client::TlsStream, TlsConnector};
use types::Result;

#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(windows)]
use wintool::adapter::get_main_adapter_gwif;
#[cfg(windows)]
use wintun::Adapter;

use crate::{
    awintun::{
        tcp::start_tcp,
        udp::{run_udp_dispatch, start_udp},
    },
    config::OPTIONS,
    proto::{TrojanRequest, UDP_ASSOCIATE},
    types,
};

#[cfg(target_os = "macos")]
use crate::osxtun::{
    route::{build_cleanup_commands, default_gateway, run_commands, RouteConfig, RouteGuard},
    tun::OsxTun,
};
#[cfg(windows)]
use crate::{
    awintun::tun::Wintun,
    types::TrojanError,
    wintun::{apply_ipset, route_add_with_if},
};

mod tcp;
#[cfg(windows)]
mod tun;
mod udp;

pub async fn init_tls_conn(
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> types::Result<TlsStream<TcpStream>> {
    let stream = tokio::net::TcpStream::connect((
        OPTIONS.wintun_args().hostname.as_str(),
        OPTIONS.wintun_args().port,
    ))
    .await?;
    let conn = connector.connect(server_name, stream).await?;
    Ok(conn)
}

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

#[cfg(windows)]
async fn async_run() -> Result<()> {
    log::info!("dll:{}", OPTIONS.wintun_args().wintun);
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = Adapter::create(&wintun, "trojan", OPTIONS.wintun_args().name.as_str(), None)?;
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    let (main_gw, main_index) = if let Some((main_gw, main_index)) = get_main_adapter_gwif() {
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
        (gw, main_index)
    } else {
        log::error!("main adapter gateway not found");
        return Err(TrojanError::MainAdapterNotFound);
    };
    let index = adapter.get_adapter_index()?;
    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        apply_ipset(file, index, main_gw, main_index)?;
    }

    let server_addr = *OPTIONS.back_addr.as_ref().unwrap();
    let mtu = OPTIONS.wintun_args().mtu;
    let mut device = TunDevice::new(Wintun::new(mtu, session));
    device.add_black_ip(server_addr.ip());
    run_device(device).await
}

#[cfg(target_os = "macos")]
async fn async_run() -> Result<()> {
    let server_addr = *OPTIONS.back_addr.as_ref().unwrap();
    let server_ip = match server_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => {
            return Err(types::TrojanError::Custom(
                "osxtun only supports IPv4 server route now".to_string(),
            ))
        }
    };
    let mtu = OPTIONS.wintun_args().mtu;
    let tun = OsxTun::create(mtu)?;
    let interface = tun.interface_name().to_string();
    let route_config = RouteConfig {
        interface: interface.clone(),
        gateway: default_gateway()?,
        server_ip,
        tun_addr: "10.255.0.2".parse()?,
        tun_peer: "10.255.0.1".parse()?,
        mtu,
    };
    let _ = run_commands(&build_cleanup_commands(&route_config));
    let _route_guard = RouteGuard::apply(route_config)?;
    log::warn!(
        "osxtun started on {} with server:{}",
        interface,
        server_addr
    );
    let mut device = TunDevice::new(tun);
    device.add_black_ip(server_addr.ip());
    device.allow_private(true);
    run_device(device).await
}

async fn run_device<T>(mut device: TunDevice<'_, T>) -> Result<()>
where
    T: Tun + Clone,
{
    let server_name: ServerName = OPTIONS.wintun_args().hostname.as_str().try_into()?;

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, &empty);
    let udp_header = Arc::new(header);

    let (data_sender, data_receiver) = channel(128);
    let (socket_sender, socket_receiver) = channel(128);
    let (close_sender, close_receiver) = channel(128);
    let connector = TlsConnector::from(config);
    spawn(run_udp_dispatch(
        data_receiver,
        socket_receiver,
        server_name.clone(),
        connector.clone(),
        OPTIONS.wintun_args().mtu,
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
            spawn(start_tcp(stream, connector.clone(), server_name.clone()));
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
