use std::{
    fs::File,
    io::{ErrorKind, Read, Write},
    mem::ManuallyDrop,
    net::SocketAddr,
    ops::Deref,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::BytesMut;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use sha2::{Digest, Sha224};
use tokio::{net::TcpStream, runtime::Builder, spawn, sync::mpsc::channel};
use tokio_rustls::{client::TlsStream, TlsConnector};
use trust_dns_proto::serialize::binary::BinDecodable;

use async_smoltcp::{Packet as _, TunDevice};

use crate::{platform, types, types::Error, LOOPER};

mod dns;
mod proto;
mod tcp;
mod udp;

pub struct Session {
    mtu: usize,
    file: ManuallyDrop<File>,
}

impl Session {
    pub fn new(fd: i32) -> types::Result<Self> {
        let mtu = LOOPER
            .read()
            .map_err(|err| Error::Lock(err.to_string()))?
            .config
            .mtu;
        Ok(Self {
            mtu,
            file: ManuallyDrop::new(File::from_raw_fd(fd)),
        })
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }
}

pub struct Packet {
    data: Vec<u8>,
}

impl Packet {
    pub fn new(mtu: usize) -> Self {
        Self {
            data: vec![0u8; mtu],
        }
    }

    pub fn set_len(&mut self, n: usize) {
        unsafe {
            self.data.set_len(n);
        }
    }
}

impl async_smoltcp::Packet for Packet {
    fn as_mut(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }

    fn as_ref(&self) -> &[u8] {
        self.data.as_slice()
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

impl async_smoltcp::Tun for Session {
    type Packet = Packet;

    fn receive(&self) -> std::io::Result<Option<Self::Packet>> {
        let mut file = self.file.deref();
        let mut packet = Packet::new(self.mtu);
        match file.read(packet.as_mut()) {
            Ok(0) => Err(ErrorKind::BrokenPipe.into()),
            Ok(n) => {
                packet.set_len(n);
                Ok(Some(packet))
            }
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::Interrupted =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn send(&self, packet: Self::Packet) -> std::io::Result<()> {
        let mut file = self.file.deref();
        file.write_all(packet.as_ref())
    }

    fn allocate_packet(&self, len: usize) -> std::io::Result<Self::Packet> {
        Ok(Packet::new(len))
    }
}

pub async fn init_tls_conn(
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> types::Result<TlsStream<TcpStream>> {
    let looper = LOOPER.read().map_err(|err| Error::Lock(err.to_string()))?;
    let domain = looper.config.domain.clone();
    let port = looper.config.port;
    let stream = tokio::net::TcpStream::connect((domain, port)).await?;
    let conn = connector.connect(server_name, stream).await?;
    Ok(conn)
}

fn digest_pass(pass: &String) -> String {
    let mut encoder = Sha224::new();
    encoder.update(pass.as_bytes());
    let result = encoder.finalize();
    hex::encode(result.as_slice())
}

pub async fn async_run(fd: i32, running: Arc<AtomicBool>) -> types::Result<()> {
    log::error!("vpn process start running");
    let config = LOOPER
        .read()
        .map_err(|err| types::Error::Lock(err.to_string()))?
        .config
        .clone();
    let session = Arc::new(Session::new(fd));

    let pass = digest_pass(&config.password);

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

    let mut device = TunDevice::new(session);

    let trusted_addr = (config.trust_dns.clone() + ":53").parse()?;
    let distrusted_addr = (config.distrust_dns.clone() + ":53").parse()?;

    let empty: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut header = BytesMut::new();
    TrojanRequest::generate(&mut header, UDP_ASSOCIATE, pass.as_bytes(), &empty);
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
        udp_header.clone(),
        close_receiver,
        close_sender.clone(),
    ));

    let mut last_speed_time = Instant::now();
    while running.load(Ordering::Relaxed) {
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
                pass.clone(),
            ));
        }
        for socket in udp_sockets {
            log::info!("accept udp to:{}", socket.peer_addr());
            if socket.peer_addr_std() == dns_addr {
                spawn(start_dns(
                    socket,
                    config.clone(),
                    server_addr,
                    server_name.clone(),
                    udp_header.clone(),
                    trusted_addr,
                    distrusted_addr,
                    context.blocked_domains.clone(),
                ));
            } else {
                log::info!("accept udp to:{}", socket.peer_addr());
                let writer = Arc::new(socket.writer());
                let _ = socket_sender.send(writer).await;
                spawn(start_udp(socket, data_sender.clone(), close_sender.clone()));
            }
        }

        if last_speed_time.elapsed().as_millis() >= context.options.speed_update_ms {
            let (rx_speed, tx_speed) = device.calculate_speed();
            let (rx_speed, rx_unit) = get_speed_and_unit(rx_speed);
            let (tx_speed, tx_unit) = get_speed_and_unit(tx_speed);
            emit_event(
                EventType::UpdateSpeed,
                format!(
                    "上行速度:{:.1}{}/s, 下行速度:{:.1}{}/s",
                    rx_speed, rx_unit, tx_speed, tx_unit
                ),
            )?;
            last_speed_time = std::time::Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Ok(())
}

fn get_speed_and_unit(speed: f64) -> (f64, &'static str) {
    if speed >= 1024.0 {
        (speed / 1024.0, "MB")
    } else {
        (speed, "KB")
    }
}

pub fn run(fd: i32, running: Arc<AtomicBool>) -> types::Result<()> {
    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async_run(fd, running))
}
