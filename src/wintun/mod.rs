use std::{
    convert::TryInto,
    net::{Ipv4Addr, SocketAddr},
    process::Command,
    sync::Arc,
};

use crossbeam::channel::Sender;
use mio::{Events, Poll, Token, Waker};

use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
use wintun::{Adapter, Session};

use crate::{
    proxy::IdlePool,
    resolver::DnsResolver,
    types::Result,
    wintun::{
        ip::is_private,
        tcp::TcpRequest,
        udp::{UdpRequest, UdpServer},
    },
    OPTIONS,
};

mod ip;
mod tcp;
mod udp;

/// Token used for dns resolver
const RESOLVER: usize = 1;
const MIN_INDEX: usize = 2;
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
const CHANNEL_CNT: usize = 3;
/// channel index  for `IdlePool`
const CHANNEL_IDLE: usize = 0;
/// channel index for client `UdpConnection`
const CHANNEL_UDP: usize = 1;
/// channel index for remote tcp connection
const CHANNEL_TCP: usize = 2;

pub fn run() -> Result<()> {
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = match Adapter::open(&wintun, OPTIONS.wintun_args().name.as_str()) {
        Ok(a) => a,
        Err(_) => Adapter::create(
            &wintun,
            "trojan",
            OPTIONS.wintun_args().name.as_str(),
            OPTIONS.wintun_args().guid,
        )?,
    };

    if OPTIONS.wintun_args().delete {
        if let Ok(adapter) = Arc::try_unwrap(adapter) {
            adapter.delete()?;
        }
        return Ok(());
    }

    let index = adapter.get_adapter_index(OPTIONS.wintun_args().guid)?;

    if let Err(err) = Command::new("route")
        .args([
            "add",
            "8.8.8.8",
            "mask",
            "255.255.255.255",
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            index.to_string().as_str(),
        ])
        .output()
    {
        log::error!("route add 8.8.8.8 failed:{}", err);
    }

    let hostname = OPTIONS.wintun_args().hostname.as_str().try_into()?;

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

    let poll = Poll::new()?;
    let resolver = DnsResolver::new(&poll, Token(RESOLVER));
    let mut pool = IdlePool::new(
        config,
        hostname,
        OPTIONS.wintun_args().pool_size + 1,
        OPTIONS.wintun_args().port,
        OPTIONS.wintun_args().hostname.clone(),
    );
    pool.init(&poll, &resolver);
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);

    let (udp_req_sender, udp_req_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);
    let (tcp_req_sender, _tcp_req_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

    let udp_server = UdpServer::new(udp_req_receiver, session.clone());

    let waker = resolver.get_waker();
    rayon::spawn(|| {
        do_tun_read(session, waker, udp_req_sender, tcp_req_sender).unwrap();
    });

    do_network(poll, resolver, pool, udp_server)
}

fn do_tun_read(
    session: Arc<Session>,
    waker: Arc<Waker>,
    udp_sender: Sender<UdpRequest>,
    tcp_sender: Sender<TcpRequest>,
) -> Result<()> {
    log::warn!("do_tun_read started");
    loop {
        let packet = session.receive_blocking()?;
        let version = packet.bytes()[0] >> 4;
        if version == 4 {
            let packet = Ipv4Packet::new_checked(packet.bytes())?;
            let source_addr = packet.src_addr();
            let target_addr = packet.dst_addr();
            if is_private(target_addr) {
                log::debug!("[{}->{}]skip packet", source_addr, target_addr);
                continue;
            }
            match packet.protocol() {
                IpProtocol::Udp => {
                    let packet = UdpPacket::new_checked(packet.payload())?;
                    let source =
                        SocketAddr::new(Ipv4Addr::from(source_addr).into(), packet.src_port());
                    let target =
                        SocketAddr::new(Ipv4Addr::from(target_addr).into(), packet.dst_port());
                    if let Ok(()) = udp_sender.try_send(UdpRequest {
                        source,
                        target,
                        payload: Vec::from(packet.payload()),
                    }) {
                        log::info!(
                            "[{}->{}]receive udp packet size:{}",
                            source,
                            target,
                            packet.payload().len()
                        );
                    } else {
                        log::warn!("udp buffer is full, skip packet");
                    }
                }
                IpProtocol::Tcp => {}
                _ => {}
            }
        } else {
        }

        waker.wake()?;
    }
}

fn do_network(
    mut poll: Poll,
    mut resolver: DnsResolver,
    mut pool: IdlePool,
    mut udp_server: UdpServer,
) -> Result<()> {
    log::warn!("do_network started");
    let mut events = Events::with_capacity(1024);
    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token().0 {
                RESOLVER => {
                    resolver.consume(|_, ip| {
                        pool.resolve(ip);
                    });
                    udp_server.do_local(&mut pool, &poll, &resolver);
                }
                i if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(event, &poll);
                }
                i if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.do_remote(event, &poll);
                }
                _ => {}
            }
        }
    }
}
