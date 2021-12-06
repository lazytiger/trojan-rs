use std::{convert::TryInto, net::SocketAddr, process::Command, sync::Arc};

use crossbeam::channel::{Receiver, Sender};
use mio::{Events, Poll, Token, Waker};
use pnet::{
    ipnetwork::{IpNetwork, IpNetworkIterator},
    packet::{ip::IpNextHeaderProtocols, udp::UdpPacket, Packet as _, Packet},
};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use wintun::{Adapter, Session};

use crate::{
    proxy::IdlePool,
    resolver::DnsResolver,
    types::Result,
    wintun::{
        ip::IpPacket,
        tcp::{TcpRequest, TcpResponse},
        udp::{UdpRequest, UdpResponse, UdpServer},
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
    let mut adapter = match Adapter::open(&wintun, OPTIONS.wintun_args().name.as_str()) {
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
    _tcp_sender: Sender<TcpRequest>,
) -> Result<()> {
    log::warn!("do_tun_read started");
    let private = IpNetwork::new("224.0.0.0".parse()?, 4)?;
    loop {
        let packet = session.receive_blocking()?;
        if let Some(packet) = IpPacket::new(packet.bytes()) {
            let source_addr = packet.get_source();
            let target_addr = packet.get_destination();
            if !target_addr.is_global() || private.contains(target_addr) {
                log::debug!("ignore private ip:{}", target_addr);
                continue;
            }
            if let IpPacket::V4(p) = &packet {
                log::info!(
                    "version:{}, ttl:{}, dscp:{}, ecn:{}, flags:{}, offset:{}, id:{}, total:{}, header:{}, options:{:?}",
                    p.get_version(),
                    p.get_ttl(),
                    p.get_dscp(),
                    p.get_ecn(),
                    p.get_flags(),
                    p.get_fragment_offset(),
                    p.get_identification(),
                    p.get_total_length(),
                    p.get_header_length(),
                    p.get_options_raw(),
                );
            }
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {
                    if let Some(packet) = UdpPacket::new(packet.payload()) {
                        let source = SocketAddr::new(source_addr, packet.get_source());
                        let target = SocketAddr::new(target_addr, packet.get_destination());
                        if let Err(_err) = udp_sender.try_send(UdpRequest {
                            source,
                            target,
                            payload: Vec::from(packet.payload()),
                        }) {
                            log::warn!("udp send buffer is full, drop packet now");
                        } else {
                            log::info!(
                                "[{}->{}]receive udp packet size:{}",
                                source,
                                target,
                                packet.payload().len()
                            );
                        }
                    } else {
                        log::error!("parse udp packet failed");
                    }
                }
                IpNextHeaderProtocols::Tcp => {}
                _ => {}
            }
            waker.wake()?;
        } else {
            log::error!("invalid ip packet");
        }
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
