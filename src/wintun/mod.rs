use std::{convert::TryInto, net::SocketAddr, process::Command, sync::Arc};

use crossbeam::channel::{Receiver, Sender};
use mio::{Events, Poll, Token, Waker};
use pnet::packet::{ip::IpNextHeaderProtocols, udp::UdpPacket, Packet as _, Packet};
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

pub async fn run() -> Result<()> {
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let mut adapter = match Adapter::open(&wintun, "trojan", OPTIONS.wintun_args().name.as_str()) {
        Ok(a) => a,
        Err(_) => {
            Adapter::create(
                &wintun,
                "trojan",
                OPTIONS.wintun_args().name.as_str(),
                OPTIONS.wintun_args().guid,
            )?
            .adapter
        }
    };

    if OPTIONS.wintun_args().delete {
        adapter.delete(true)?;
        return Ok(());
    }

    if let Some(guid) = OPTIONS.wintun_args().guid {
        adapter.set_guid(guid);
    }

    let index = adapter.get_adapter_index()?;

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

    let hostname = OPTIONS.proxy_args().hostname.as_str().try_into()?;

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
    let mut pool = IdlePool::new(config, hostname);
    pool.init(&poll, &resolver);

    let (udp_req_sender, udp_req_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);
    let (udp_resp_sender, udp_resp_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);
    let (tcp_req_sender, _tcp_req_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);
    let (tcp_resp_sender, tcp_resp_receiver) =
        crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);

    let udp_server = UdpServer::new(udp_req_receiver, udp_resp_sender);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    tokio::select! {
        err = do_tun_read(session.clone(), resolver.get_waker(), udp_req_sender, tcp_req_sender) => {
            if let Err(err) = err {
                log::error!("session read failed:{:?}", err);
            }
        },
        err = do_tun_send(session.clone(), tcp_resp_receiver, udp_resp_receiver) => {
            if let Err(err) = err {
                log::error!("session send failed:{:?}", err);
            }
        },
        err = do_network(poll, resolver, pool, udp_server) => {
            if let Err(err) = err {
                log::error!("network failed:{:?}", err);
            }
        }
    };
    Ok(())
}

async fn do_tun_read(
    session: Arc<Session>,
    waker: Arc<Waker>,
    udp_sender: Sender<UdpRequest>,
    _tcp_sender: Sender<TcpRequest>,
) -> Result<()> {
    loop {
        let packet = session.receive_blocking()?;
        if let Some(packet) = IpPacket::new(packet.bytes()) {
            let source_addr = packet.get_source();
            let target_addr = packet.get_destination();
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

async fn do_tun_send(
    session: Arc<Session>,
    tcp_receiver: Receiver<TcpResponse>,
    udp_receiver: Receiver<UdpResponse>,
) -> Result<()> {
    loop {
        crossbeam::select! {
            recv(udp_receiver) -> packet => {
                let packet = packet?;
                let mut send = session.allocate_send_packet(packet.packet().len() as u16)?;
                send.bytes_mut().copy_from_slice(packet.packet());
                session.send_packet(send);
            },
            recv(tcp_receiver) -> _packet => {

            }
        }
    }
}

async fn do_network(
    mut poll: Poll,
    mut resolver: DnsResolver,
    mut pool: IdlePool,
    mut udp_server: UdpServer,
) -> Result<()> {
    let mut events = Events::with_capacity(1024);
    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            match event.token().0 {
                i if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(event, &poll);
                }
                i if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.ready(&mut pool, &poll, &resolver);
                }
                i if i % CHANNEL_CNT == CHANNEL_TCP => {}
                _ => resolver.consume(|_, ip| {
                    pool.resolve(ip);
                }),
            }
        }
    }
}
