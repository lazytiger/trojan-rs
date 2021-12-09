use std::{collections::BTreeMap, convert::TryInto, process::Command, sync::Arc};

use crossbeam::channel::Sender;
use mio::{Events, Poll, Token, Waker};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use smoltcp::{
    iface::{InterfaceBuilder, Routes},
    socket::{
        Socket, SocketHandle, SocketSet, TcpSocket, TcpSocketBuffer, UdpPacketMetadata, UdpSocket,
        UdpSocketBuffer,
    },
    time::{Duration, Instant},
    wire::{
        IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Packet,
        TcpPacket, UdpPacket,
    },
};
use wintun::{Adapter, Session};

use crate::{
    proxy::IdlePool,
    resolver::DnsResolver,
    types::Result,
    wintun::{
        ip::{is_private, TunInterface},
        tcp::TcpServer,
        udp::UdpServer,
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

fn add_route(address: &str, netmask: &str, index: u32) {
    if let Err(err) = Command::new("route")
        .args([
            "add",
            address,
            "mask",
            netmask,
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            index.to_string().as_str(),
        ])
        .output()
    {
        log::error!("route add {} failed:{}", address, err);
    }
}

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
    add_route("8.8.8.8", "255.255.255.255", index);

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

    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let mut resolver = DnsResolver::new(waker, Token(RESOLVER));
    let mut pool = IdlePool::new(
        config,
        hostname,
        OPTIONS.wintun_args().pool_size + 1,
        OPTIONS.wintun_args().port,
        OPTIONS.wintun_args().hostname.clone(),
    );
    pool.init(&poll, &resolver);
    pool.init_index(CHANNEL_CNT, CHANNEL_IDLE, MIN_INDEX, MAX_INDEX);

    let (sender, receiver) = crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);

    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)];

    let mut routes = Routes::new(BTreeMap::new());
    routes
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .unwrap();
    let mut interface = InterfaceBuilder::new(TunInterface::new(
        session.clone(),
        receiver,
        OPTIONS.wintun_args().mtu,
    ))
    .any_ip(true)
    .ip_addrs(ip_addrs)
    .routes(routes)
    .finalize();

    let mut sockets = SocketSet::new([]);
    let mut events = Events::with_capacity(1024);
    let timeout = Some(Duration::from_millis(1));
    let mut udp_server = UdpServer::new();
    let mut tcp_server = TcpServer::new();

    let mut last_udp_check_time = std::time::Instant::now();
    let mut last_tcp_check_time = std::time::Instant::now();
    let check_duration = std::time::Duration::new(1, 0);

    loop {
        let now = Instant::now();
        let timeout = interface.poll_delay(&sockets, now).or(timeout);
        poll.poll(
            &mut events,
            timeout.map(|d| std::time::Duration::from_millis(d.total_millis())),
        )?;
        for event in &events {
            match event.token().0 {
                RESOLVER => {
                    resolver.consume(|_, ip| {
                        pool.resolve(ip);
                    });
                }
                i if i % CHANNEL_CNT == CHANNEL_IDLE => {
                    pool.ready(event, &poll);
                }
                i if i % CHANNEL_CNT == CHANNEL_UDP => {
                    udp_server.do_remote(event, &poll, &mut sockets);
                }
                _ => {
                    tcp_server.do_remote(event, &poll, &mut sockets);
                }
            }
        }
        let (udp_handles, tcp_handles) = do_tun_read(&session, &sender, &mut sockets)?;
        if let Err(err) = interface.poll(&mut sockets, now) {
            log::info!("interface error:{}", err);
        }
        udp_server.do_local(&mut pool, &poll, &resolver, udp_handles, &mut sockets);
        tcp_server.do_local(&mut pool, &poll, &resolver, tcp_handles, &mut sockets);

        let now = std::time::Instant::now();
        if now - last_tcp_check_time > check_duration {
            tcp_server.check_timeout(&poll, now, &mut sockets);
            last_tcp_check_time = now;
        }

        if now - last_udp_check_time > OPTIONS.udp_idle_duration {
            udp_server.check_timeout(now, &mut sockets);
            last_udp_check_time = now;
        }
    }
}

fn do_tun_read(
    session: &Arc<Session>,
    sender: &Sender<Vec<u8>>,
    sockets: &mut SocketSet,
) -> Result<(Vec<SocketHandle>, Vec<SocketHandle>)> {
    let mut udp_handles = Vec::new();
    let mut tcp_handles = Vec::new();
    loop {
        let packet = session.try_receive()?;
        if packet.is_none() {
            break;
        }
        let packet = packet.unwrap();
        let (src_addr, dst_addr, payload, protocol) =
            match IpVersion::of_packet(packet.bytes()).unwrap() {
                IpVersion::Ipv4 => {
                    let packet = Ipv4Packet::new_checked(packet.bytes()).unwrap();
                    let src_addr = packet.src_addr();
                    let dst_addr = packet.dst_addr();
                    (
                        IpAddress::Ipv4(src_addr),
                        IpAddress::Ipv4(dst_addr),
                        packet.payload(),
                        packet.protocol(),
                    )
                }
                IpVersion::Ipv6 => {
                    let packet = Ipv6Packet::new_checked(packet.bytes()).unwrap();
                    let src_addr = packet.src_addr();
                    let dst_addr = packet.dst_addr();
                    (
                        IpAddress::Ipv6(src_addr),
                        IpAddress::Ipv6(dst_addr),
                        packet.payload(),
                        packet.next_header(),
                    )
                }
                _ => continue,
            };
        let (src_port, dst_port, notify, connect) = match protocol {
            IpProtocol::Udp => {
                let packet = UdpPacket::new_checked(payload).unwrap();
                (packet.src_port(), packet.dst_port(), true, None)
            }
            IpProtocol::Tcp => {
                let packet = TcpPacket::new_checked(payload).unwrap();
                (
                    packet.src_port(),
                    packet.dst_port(),
                    !packet.payload().is_empty() || packet.fin(),
                    Some(packet.syn() && !packet.ack()),
                )
            }
            _ => continue,
        };

        let src_endpoint = IpEndpoint::new(src_addr, src_port);
        let dst_endpoint = IpEndpoint::new(dst_addr, dst_port);
        if is_private(dst_endpoint) {
            continue;
        }

        if let Some(connect) = connect {
            if let Some(handle) = if connect {
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0; 10240]),
                    TcpSocketBuffer::new(vec![0; 10240]),
                );
                socket.listen(dst_endpoint).unwrap();
                Some(sockets.add(socket))
            } else {
                sockets.iter().find_map(|socket| match socket {
                    Socket::Tcp(socket)
                        if socket.local_endpoint() == dst_endpoint
                            && socket.remote_endpoint() == src_endpoint =>
                    {
                        Some(socket.handle())
                    }
                    _ => None,
                })
            } {
                if notify {
                    tcp_handles.push(handle);
                }
            }
        } else {
            let handle = sockets.iter().find_map(|socket| match socket {
                Socket::Udp(socket) if socket.endpoint() == dst_endpoint => Some(socket.handle()),
                _ => None,
            });
            let handle = match handle {
                None => {
                    let mut socket = UdpSocket::new(
                        UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 1500]),
                        UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY], vec![0; 1500]),
                    );
                    socket.bind(dst_endpoint)?;
                    sockets.add(socket)
                }
                Some(handle) => handle,
            };
            udp_handles.push(handle);
        }

        if let Err(err) = sender.try_send(packet.bytes().into()) {
            log::warn!("sender buffer is full:{}", err);
        }
    }

    Ok((udp_handles, tcp_handles))
}
