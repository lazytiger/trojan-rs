use std::{collections::BTreeMap, convert::TryInto, process::Command, sync::Arc, thread};

use crossbeam::channel::Sender;
use mio::{Events, Poll, Token, Waker};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use smoltcp::{
    iface::{Interface, InterfaceBuilder, Routes},
    socket::{Socket, TcpSocket, TcpSocketBuffer, UdpPacketMetadata, UdpSocket, UdpSocketBuffer},
    time::{Duration, Instant},
    wire::{
        IpAddress, IpCidr, IpEndpoint, IpProtocol, IpVersion, Ipv4Address, Ipv4Packet, Ipv6Packet,
        TcpPacket, UdpPacket,
    },
};
use wintun::{Adapter, Session};

use crate::{
    dns::get_adapter_ip,
    proxy::IdlePool,
    resolver::DnsResolver,
    types::Result,
    wintun::{
        ipset::{is_private, IPSet},
        tcp::TcpServer,
        tun::TunInterface,
        udp::UdpServer,
        waker::Wakers,
    },
    OPTIONS,
};
pub use route::route_add_with_if;

mod ipset;
mod route;
mod tcp;
mod tun;
mod udp;
mod waker;

pub(crate) type SocketSet<'a> = Interface<'a, TunInterface>;

/// Token used for DNS resolver
const RESOLVER: usize = 1;
/// Minimum index
const MIN_INDEX: usize = 2;
/// Maximum index
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
/// Channel count for index
const CHANNEL_CNT: usize = 3;
/// Channel index  for `IdlePool`
const CHANNEL_IDLE: usize = 0;
/// Channel index for client `UdpConnection`
const CHANNEL_UDP: usize = 1;
/// Channel index for remote tcp connection
const CHANNEL_TCP: usize = 2;

pub fn run() -> Result<()> {
    log::info!("dll:{}", OPTIONS.wintun_args().wintun);
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let adapter = Adapter::create(&wintun, "trojan", OPTIONS.wintun_args().name.as_str(), None)?;
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    let index = adapter.get_adapter_index()?;

    if let Some(file) = &OPTIONS.wintun_args().route_ipset {
        let mut ipset = IPSet::with_file(file.as_str())?;
        if OPTIONS.wintun_args().inverse_route {
            ipset = !ipset;
        }
        //route_add_with_if(757147431, !0, index)?;
        //route_add_with_if(794538172, !0, index)?;
        ipset.add_route(index)?;
        log::warn!("route add completed");
    }

    while get_adapter_ip(OPTIONS.wintun_args().name.as_str()).is_none() {
        thread::sleep(std::time::Duration::new(1, 0));
    }
    let gateway = get_adapter_ip(OPTIONS.wintun_args().name.as_str()).unwrap();
    log::warn!("wintun is ready at:{}", gateway);

    if OPTIONS.wintun_args().with_dns {
        let _ = thread::spawn(|| {
            let program = std::env::current_exe().unwrap();
            let args = OPTIONS.wintun_args();
            let log_file = if !OPTIONS.log_file.is_empty() {
                OPTIONS.log_file.clone() + ".dns"
            } else {
                "".into()
            };
            let message = match Command::new(program.clone())
                .args([
                    "--log-file",
                    log_file.as_str(),
                    "--local-addr",
                    OPTIONS.local_addr.as_str(),
                    "--password",
                    OPTIONS.password.as_str(),
                    "--log-level",
                    OPTIONS.log_level.to_string().as_str(),
                    "--udp-idle-timeout",
                    OPTIONS.udp_idle_timeout.to_string().as_str(),
                    "--tcp-idle-timeout",
                    OPTIONS.tcp_idle_timeout.to_string().as_str(),
                    "dns",
                    "-n",
                    args.name.as_str(),
                    "--blocked-domain-list",
                    args.blocked_domain_list.as_str(),
                    "--dns-listen-address",
                    args.dns_listen_address.as_str(),
                    "--trusted-dns",
                    args.trusted_dns.as_str(),
                    "--poisoned-dns",
                    args.poisoned_dns.as_str(),
                ])
                .output()
            {
                Ok(output) => {
                    if output.status.success() {
                        "success".into()
                    } else {
                        String::from_utf8(output.stderr).unwrap()
                    }
                }
                Err(err) => err.to_string(),
            };
            log::error!("trojan dns exit with message:{}", message);
            std::process::exit(-1);
        });
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

    let (rx_sender, rx_receiver) = crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);
    let (tx_sender, tx_receiver) = crossbeam::channel::bounded(OPTIONS.wintun_args().buffer_size);

    let ip_addrs = [IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)];

    let mut routes = Routes::new(BTreeMap::new());
    routes
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .unwrap();
    let mut interface = InterfaceBuilder::new(
        TunInterface::new(tx_sender, rx_receiver, OPTIONS.wintun_args().mtu),
        [],
    )
    .any_ip(true)
    .ip_addrs(ip_addrs)
    .routes(routes)
    .finalize();

    let mut events = Events::with_capacity(1024);
    let timeout = Some(Duration::from_millis(1));
    let mut udp_server = UdpServer::new();
    let mut tcp_server = TcpServer::new();

    let mut last_udp_check_time = std::time::Instant::now();
    let mut last_tcp_check_time = std::time::Instant::now();
    let check_duration = std::time::Duration::new(10, 0);

    let tx_session = session.clone();
    let _ = thread::spawn(move || {
        while let Ok(data) = tx_receiver.recv() {
            match tx_session.allocate_send_packet(data.len() as u16) {
                Ok(mut packet) => {
                    packet.bytes_mut().copy_from_slice(data.as_slice());
                    tx_session.send_packet(packet);
                }
                Err(err) => {
                    log::error!("allocate send packet failed:{:?}", err);
                }
            }
        }
    });

    let mut now = Instant::now();
    let mut wakers = Wakers::new();
    loop {
        wakers.clear();
        do_tun_read(&session, &rx_sender, &mut interface, &mut wakers)?;
        if let Err(err) = interface.poll(now) {
            log::info!("interface error:{}", err);
        }
        udp_server.do_local(&mut pool, &poll, &resolver, &mut wakers, &mut interface);
        tcp_server.do_local(&mut pool, &poll, &resolver, &mut wakers, &mut interface);

        now = Instant::now();
        let timeout = interface.poll_delay(now).or(timeout);
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
                    udp_server.do_remote(event, &poll, &mut interface, &mut wakers);
                }
                _ => {
                    tcp_server.do_remote(event, &poll, &mut interface, &mut wakers);
                }
            }
        }

        let now = std::time::Instant::now();
        if now - last_tcp_check_time > check_duration {
            tcp_server.check_timeout(&poll, now, &mut interface);
            last_tcp_check_time = now;
        }

        if now - last_udp_check_time > OPTIONS.udp_idle_duration {
            udp_server.check_timeout(now, &mut interface);
            last_udp_check_time = now;
        }
    }
}

fn do_tun_read(
    session: &Arc<Session>,
    sender: &Sender<Vec<u8>>,
    sockets: &mut SocketSet,
    wakers: &mut Wakers,
) -> Result<()> {
    for _ in 0..1024 {
        let packet = session.try_receive()?;
        if packet.is_none() {
            break;
        }
        let packet = packet.unwrap();
        let (dst_addr, payload, protocol) = match IpVersion::of_packet(packet.bytes()).unwrap() {
            IpVersion::Ipv4 => {
                let packet = Ipv4Packet::new_checked(packet.bytes()).unwrap();
                let dst_addr = packet.dst_addr();
                (
                    IpAddress::Ipv4(dst_addr),
                    packet.payload(),
                    packet.protocol(),
                )
            }
            IpVersion::Ipv6 => {
                let packet = Ipv6Packet::new_checked(packet.bytes()).unwrap();
                let dst_addr = packet.dst_addr();
                (
                    IpAddress::Ipv6(dst_addr),
                    packet.payload(),
                    packet.next_header(),
                )
            }
            _ => continue,
        };
        let (dst_port, connect) = match protocol {
            IpProtocol::Udp => {
                let packet = UdpPacket::new_checked(payload).unwrap();
                (packet.dst_port(), None)
            }
            IpProtocol::Tcp => {
                let packet = TcpPacket::new_checked(payload).unwrap();
                (packet.dst_port(), Some(packet.syn() && !packet.ack()))
            }
            _ => continue,
        };

        let dst_endpoint = IpEndpoint::new(dst_addr, dst_port);
        if is_private(dst_endpoint) {
            continue;
        }

        if connect.is_some() && connect.unwrap() {
            let socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0; OPTIONS.wintun_args().tcp_rx_buffer_size]),
                TcpSocketBuffer::new(vec![0; OPTIONS.wintun_args().tcp_tx_buffer_size]),
            );
            let handle = sockets.add_socket(socket);
            let socket = sockets.get_socket::<TcpSocket>(handle);
            socket.listen(dst_endpoint).unwrap();
            socket.set_nagle_enabled(false);
            socket.set_ack_delay(None);
            let (rx, tx) = wakers.get_tcp_wakers(handle);
            socket.register_recv_waker(rx);
            socket.register_send_waker(tx);
            log::info!("handle:{} is tcp", handle);
        } else if !sockets.sockets().any(|(_, socket)| {
            if let Socket::Udp(socket) = socket {
                socket.endpoint() == dst_endpoint
            } else {
                false
            }
        }) {
            let mut socket = UdpSocket::new(
                UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; OPTIONS.wintun_args().udp_rx_meta_size],
                    vec![0; OPTIONS.wintun_args().udp_rx_buffer_size],
                ),
                UdpSocketBuffer::new(
                    vec![UdpPacketMetadata::EMPTY; OPTIONS.wintun_args().udp_rx_meta_size],
                    vec![0; OPTIONS.wintun_args().udp_tx_buffer_size],
                ),
            );
            socket.bind(dst_endpoint)?;
            let handle = sockets.add_socket(socket);
            log::info!("handle:{} is udp", handle);
            let socket = sockets.get_socket::<UdpSocket>(handle);
            let (rx, tx) = wakers.get_udp_wakers(handle);
            socket.register_recv_waker(rx);
            socket.register_send_waker(tx);
        }

        if let Err(err) = sender.try_send(packet.bytes().into()) {
            log::error!("tun read channel is full:{}", err);
        }
    }
    Ok(())
}
