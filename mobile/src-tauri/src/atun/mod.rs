use std::{
    cell::RefCell,
    io::Read,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{atomic::AtomicBool, Arc},
    time::{Duration, SystemTime},
};

use hyper_rustls::ConfigBuilderExt;
use rustls::{ClientConfig, ClientConnection, ServerName};
use sha2::{Digest, Sha224};
use smoltcp::{
    iface::{Config, Interface, SocketSet},
    wire::{IpAddress, IpCidr, IpEndpoint, Ipv4Address},
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tauri::utils;
use tokio::{spawn, sync::Mutex};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RecordType},
    serialize::binary::BinDecodable,
};

use crate::{
    atun::{
        device::{UdpStream, VpnDevice},
        dns::start_dns,
        tcp::start_tcp,
        tls_stream::TlsClientStream,
        udp::start_udp,
    },
    platform, types,
    types::VpnError,
    Context,
};

mod device;
mod dns;
mod proto;
mod tcp;
mod tls_stream;
mod udp;

pub async fn init_tls_conn(
    config: Arc<ClientConfig>,
    buffer_size: usize,
    server_addr: SocketAddr,
    server_name: ServerName,
) -> types::Result<TlsClientStream> {
    let stream = tokio::net::TcpStream::connect(server_addr).await?;
    let session = ClientConnection::new(config, server_name)?;
    TlsClientStream::new(stream, session, buffer_size)
}

fn prepare_device(device: &mut VpnDevice) -> Interface {
    let mut config = Config::default();
    config.random_seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut interface = Interface::new(config, device);
    interface.set_any_ip(true);
    interface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .unwrap();

    interface.update_ip_addrs(|ips| {
        ips.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)).unwrap();
    });
    interface
}

fn digest_pass(pass: &String) -> String {
    let mut encoder = Sha224::new();
    encoder.update(pass.as_bytes());
    let result = encoder.finalize();
    hex::encode(result.as_slice())
}

/// This function resolves a domain name to a list of IP addresses.
pub fn resolve(name: &str, dns_server_addr: &str) -> types::Result<Vec<IpAddr>> {
    let dns_server_addr: SocketAddr = dns_server_addr.parse()?;
    let dns_server_addr: SockAddr = dns_server_addr.into();
    let mut socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    let addr: SockAddr = addr.into();
    socket.bind(&addr)?;
    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.set_id(1);
    let mut query = Query::new();
    let name = Name::from_str(name)?;
    query.set_name(name);
    query.set_query_type(RecordType::A);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    let request = message.to_vec()?;
    if request.len() != socket.send_to(request.as_slice(), &dns_server_addr)? {
        return Err(VpnError::Resolve);
    }
    let mut response = vec![0u8; 1024];
    socket.set_read_timeout(Some(Duration::from_millis(3000)))?;
    let length = socket.read(response.as_mut_slice())?;
    let message = Message::from_bytes(&response.as_slice()[..length])?;
    if message.id() != 1 {
        Err(VpnError::Resolve)
    } else {
        Ok(message
            .answers()
            .iter()
            .filter_map(|record| record.data().and_then(|data| data.to_ip_addr()))
            .collect())
    }
}

fn show_info(level: &String) -> bool {
    level == "Debug" || level == "Info" || level == "Trace"
}

pub async fn run(
    fd: i32,
    dns: String,
    context: Context,
    running: Arc<AtomicBool>,
) -> types::Result<()> {
    let session = Arc::new(platform::Session::new(
        fd,
        context.options.mtu,
        show_info(&context.options.log_level),
    ));

    let server_ip = resolve(
        context.options.hostname.as_str(),
        (context.options.untrusted_dns.clone() + ":53").as_str(),
    )?;

    if server_ip.is_empty() {
        return Err(VpnError::Resolve);
    }

    let server_name: ServerName = context.options.hostname.as_str().try_into()?;

    let server_addr = SocketAddr::new(server_ip[0], context.options.port);
    let listener_addr = dns + ":53";
    let listener_addr: SocketAddr = listener_addr.parse().unwrap();

    let pass = digest_pass(&context.options.password);

    let config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_native_roots()
            .with_no_client_auth(),
    );
    let sockets = Arc::new(RefCell::new(unsafe {
        std::mem::transmute(SocketSet::new([]))
    }));
    let mut device = VpnDevice::new(
        session.clone(),
        sockets,
        context.options.mtu,
        IpEndpoint::from(server_addr),
        IpEndpoint::from(listener_addr),
    );

    let mut interface = prepare_device(&mut device);

    let listener = device.create_udp_socket(listener_addr.into());

    let device = Arc::new(Mutex::new(device));

    let trusted_addr = (context.options.trusted_dns.clone() + ":53").parse()?;
    let distrusted_addr = (context.options.untrusted_dns.clone() + ":53").parse()?;

    let listener = VpnDevice::new_udp(&device, listener, listener_addr.into()).await;
    spawn(start_dns(
        listener,
        config.clone(),
        server_addr,
        server_name.clone(),
        4096,
        pass.clone(),
        trusted_addr,
        distrusted_addr,
        context.blocked_domains,
    ));
    loop {
        let mut lock = device.lock().await;
        lock.poll(&mut interface);
        for stream in VpnDevice::accept_tcp(&device).await {
            spawn(start_tcp(
                stream,
                config.clone(),
                server_addr,
                server_name.clone(),
                4096,
                pass.clone(),
            ));
        }
        for stream in VpnDevice::accept_udp(&device).await {
            spawn(start_udp(
                stream,
                server_addr,
                server_name.clone(),
                config.clone(),
                4096,
                pass.clone(),
            ));
        }
        let mut lock = device.lock().await;
        if let Some(delay) = lock.poll_delay(&mut interface) {
            tokio::time::sleep(delay.into()).await;
        }
    }
}
