use std::{
    fs::File,
    io::BufReader,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{net::TcpListener, Events, Interest, Poll, Token, Waker};
use rustls::{
    server::{AllowAnyAnonymousOrAuthenticatedClient, NoClientAuth},
    KeyLogFile, RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, read_one, Item};

pub use tls_server::TlsServer;

use crate::{
    config::OPTIONS,
    resolver::DnsResolver,
    server::{stat::Statistics, tls_server::PollEvent},
    types::Result,
};

mod connection;
pub mod ping_backend;
mod stat;
mod tcp_backend;
mod tls_server;
mod udp_backend;

const MIN_INDEX: usize = 3;
const MAX_INDEX: usize = usize::MAX / CHANNEL_CNT;
const CHANNEL_CNT: usize = 2;
const CHANNEL_PROXY: usize = 0;
const CHANNEL_BACKEND: usize = 1;
const RESOLVER: usize = 2;
const LISTENER: usize = 1;

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let cert_file = File::open(filename).unwrap();
    let mut buff_reader = BufReader::new(cert_file);
    certs(&mut buff_reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let key_file = File::open(filename).unwrap();
    let mut buff_reader = BufReader::new(key_file);
    loop {
        match read_one(&mut buff_reader).unwrap() {
            Some(Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }
    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    )
}

pub fn init_config() -> Result<Arc<ServerConfig>> {
    let client_auth = if OPTIONS.server_args().check_auth {
        let roots = load_certs(OPTIONS.server_args().cert.as_str());
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root)?;
        }
        AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots).boxed()
    } else {
        NoClientAuth::boxed()
    };

    let certs = load_certs(OPTIONS.server_args().cert.as_str());
    let private_key = load_private_key(OPTIONS.server_args().key.as_str());
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, private_key, vec![], vec![])?;
    config.key_log = Arc::new(KeyLogFile::new());

    let mut protocols: Vec<Vec<u8>> = Vec::new();
    for protocol in &OPTIONS.server_args().alpn {
        protocols.push(protocol.as_str().into());
    }
    if !protocols.is_empty() {
        config.alpn_protocols = protocols;
    }
    Ok(Arc::new(config))
}

pub fn run() -> Result<()> {
    let config = init_config()?;
    let mut poll = Poll::new()?;
    let waker = Arc::new(Waker::new(poll.registry(), Token(RESOLVER))?);
    let mut resolver = DnsResolver::new(waker, Token(RESOLVER), None);
    resolver.set_cache_timeout(OPTIONS.server_args().dns_cache_time);
    let addr = OPTIONS.local_addr.parse()?;
    let mut listener = TcpListener::bind(addr)?;
    poll.registry()
        .register(&mut listener, Token(LISTENER), Interest::READABLE)?;
    let mut server = TlsServer::new(listener, config);
    let mut events = Events::with_capacity(1024);
    let mut last_check_time = Instant::now();
    let check_duration = Duration::new(1, 0);
    let mut last_status_time = Instant::now();
    let status_check = Duration::new(60, 0);
    let mut stats = Statistics::new();
    loop {
        poll.poll(&mut events, Some(check_duration))?;
        for event in &events {
            match event.token() {
                Token(LISTENER) => {
                    server.accept(&poll);
                }
                Token(RESOLVER) => {
                    resolver.consume(|token, ip| {
                        server.do_conn_event(&poll, PollEvent::Dns((token, ip)), None, &mut stats);
                    });
                }
                _ => {
                    server.do_conn_event(
                        &poll,
                        PollEvent::Network(event),
                        Some(&mut resolver),
                        &mut stats,
                    );
                }
            }
        }
        server.remove_closed();
        server.poll_ping(&mut stats);
        let now = Instant::now();
        if now - last_check_time > check_duration {
            server.check_timeout(now, &poll);
            last_check_time = now;
        }
        if now - last_status_time > status_check {
            stats.save(
                OPTIONS.server_args().status_file.as_str(),
                OPTIONS.server_args().status_limit,
            );
            last_status_time = now;
        }
    }
}
