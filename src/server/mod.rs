use std::{
    fs::File,
    io::BufReader,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{net::TcpListener, Events, Interest, Poll, Token};
use rustls::{
    server::{AllowAnyAnonymousOrAuthenticatedClient, NoClientAuth},
    KeyLogFile, RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, read_one, Item};

pub use tls_server::TlsServer;

use crate::{config::OPTIONS, resolver::DnsResolver, server::tls_server::PollEvent};

mod connection;
mod tcp_backend;
mod tls_server;
mod udp_backend;

const MIN_INDEX: usize = 2;
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

fn init_config() -> Arc<ServerConfig> {
    let client_auth = if OPTIONS.server_args().check_auth {
        let roots = load_certs(OPTIONS.server_args().cert.as_str());
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(&root).unwrap();
        }
        AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
    } else {
        NoClientAuth::new()
    };

    let suits = rustls::ALL_CIPHER_SUITES.to_vec();
    let certs = load_certs(OPTIONS.server_args().cert.as_str());
    let private_key = load_private_key(OPTIONS.server_args().key.as_str());
    let mut config = ServerConfig::builder()
        .with_cipher_suites(&suits)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp_and_sct(certs, private_key, vec![], vec![])
        .unwrap();
    config.key_log = Arc::new(KeyLogFile::new());

    let mut protocols: Vec<Vec<u8>> = Vec::new();
    for protocol in &OPTIONS.server_args().alpn {
        protocols.push(protocol.as_str().into());
    }
    if !protocols.is_empty() {
        config.alpn_protocols = protocols;
    }
    Arc::new(config)
}

pub fn run() {
    let config = init_config();
    let mut poll = Poll::new().unwrap();
    let mut resolver = DnsResolver::new(&poll, Token(RESOLVER));
    resolver.set_cache_timeout(OPTIONS.server_args().dns_cache_time);
    let addr = OPTIONS.local_addr.parse().unwrap();
    let mut listener = TcpListener::bind(addr).unwrap();
    poll.registry()
        .register(&mut listener, Token(LISTENER), Interest::READABLE)
        .unwrap();
    let mut server = TlsServer::new(listener, config);
    let mut events = Events::with_capacity(1024);
    let mut last_check_time = Instant::now();
    let check_duration = Duration::new(1, 0);
    loop {
        poll.poll(&mut events, Some(check_duration)).unwrap();
        for event in &events {
            match event.token() {
                Token(LISTENER) => {
                    server.accept();
                }
                Token(RESOLVER) => {
                    resolver.consume(|token, ip| {
                        server.do_conn_event(&poll, PollEvent::Dns((token, ip)), None);
                    });
                }
                _ => {
                    server.do_conn_event(&poll, PollEvent::Network(&event), Some(&mut resolver));
                }
            }
        }
        let now = Instant::now();
        if now - last_check_time > check_duration {
            server.check_timeout(now, &poll);
            last_check_time = now;
        }
    }
}
