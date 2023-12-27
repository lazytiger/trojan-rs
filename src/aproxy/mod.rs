use std::{
    net::{IpAddr, SocketAddr},
    sync::{atomic::AtomicBool, Arc},
};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider,
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::{
    net::{lookup_host, TcpListener, TcpStream, UdpSocket},
    runtime::Runtime,
    sync::mpsc::unbounded_channel,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::{
    aproxy::{
        profiler::{run_profiler, start_check_server},
        tcp::run_tcp,
        udp::run_udp,
    },
    config::OPTIONS,
    proxy::new_socket,
    types,
    types::Result,
};

mod profiler;
mod tcp;
mod udp;

pub fn run() -> Result<()> {
    let runtime = Runtime::new()?;
    runtime.block_on(async_run())
}

#[derive(Debug)]
pub struct InsecureAuth;

impl ServerCertVerifier for InsecureAuth {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn prepare_tls_config() -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    if OPTIONS.proxy_args().insecure {
        log::info!("insecure settings");
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureAuth));
    }
    Arc::new(config)
}

async fn async_run() -> Result<()> {
    log::info!("insecure:{}", OPTIONS.proxy_args().insecure);
    let addr: SocketAddr = OPTIONS.local_addr.parse()?;
    let tcp_listener = TcpListener::from_std(new_socket(addr, false)?.into())?;
    let udp_listener = UdpSocket::from_std(new_socket(addr, true)?.into())?;
    let server_name: ServerName = OPTIONS.proxy_args().hostname.as_str().try_into()?;
    let config = prepare_tls_config();
    let connector = TlsConnector::from(config);
    start_check_server(
        OPTIONS.proxy_args().hostname.clone(),
        150,
        OPTIONS.proxy_args().bypass_timeout,
    );

    let (sender, receiver) = if OPTIONS.proxy_args().enable_bypass {
        let (sender, receiver) = unbounded_channel();
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };

    if sender.is_none() {
        tokio::select! {
            ret = run_tcp(tcp_listener, server_name.clone(), connector.clone(), sender.clone()) => {
                log::error!("tcp routine exit with:{:?}", ret);
            },
            ret = run_udp(udp_listener, server_name.clone(), connector.clone(), sender.clone()) => {
                log::error!("udp routine exit with:{:?}", ret);
            }
        }
    } else {
        tokio::select! {
            ret = run_tcp(tcp_listener, server_name.clone(), connector.clone(), sender.clone()) => {
                log::error!("tcp routine exit with:{:?}", ret);
            },
            ret = run_udp(udp_listener, server_name.clone(), connector.clone(), sender.clone()) => {
                log::error!("udp routine exit with:{:?}", ret);
            }
            ret = run_profiler(receiver, sender, server_name.clone(), connector) => {
                log::error!("profiler routine exit with:{:?}", ret);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
async fn wait_until_stop(_running: Arc<AtomicBool>, _ip: IpAddr) {}

#[cfg(not(target_os = "windows"))]
async fn wait_until_stop(running: Arc<AtomicBool>, ip: IpAddr) {
    let timeout = OPTIONS.proxy_args().ipset_timeout;
    {
        let proxy_data = OPTIONS
            .proxy_args()
            .proxy_data
            .as_ref()
            .unwrap()
            .lock()
            .await;
        if timeout == 0 || proxy_data.skip_dns == Some(ip) {
            return;
        }
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut counter = 0;
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        tick.tick().await;
        counter += 1;
        if counter % timeout != 1 {
            continue;
        }
        let mut proxy_data = OPTIONS
            .proxy_args()
            .proxy_data
            .as_ref()
            .unwrap()
            .lock()
            .await;
        match proxy_data
            .no_bypass_session
            .add(ip, Some(timeout as u32 + 5))
        {
            Ok(ret) => {
                if !ret {
                    log::error!("add ip:{} to ipset failed", ip);
                }
            }
            Err(err) => {
                log::error!("add ip:{} to ipset failed:{}", ip, err);
            }
        }
    }
}

pub async fn init_tls_conn(
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> types::Result<TlsStream<TcpStream>> {
    let ips: Vec<_> = lookup_host((
        OPTIONS.proxy_args().hostname.as_str(),
        OPTIONS.proxy_args().port,
    ))
    .await?
    .collect();
    #[cfg(target_os = "linux")]
    {
        let mut proxy_data = OPTIONS
            .proxy_args()
            .proxy_data
            .as_ref()
            .unwrap()
            .lock()
            .await;
        for ip in &ips {
            if !proxy_data.server_ips.contains(&ip.ip()) {
                proxy_data.server_ips.push(ip.ip());
                if let Err(err) = proxy_data.bypass_session.add(ip.ip(), None) {
                    log::error!("add ip:{} to session failed:{}", ip, err);
                }
            }
        }
    }
    let stream = tokio::net::TcpStream::connect(ips.as_slice()).await?;
    let conn = connector.connect(server_name, stream).await?;
    Ok(conn)
}
