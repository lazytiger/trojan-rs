use std::net::IpAddr;

use derive_more::From;
use log::SetLoggerError;

#[cfg(target_os = "linux")]
use ipset::{
    types::{EnvOption, HashIp},
    Session,
};

#[allow(dead_code)]
#[derive(From, Debug)]
pub enum TrojanError {
    StdIo(std::io::Error),
    Rustls(rustls::Error),
    #[cfg(target_os = "windows")]
    Wintun(wintun::Error),
    LibLoading(libloading::Error),
    Dummy(()),
    AddrParse(std::net::AddrParseError),
    DnsName(rustls_pki_types::InvalidDnsNameError),
    VerifiedBuilder(rustls::client::VerifierBuilderError),
    Webpki(webpki::Error),
    CrossbeamRecv(crossbeam::channel::RecvError),
    #[from(ignore)]
    NonWindowsPlatform,
    #[from(ignore)]
    Winapi(String),
    #[from(ignore)]
    TxBreak(Option<std::io::Error>),
    #[from(ignore)]
    RxBreak(Option<std::io::Error>),
    DnsProto(trust_dns_proto::error::ProtoError),
    #[from(ignore)]
    MainAdapterNotFound,
    Notify(notify::Error),
    SetLogger(SetLoggerError),
    TokioSendIpAddr(tokio::sync::mpsc::error::SendError<IpAddr>),
    #[from(ignore)]
    Resolve,
    Elapsed(tokio::time::error::Elapsed),
}

unsafe impl Send for TrojanError {}

#[allow(dead_code)]
pub enum CopyResult {
    RxBlock,
    TxBlock,
}

pub type Result<T> = std::result::Result<T, TrojanError>;

#[cfg(target_os = "linux")]
pub struct ProxyData {
    pub server_ips: Vec<IpAddr>,
    pub bypass_session: Session<HashIp>,
    pub no_bypass_session: Session<HashIp>,
}

#[cfg(target_os = "linux")]
impl ProxyData {
    pub fn new(no_bypass: &str, bypass: &str) -> Self {
        let no_bypass_session = Session::new(no_bypass);
        no_bypass_session.set_option(EnvOption::Exist);
        let bypass_session = Session::new(bypass);
        bypass_session.set_option(EnvOption::Exist);
        Self {
            server_ips: vec![],
            bypass_session,
            no_bypass_session,
        }
    }
}
