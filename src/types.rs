use std::net::IpAddr;

use derive_more::From;
use log::SetLoggerError;

#[allow(dead_code)]
#[derive(From, Debug)]
pub enum TrojanError {
    StdIo(std::io::Error),
    Rustls(rustls::Error),
    #[cfg(target_os = "windows")]
    Wintun(wintun::WintunError),
    LibLoading(libloading::Error),
    Dummy(()),
    AddrParse(std::net::AddrParseError),
    InvalidDnsName(rustls::client::InvalidDnsNameError),
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
