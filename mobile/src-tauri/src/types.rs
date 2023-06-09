use derive_more::From;

#[derive(From, Debug)]
pub enum VpnError {
    #[cfg(target_os = "android")]
    JNI(jni::errors::Error),
    Tauri(tauri::Error),
    #[from(ignore)]
    RLock(String),
    #[from(ignore)]
    WLock(String),
    NoWindow,
    NoPlatformContext,
    Io(std::io::Error),
    Rustls(rustls::Error),
    AddrParse(std::net::AddrParseError),
    DnsProto(trust_dns_proto::error::ProtoError),
    #[from(ignore)]
    TxBreak(Option<std::io::Error>),
    #[from(ignore)]
    RxBreak(Option<std::io::Error>),
    Resolve,
    InvalidDnsName(rustls::client::InvalidDnsNameError),
    Smoltcp(smoltcp::wire::Error),
    Json(serde_json::Error),
}

#[allow(dead_code)]
pub enum CopyResult {
    RxBlock,
    TxBlock,
}

pub type Result<T> = std::result::Result<T, VpnError>;
