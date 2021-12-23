use derive_more::From;

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
    Smoltcp(smoltcp::Error),
    #[from(ignore)]
    NonWindowsPlatform,
    #[from(ignore)]
    Winapi(String),
}

pub type Result<T> = std::result::Result<T, TrojanError>;
