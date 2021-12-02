use derive_more::From;

#[derive(From, Debug)]
pub enum TrojanError {
    StdIo(std::io::Error),
    Rustls(rustls::Error),
    Wintun(wintun::WintunError),
    LibLoading(libloading::Error),
    Dummy(()),
    AddrParse(std::net::AddrParseError),
    InvalidDnsName(rustls::client::InvalidDnsNameError),
    Webpki(webpki::Error),
    Recv(std::sync::mpsc::RecvError),
}

pub type Result<T> = std::result::Result<T, TrojanError>;
