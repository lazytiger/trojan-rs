use std::{any::Any, io::Result, net::SocketAddr};

fn unsupported() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "proxy mode is not supported on this platform",
    )
}

#[allow(dead_code)]
pub fn set_mark<T: Any>(_socket: &T, _mark: u8) -> Result<()> {
    Ok(())
}

pub fn set_socket_opts<T: Any>(_v4: bool, _is_udp: bool, _socket: &T) -> Result<()> {
    Err(unsupported())
}

pub fn get_oridst_addr<T: Any>(_s: &T) -> Result<SocketAddr> {
    Err(unsupported())
}

pub fn recv_from_with_destination<T: Any>(
    _socket: &T,
    _buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    Err(unsupported())
}
