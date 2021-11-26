use std::{any::Any, io::Result, net::SocketAddr};

#[allow(dead_code)]
pub fn set_mark<T: Any>(_socket: &T, _mark: u8) -> Result<()> {
    Ok(())
}

pub fn set_socket_opts<T: Any>(_v4: bool, _is_udp: bool, _socket: &T) -> Result<()> {
    unimplemented!("proxy mode not supported in windows");
}

pub fn get_oridst_addr<T: Any>(_s: &T) -> Result<SocketAddr> {
    unimplemented!("proxy mode not supported in windows");
}

pub fn recv_from_with_destination<T: Any>(
    _socket: &T,
    _buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    unimplemented!("proxy mode not supported in windows");
}
