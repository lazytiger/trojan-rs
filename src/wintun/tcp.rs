use crate::{idle_pool::IdlePool, resolver::DnsResolver};
use mio::Poll;
use smoltcp::socket::{SocketHandle, SocketSet};

pub struct TcpServer {}

impl TcpServer {
    pub fn new() -> Self {
        Self {}
    }

    pub(crate) fn do_local(
        &self,
        pool: &mut IdlePool,
        poll: &Poll,
        resolver: &DnsResolver,
        handles: Vec<SocketHandle>,
        sockets: &mut SocketSet,
    ) {
    }
}
