use std::{thread, time::Duration};

use mio::{Events, Poll};

use server::DnsServer;

pub use crate::dns::adapter::{get_adapter_ip, get_main_adapter_gwif};
use crate::{dns::adapter::get_adapter_index, types::Result, OPTIONS};

mod adapter;
mod domain;
mod server;

/// Token for trusted DNS server
const DNS_TRUSTED: usize = 2;
/// Token for poisoned DNS server
const DNS_POISONED: usize = 3;
/// Token for local DNS server
const DNS_LOCAL: usize = 4;

pub fn run() -> Result<()> {
    while get_adapter_ip(OPTIONS.dns_args().tun_name.as_str()).is_none() {
        thread::sleep(Duration::new(1, 0));
    }
    let index = get_adapter_index(OPTIONS.dns_args().tun_name.as_str()).unwrap();

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut dns_server = DnsServer::new(index);
    dns_server.setup(&poll);

    log::warn!("dns server is ready");
    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            dns_server.ready(event, &poll);
        }
    }
}
