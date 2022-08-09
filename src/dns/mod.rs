use std::{thread, time::Duration};

use mio::{Events, Poll};
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, TRUE},
    um::{consoleapi::SetConsoleCtrlHandler, wincon},
};

use server::DnsServer;

use crate::{dns::adapter::get_adapter_index, OPTIONS, types::Result};
pub use crate::dns::adapter::{get_adapter_ip, get_main_adapter_gwif, set_dns_server};

mod adapter;
mod domain;
mod server;

/// Token for trusted DNS server
const DNS_TRUSTED: usize = 2;
/// Token for poisoned DNS server
const DNS_POISONED: usize = 3;
/// Token for local DNS server
const DNS_LOCAL: usize = 4;

extern "system" fn console_callback(ctrl_type: DWORD) -> BOOL {
    log::warn!("console_callback called:{}", ctrl_type);
    match ctrl_type {
        wincon::CTRL_C_EVENT
        | wincon::CTRL_CLOSE_EVENT
        | wincon::CTRL_BREAK_EVENT
        | wincon::CTRL_SHUTDOWN_EVENT
        | wincon::CTRL_LOGOFF_EVENT => {
            set_dns_server("".into());
        }
        _ => (),
    }
    FALSE
}

pub fn run() -> Result<()> {
    unsafe {
        if FALSE == SetConsoleCtrlHandler(Some(console_callback), TRUE) {
            log::warn!("register console ctrl handle failed");
        } else {
            log::info!("register console ctrl handle success");
        }
    }

    while get_adapter_ip(OPTIONS.dns_args().tun_name.as_str()).is_none() {
        thread::sleep(Duration::new(1, 0));
    }
    let index = get_adapter_index(OPTIONS.dns_args().tun_name.as_str()).unwrap();

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut dns_server = DnsServer::new(index);
    dns_server.setup(&poll);
    if !set_dns_server(dns_server.name_server()) {
        log::warn!("set dns server failed");
    }

    log::warn!("dns server is ready");
    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            dns_server.ready(event, &poll);
        }
    }
}
