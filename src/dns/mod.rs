use std::{path::Path, thread, time::Duration};

use crossbeam::channel::{unbounded, Sender};
use mio::{Events, Poll};
use notify::{Event, EventHandler, RecursiveMode, Watcher};
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, TRUE},
    um::{consoleapi::SetConsoleCtrlHandler, wincon},
};

use server::DnsServer;

pub use crate::dns::adapter::{get_adapter_ip, get_main_adapter_gwif, set_dns_server};
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

struct FileMonitor {
    sender: Sender<Event>,
}

impl EventHandler for FileMonitor {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        match event {
            Ok(event) => {
                if let Err(err) = self.sender.send(event) {
                    log::error!("send event failed:{}", err);
                }
            }
            Err(err) => log::error!("handle event failed:{}", err),
        }
    }
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

    let (sender, receiver) = unbounded();
    let monitor = FileMonitor { sender };
    let mut watcher = notify::recommended_watcher(monitor)?;
    let watched_file = Path::new(OPTIONS.dns_args().blocked_domain_list.as_str());
    watcher.watch(&watched_file, RecursiveMode::NonRecursive)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut dns_server = DnsServer::new(index);
    dns_server.setup(&poll);
    if !set_dns_server(dns_server.name_server()) {
        log::warn!("set dns server failed");
    }

    log::warn!("dns server is ready");
    let timeout = Duration::from_secs(1);
    loop {
        let count = receiver.try_iter().count();
        if count > 0 {
            log::warn!("update domain now");
            dns_server.update_domain();
        }
        poll.poll(&mut events, Some(timeout))?;
        for event in &events {
            dns_server.ready(event, &poll);
        }
    }
}
