use std::{
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    thread,
    time::Duration,
};

use crossbeam::channel::{unbounded, Sender};
use mio::{Events, Poll};
use notify::{Event, EventHandler, RecursiveMode, Watcher};
use winapi::{
    shared::minwindef::{BOOL, DWORD, FALSE, TRUE},
    um::{consoleapi::SetConsoleCtrlHandler, wincon},
};

use server::DnsServer;
pub use wintool::adapter::{
    get_adapter_index, get_adapter_ip, get_main_adapter_gwif, set_dns_server,
};

use crate::{
    types::{Result, TrojanError},
    wintun::route_add_with_if,
    OPTIONS,
};

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

    if let Some((main_gw, main_index)) = get_main_adapter_gwif() {
        log::warn!(
            "main adapter gateway is {}, main adapter index is :{}",
            main_gw,
            main_index
        );
        let gw: Ipv4Addr = OPTIONS.dns_args().poisoned_dns.parse()?;
        if let Some(SocketAddr::V4(v4)) = &OPTIONS.back_addr {
            let index: u32 = (*v4.ip()).into();
            route_add_with_if(index, !0, gw.into(), main_index)?;
        }
    } else {
        log::error!("main adapter gateway not found");
        return Err(TrojanError::MainAdapterNotFound);
    }
    let index = get_adapter_index(OPTIONS.dns_args().tun_name.as_str()).unwrap();

    let (sender, receiver) = unbounded();
    let monitor = FileMonitor { sender };
    let mut watcher = notify::recommended_watcher(monitor)?;
    let domain_path = Path::new(OPTIONS.dns_args().blocked_domain_list.as_str());
    let hosts_path = Path::new(OPTIONS.dns_args().hosts.as_str());
    watcher.watch(domain_path, RecursiveMode::NonRecursive)?;
    watcher.watch(hosts_path, RecursiveMode::NonRecursive)?;

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut dns_server = DnsServer::new(index);
    dns_server.setup(&poll);
    if !set_dns_server(dns_server.name_server()) {
        log::error!("set dns server failed");
        return Ok(());
    }

    log::warn!("dns server is ready");
    let timeout = Duration::from_secs(1);
    loop {
        let mut update_domain = false;
        let mut update_hosts = false;
        for event in receiver.try_iter() {
            if event.paths.contains(&domain_path.to_path_buf()) {
                update_domain = true;
            }
            if event.paths.contains(&hosts_path.to_path_buf()) {
                update_hosts = true;
            }
        }
        if update_domain {
            log::warn!("domain file changed, update now");
            dns_server.update_domain();
        }
        if update_hosts {
            log::warn!("hosts file changed, update now");
            dns_server.update_hosts();
        }
        poll.poll(&mut events, Some(timeout))?;
        for event in &events {
            dns_server.ready(event, &poll);
        }
    }
}
