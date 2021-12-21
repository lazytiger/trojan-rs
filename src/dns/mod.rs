use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::Command,
    thread,
    time::Duration,
};

use mio::{Events, Poll};
use server::DnsServer;

use crate::{types::Result, OPTIONS};

pub use crate::dns::adapter::get_adapter_ip;

mod adapter;
mod domain;
mod server;

/// Token for trusted DNS server
const DNS_TRUSTED: usize = 2;
/// Token for poisoned DNS server
const DNS_POISONED: usize = 3;
/// Token for local DNS server
const DNS_LOCAL: usize = 4;

#[allow(dead_code)]
pub fn add_route_with_if(address: &str, netmask: &str, index: u32) -> bool {
    match Command::new("route")
        .args([
            "add",
            address,
            "mask",
            netmask,
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            index.to_string().as_str(),
        ])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!(
                    "route add {} mask {} 0.0.0.0 metric 1 if {}",
                    address,
                    netmask,
                    index
                );
                return true;
            } else {
                log::info!(
                    "route add {} mask {} 0.0.0.0 metric 1 if {} failed:{}",
                    address,
                    netmask,
                    index,
                    String::from_utf8(output.stderr).unwrap(),
                );
            }
        }
        Err(err) => {
            log::error!("route add {} failed:{}", address, err);
        }
    }
    false
}

#[allow(dead_code)]
fn add_route_with_gw(address: &str, netmask: &str, gateway: &str) -> bool {
    match Command::new("route")
        .args(["add", address, "mask", netmask, gateway, "METRIC", "1"])
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                log::info!(
                    "route add {} mask {} {} metric 1",
                    address,
                    netmask,
                    gateway
                );
                return true;
            } else {
                log::error!(
                    "route add {} mask {} {} metric 1 failed:{}",
                    address,
                    netmask,
                    gateway,
                    String::from_utf8(output.stderr).unwrap(),
                );
            }
        }
        Err(err) => log::error!("route add {} failed:{}", address, err),
    }
    false
}

pub fn run() -> Result<()> {
    while get_adapter_ip(OPTIONS.dns_args().tun_name.as_str()).is_none() {
        thread::sleep(Duration::new(1, 0));
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    let mut dns_server = DnsServer::new();
    dns_server.setup(&poll);

    loop {
        poll.poll(&mut events, None)?;
        for event in &events {
            dns_server.ready(event, &poll);
        }
    }
}

#[allow(dead_code)]
fn add_ipset(config: &str, gw: &str) -> Result<()> {
    let file = File::open(config)?;
    let buffer = BufReader::new(file);
    buffer.lines().for_each(|line| {
        let line = line.unwrap();
        let line: Vec<_> = line.split('/').collect();
        log::info!("route add {} mask {}", line[0], line[1]);
        add_route_with_gw(line[0], line[1], gw);
    });
    Ok(())
}
