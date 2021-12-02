use crate::types::Result;
use crate::OPTIONS;
use pnet::packet::ipv4::Ipv4Packet;
use std::process::Command;
use std::sync::Arc;
use wintun::{Adapter, Packet};

pub fn run() -> Result<()> {
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let mut adapter = match Adapter::open(&wintun, "trojan", OPTIONS.wintun_args().name.as_str()) {
        Ok(a) => a,
        Err(_) => {
            Adapter::create(
                &wintun,
                "trojan",
                OPTIONS.wintun_args().name.as_str(),
                Some(OPTIONS.wintun_args().guid),
            )?
            .adapter
        }
    };

    if OPTIONS.wintun_args().delete {
        adapter.delete(true)?;
        return Ok(());
    }

    adapter.set_guid(OPTIONS.wintun_args().guid);

    let index = adapter.get_adapter_index()?;

    if let Err(err) = Command::new("route")
        .args([
            "add",
            "8.8.8.8",
            "mask",
            "255.255.255.255",
            "0.0.0.0",
            "METRIC",
            "1",
            "IF",
            index.to_string().as_str(),
        ])
        .output()
    {
        log::error!("route add 8.8.8.8 failed:{}", err);
    }

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    loop {
        let packet = session.receive_blocking()?;
        if let Some(packet) = Ipv4Packet::new(packet.bytes()) {
            log::info!(
                "{}->{}, {}",
                packet.get_source(),
                packet.get_destination(),
                packet.get_next_level_protocol()
            );
        } else {
            log::info!("ip v6 packet");
        }
    }
}
