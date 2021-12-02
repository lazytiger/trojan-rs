use std::{
    process::Command,
    sync::{mpsc::Receiver, Arc},
};

use crossbeam::channel::Sender;
use pnet::packet::{ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, Packet as _};
use wintun::{Adapter, Packet, Session};

use crate::{types::Result, OPTIONS};

mod udp;

pub async fn run() -> Result<()> {
    let wintun = unsafe { wintun::load_from_path(&OPTIONS.wintun_args().wintun)? };
    let mut adapter = match Adapter::open(&wintun, "trojan", OPTIONS.wintun_args().name.as_str()) {
        Ok(a) => a,
        Err(_) => {
            Adapter::create(
                &wintun,
                "trojan",
                OPTIONS.wintun_args().name.as_str(),
                OPTIONS.wintun_args().guid,
            )?
            .adapter
        }
    };

    if OPTIONS.wintun_args().delete {
        adapter.delete(true)?;
        return Ok(());
    }

    if let Some(guid) = OPTIONS.wintun_args().guid {
        adapter.set_guid(guid);
    }

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
    tokio::select! {
        err = do_tun_read(session) => {
            if let Err(err) = err {
                log::error!("session read failed:{:?}", err);
            }
        },
        err = do_tun_send(session) => {
            if let Err(err) = err {
                log::error!("session send failed:{:?}", err);
            }
        },
        err = do_network() => {
            if let Err(err) = err {
                log::error!("network failed:{:?}", err);
            }
        }
    };
    Ok(())
}

async fn do_tun_read(session: Arc<Session>) -> Result<()> {
    loop {
        let packet = session.receive_blocking()?;
        if let Some(packet) = Ipv4Packet::new(packet.bytes()) {
            match packet.get_next_level_protocol() {
                IpNextHeaderProtocols::Udp => {}
                IpNextHeaderProtocols::Tcp => {}
                _ => {}
            }
        } else {
            log::info!("ip v6 packet");
        }
    }
}

async fn do_tun_send(session: Arc<Session>, receiver: Receiver<Ipv4Packet<'static>>) -> Result<()> {
    loop {
        let packet = receiver.recv()?;
        let mut send = session.allocate_send_packet(packet.payload().len() as u16)?;
        send.bytes_mut().copy_from_slice(packet.payload());
        session.send_packet(send);
    }
}

async fn do_network() -> Result<()> {
    Ok(())
}
