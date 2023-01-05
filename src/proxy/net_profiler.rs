use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crossbeam::channel::{unbounded, Sender};
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};

pub struct NetProfiler {
    set: HashSet<IpAddr>,
    sender: Sender<IpAddr>,
}

impl NetProfiler {
    pub fn new() -> Self {
        let (req_sender, req_receiver) = unbounded();
        let (resp_sender, resp_receiver) = unbounded();
        tokio::spawn(async move {
            let config = ConfigBuilder::default().kind(ICMP::V4).build();
            let client = Arc::new(Client::new(&config).unwrap());
            req_receiver.iter().fold(0, |mut id, ip| {
                if id == u16::MAX {
                    id = 0
                };
                let client_copy = client.clone();
                let sender = resp_sender.clone();
                tokio::spawn(async move {
                    let mut pinger = client_copy.pinger(ip, PingIdentifier(id)).await;
                    let mut failed = 0;
                    let mut avg_cost = 0;
                    for i in 0..100u128 {
                        if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
                            avg_cost = ((avg_cost * i) + cost.as_millis()) / (i + 1);
                        } else {
                            failed += 1;
                        }
                    }
                    if failed < 3 && avg_cost < 200 {
                        if let Err(err) = sender.send(ip) {
                            log::error!("send response ip:{} failed:{}", ip, err);
                        }
                    }
                });
                id + 1
            });
        });
        tokio::spawn(async move {
            cfg_if::cfg_if! {
                if #[cfg(unix)] {
                    let session = ipset::Session::new();
                }
            }
            resp_receiver.iter().for_each(|ip| {
                cfg_if::cfg_if! {
                    if #[cfg(unix)] {
                        if let Err(err) = session.add("byplist", ip) {
                            log::error!("add ip:{} to ipset byplist failed:{}", ip, err);
                        }
                    } else {
                        log::info!("bypass ip:{}", ip);
                    }
                }
            });
        });
        Self {
            set: HashSet::new(),
            sender: req_sender,
        }
    }
    pub fn check(&mut self, ip: IpAddr) {
        if self.set.insert(ip) {
            if let Err(err) = self.sender.send(ip) {
                log::error!("send ip:{} failed:{}", err, ip);
            }
        }
    }
}
