use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};

use crossbeam::channel::{unbounded, Sender};
use ipset::Session;
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};

use crate::config::OPTIONS;

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
            cfg_if::cfg_if! {
                if #[cfg(unix)] {
                    let mut session = Session::new();
                }
            }
            req_receiver.iter().fold(0, |mut id, ip| {
                cfg_if::cfg_if! {
                    if #[cfg(unix)] {
                        if let Ok(true) = session.test(OPTIONS.proxy_args().no_bypass_ipset.as_str(), ip) {
                            return id;
                        }
                    }
                }
                if id == u16::MAX {
                    id = 0
                };
                let client_copy = client.clone();
                let sender = resp_sender.clone();
                tokio::spawn(async move {
                    let mut pinger = client_copy.pinger(ip, PingIdentifier(id)).await;
                    pinger.timeout(Duration::from_millis(
                        OPTIONS.proxy_args().ping_timeout as u64,
                    ));
                    let mut failed = 0;
                    let mut avg_cost = 0;
                    for i in 0..100u128 {
                        if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
                            avg_cost = ((avg_cost * i) + cost.as_millis()) / (i + 1);
                        } else {
                            failed += 1;
                        }
                    }
                    if failed < OPTIONS.proxy_args().bypass_lost_ratio
                        && avg_cost < OPTIONS.proxy_args().bypass_avg_cost as u128
                    {
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
                    let mut session = ipset::Session::new();
                }
            }
            resp_receiver.iter().for_each(|ip| {
                log::warn!("{} should be bypassed", ip);
                cfg_if::cfg_if! {
                    if #[cfg(unix)] {
                        if let Err(err) = session.add(OPTIONS.proxy_args().bypass_ipset.as_str(), ip) {
                            log::error!("add ip:{} to ipset byplist failed:{:?}", ip, err);
                        }
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
