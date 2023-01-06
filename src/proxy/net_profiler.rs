use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{Arc, RwLock},
    thread,
    time::Duration,
};

use dns_lookup::lookup_host;
use rand::random;
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};
use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

pub struct NetProfiler {
    set: HashSet<IpAddr>,
    sender: Option<UnboundedSender<IpAddr>>,
}

struct Condition {
    avg_cost: u128,
    lost_ratio: u16,
}

lazy_static::lazy_static! {
    static ref CONDITION:RwLock<Condition> = RwLock::new(
        Condition{
            avg_cost:200,
            lost_ratio:5,
        }
    );
}

async fn start_check_routine(
    req_receiver: UnboundedReceiver<IpAddr>,
    resp_sender: UnboundedSender<IpAddr>,
    resp_receiver: UnboundedReceiver<IpAddr>,
    bypass_ipset: String,
    nobypass_ipset: String,
) {
    log::info!("start check routine");
    let handle1 = tokio::spawn(start_request(req_receiver, resp_sender, nobypass_ipset));
    let handle2 = tokio::spawn(start_response(resp_receiver, bypass_ipset));
    if let Err(err) = handle2.await {
        log::error!("response routine failed:{}", err);
    }
    if let Err(err) = handle1.await {
        log::error!("request routine failed:{}", err);
    }
}

#[allow(unused_variables)]
async fn start_response(mut receiver: UnboundedReceiver<IpAddr>, name: String) {
    log::info!("start response routine");
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let mut session = ipset::Session::new();
        }
    }
    loop {
        let ip = if let Some(ip) = receiver.recv().await {
            ip
        } else {
            break;
        };
        log::warn!("{} should be bypassed", ip);
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                if let Err(err) = session.add(name.as_str(), ip) {
                    log::error!("add ip:{} to ipset {} failed:{:?}", ip, name, err);
                }
            }
        }
    }
    log::info!("stop response routine");
}

#[allow(unused_variables)]
async fn start_request(
    mut receiver: UnboundedReceiver<IpAddr>,
    sender: UnboundedSender<IpAddr>,
    name: String,
) {
    log::info!("start request routine");
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client = Arc::new(Client::new(&config).unwrap());
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let mut session = ipset::Session::new();
        }
    }
    let mut id = 0u16;
    loop {
        let ip = if let Some(ip) = receiver.recv().await {
            ip
        } else {
            break;
        };
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                if let Ok(true) = session.test(name.as_str(), ip) {
                    continue;
                }
            }
        }
        log::info!("request {}", ip);
        tokio::spawn(do_check(ip, client.clone(), id, sender.clone()));
        id = id.wrapping_add(1);
    }
    log::info!("stop request routine");
}

async fn do_check(ip: IpAddr, client: Arc<Client>, id: u16, sender: UnboundedSender<IpAddr>) {
    log::info!("start checking {}", ip);
    let mut pinger = client.pinger(ip, PingIdentifier(id)).await;
    pinger.timeout(Duration::from_millis(999));
    let mut lost_ratio = 0;
    let mut avg_cost = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    for i in 0..100u128 {
        interval.tick().await;
        if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
            avg_cost = ((avg_cost * i) + cost.as_millis()) / (i + 1);
        } else {
            lost_ratio += 1;
        }
    }

    log::info!(
        "ip:{}, avg_cost:{}, lost_ratio:{}",
        ip,
        avg_cost,
        lost_ratio
    );
    if let Err(err) = CONDITION.read().map(|cond| {
        if lost_ratio < cond.lost_ratio && avg_cost < cond.avg_cost {
            if let Err(err) = sender.send(ip) {
                log::error!("send response ip:{} failed:{}", ip, err);
            }
        }
    }) {
        log::error!("read on condition failed:{}", err);
    }
}

async fn check_server(host: String) {
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client = Client::new(&config).unwrap();
    let mut interval = tokio::time::interval(Duration::from_secs(3600));
    loop {
        interval.tick().await;
        let ip = if let Ok(Some(ip)) =
            lookup_host(host.as_str()).map(|data| data.iter().find(|ip| ip.is_ipv4()).cloned())
        {
            ip
        } else {
            continue;
        };
        let mut pinger = client.pinger(ip, PingIdentifier(random())).await;
        pinger.timeout(Duration::from_millis(999));
        let mut avg_cost = 0;
        let mut lost_ratio = 0;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        for i in 0..100u128 {
            tick.tick().await;
            if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
                avg_cost = ((avg_cost * i) + cost.as_millis()) / (i + 1);
            } else {
                lost_ratio += 1;
            }
        }
        log::info!("ip:{} avg_cost:{}, lost_ratio:{}", ip, avg_cost, lost_ratio);
        if let Err(err) = CONDITION.write().map(|mut cond| {
            cond.lost_ratio = lost_ratio;
            cond.avg_cost = avg_cost;
        }) {
            log::error!("write on condition failed:{}", err);
        }
    }
}

pub fn start_check_server(host: String) {
    thread::spawn(|| {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(check_server(host));
    });
}

impl NetProfiler {
    pub fn new(
        enable: bool,
        avg_cost: u128,
        lost_ratio: u16,
        bypass_ipset: String,
        nobypass_ipset: String,
    ) -> Self {
        let sender = if enable {
            if let Err(err) = CONDITION.write().map(|mut cond| {
                cond.lost_ratio = lost_ratio;
                cond.avg_cost = avg_cost;
            }) {
                log::error!("set condition failed:{}", err);
            }
            let (req_sender, req_receiver) = mpsc::unbounded_channel();
            let (resp_sender, resp_receiver) = mpsc::unbounded_channel();
            thread::spawn(|| {
                let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
                runtime.block_on(start_check_routine(
                    req_receiver,
                    resp_sender,
                    resp_receiver,
                    bypass_ipset,
                    nobypass_ipset,
                ));
                log::info!("check thread stopped");
            });
            Some(req_sender)
        } else {
            None
        };

        Self {
            set: HashSet::new(),
            sender,
        }
    }
    pub fn check(&mut self, ip: IpAddr) {
        if let Some(sender) = &self.sender {
            if self.set.insert(ip) {
                if let Err(err) = sender.send(ip) {
                    log::error!("send ip:{} failed:{}", err, ip);
                }
            }
        }
    }
}

#[allow(unused_imports)]
mod tests {
    use std::{thread::sleep, time::Duration};

    use crate::proxy::net_profiler::{start_check_server, NetProfiler};

    #[test_log::test]
    fn test_net_profiler() {
        let mut profiler = NetProfiler::new(true, 200, 5, "".to_string(), "".to_string());
        profiler.check("104.225.237.172".parse().unwrap());
        start_check_server("pha.hopingwhite.com".to_string());
    }
}
