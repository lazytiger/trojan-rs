use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    ops::Add,
    sync::{Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, BytesMut};
use dns_lookup::lookup_host;
use itertools::Itertools;
use mio::{event::Event, Poll, Token};
use rand::random;
use ringbuf::{HeapRb, Rb};
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};
use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{
    idle_pool::IdlePool, proto, proto::TrojanRequest, proxy::PINGER, resolver::DnsResolver,
    status::StatusProvider, tls_conn::TlsConn,
};

#[derive(Debug)]
struct PingResult {
    last_time: Instant,
    local_lost: u8,
    local_ping: u16,
    remote_lost: u8,
    remote_ping: u16,
    sent: bool,
}

impl PingResult {
    pub(crate) fn is_complete(&self) -> bool {
        self.local_lost != u8::MAX
            && self.local_ping != u16::MAX
            && self.remote_lost != u8::MAX
            && self.remote_ping != u16::MAX
    }

    fn is_no_bypass(&self) -> bool {
        self.local_ping == u16::MAX - 1 && self.local_lost == u8::MAX - 1
    }
}

impl Default for PingResult {
    fn default() -> Self {
        Self {
            last_time: Instant::now(),
            local_lost: u8::MAX,
            local_ping: u16::MAX,
            remote_lost: u8::MAX,
            remote_ping: u16::MAX,
            sent: true,
        }
    }
}

pub struct NetProfiler {
    set: HashMap<IpAddr, PingResult>,
    check_sender: Option<UnboundedSender<IpAddr>>,
    resp_receiver: Option<UnboundedReceiver<(IpAddr, u16, u8)>>,
    ipset_sender: Option<UnboundedSender<(IpAddr, bool)>>,
    conn: Option<TlsConn>,
    send_buffer: BytesMut,
    recv_buffer: BytesMut,
    timeout: Duration,
    ping_threshold: u16,
    next_check: Instant,
}

#[derive(Clone)]
struct Condition {
    ping: u16,
    lost: u8,
}

lazy_static::lazy_static! {
    static ref CONDITION:RwLock<Condition> = RwLock::new(
        Condition{
            ping:200,
            lost:5,
        }
    );
}

async fn start_check_routine(
    req_receiver: UnboundedReceiver<IpAddr>,
    resp_sender: UnboundedSender<(IpAddr, u16, u8)>,
    ipset_receiver: UnboundedReceiver<(IpAddr, bool)>,
    bypass_ipset: String,
    nobypass_ipset: String,
) {
    log::info!("start check routine");
    let handle1 = tokio::spawn(start_request(req_receiver, resp_sender, nobypass_ipset));
    let handle2 = tokio::spawn(start_response(ipset_receiver, bypass_ipset));
    if let Err(err) = handle2.await {
        log::error!("response routine failed:{}", err);
    }
    if let Err(err) = handle1.await {
        log::error!("request routine failed:{}", err);
    }
}

#[allow(unused_variables)]
async fn start_response(mut receiver: UnboundedReceiver<(IpAddr, bool)>, name: String) {
    log::info!("start response routine");
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let mut session:ipset::Session<ipset::types::HashIp> = ipset::Session::new(name);
            if let Err(err) = session.flush() {
                log::error!("flush ipset failed:{:?}", err);
            }
        }
    }
    loop {
        let (ip, add) = if let Some(ip) = receiver.recv().await {
            ip
        } else {
            break;
        };
        log::warn!("{} should be bypassed", ip);
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                if let Err(err) = if add {
                    session.add(ip, None)
                } else {
                    session.del(ip)
                } {
                    log::error!("add ip:{} to ipset failed:{:?}", ip,  err);
                }
            }
        }
    }
    log::info!("stop response routine");
}

#[allow(unused_variables)]
async fn start_request(
    mut receiver: UnboundedReceiver<IpAddr>,
    sender: UnboundedSender<(IpAddr, u16, u8)>,
    name: String,
) {
    log::info!("start request routine");
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client = Arc::new(Client::new(&config).unwrap());
    cfg_if::cfg_if! {
        if #[cfg(unix)] {
            let mut session:ipset::Session<ipset::types::HashIp> = ipset::Session::new(name);
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
                if let Ok(true) = session.test(ip) {
                    if let Err(err) = sender.send((ip, u16::MAX, u8::MAX)) {
                        log::error!("send local ping for {} failed:{}", ip, err);
                    }
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

async fn do_check(
    ip: IpAddr,
    client: Arc<Client>,
    id: u16,
    sender: UnboundedSender<(IpAddr, u16, u8)>,
) {
    log::info!("start checking {}", ip);
    let mut pinger = client.pinger(ip, PingIdentifier(id)).await;
    pinger.timeout(Duration::from_millis(999));
    let mut avg_cost = 0;
    let mut received = 0;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    for i in 0..100u128 {
        interval.tick().await;
        if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
            avg_cost = ((avg_cost * received) + cost.as_millis()) / (received + 1);
            received += 1;
        }
    }

    log::info!(
        "ip:{}, avg_cost:{}, lost_ratio:{}",
        ip,
        avg_cost,
        100 - received,
    );
    if let Err(err) = sender.send((ip, avg_cost as u16, (100 - received) as u8)) {
        log::error!("send response ip:{} failed:{}", ip, err);
    }
}

async fn check_server(host: String, timeout: u64, ip_timeout: u64) {
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client = Client::new(&config).unwrap();
    let mut interval = tokio::time::interval(Duration::from_secs(timeout));
    let size = (ip_timeout / timeout + 1) as usize;
    let mut rb = HeapRb::new(size);
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
        let mut received = 0;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        for i in 0..100u128 {
            tick.tick().await;
            if let Ok((_, cost)) = pinger.ping(PingSequence(i as u16), &[]).await {
                avg_cost = ((avg_cost * received) + cost.as_millis()) / (received + 1);
                received += 1;
            }
        }
        log::error!(
            "proxy server status, ip:{} ping:{}, lost:{}",
            ip,
            avg_cost,
            100 - received
        );
        rb.push_overwrite(Condition {
            lost: (100 - received) as u8,
            ping: avg_cost as u16,
        });
        let mut total_ping = 0;
        let mut total_lost = 0;
        for cond in rb.iter() {
            total_ping += cond.ping as usize;
            total_lost += cond.lost as usize;
        }
        let avg_ping = total_ping / rb.len();
        let avg_lost = total_lost / rb.len();

        if let Err(err) = CONDITION.write().map(|mut cond| {
            cond.lost = avg_lost as u8;
            cond.ping = avg_ping as u16;
        }) {
            log::error!("write on condition failed:{}", err);
        }
    }
}

pub fn start_check_server(host: String, timeout: u64, ip_timeout: u64) {
    thread::spawn(move || {
        let runtime = Runtime::new().unwrap();
        runtime.block_on(check_server(host, timeout, ip_timeout));
    });
}

impl NetProfiler {
    pub fn new(
        enable: bool,
        timeout: u64,
        local_threshold: u16,
        bypass_ipset: String,
        nobypass_ipset: String,
    ) -> Self {
        let (check_sender, resp_receiver, ipset_sender) = if enable {
            if let Err(err) = CONDITION.write().map(|mut cond| {
                cond.lost = 3;
                cond.ping = 200;
            }) {
                log::error!("set condition failed:{}", err);
            }
            let (req_sender, req_receiver) = mpsc::unbounded_channel();
            let (resp_sender, resp_receiver) = mpsc::unbounded_channel();
            let (ipset_sender, ipset_receiver) = mpsc::unbounded_channel();
            thread::spawn(|| {
                let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
                runtime.block_on(start_check_routine(
                    req_receiver,
                    resp_sender,
                    ipset_receiver,
                    bypass_ipset,
                    nobypass_ipset,
                ));
                log::info!("check thread stopped");
            });
            (Some(req_sender), Some(resp_receiver), Some(ipset_sender))
        } else {
            (None, None, None)
        };

        Self {
            set: HashMap::new(),
            timeout: Duration::from_secs(timeout),
            check_sender,
            resp_receiver,
            ipset_sender,
            ping_threshold: local_threshold,
            conn: None,
            send_buffer: BytesMut::new(),
            recv_buffer: BytesMut::new(),
            next_check: Instant::now().add(Duration::from_secs(timeout)),
        }
    }

    pub fn initialize(&mut self, poll: &Poll, resolver: &DnsResolver, pool: &mut IdlePool) -> bool {
        if self.ipset_sender.is_none() {
            return true;
        }
        log::error!("net profiler remote reconnect now");
        if let Some(mut conn) = pool.get(&poll, &resolver) {
            if conn.reset_index(0, Token(PINGER), &poll) {
                let mut data = BytesMut::new();
                let addr = SocketAddr::V4(SocketAddrV4::new(0.into(), 0));
                TrojanRequest::generate(&mut data, proto::PING, &addr);
                if conn.write_session(data.as_ref()) {
                    self.conn.replace(conn);
                    return true;
                }
            }
            conn.shutdown();
        }
        false
    }

    pub fn ready(
        &mut self,
        event: &Event,
        poll: &Poll,
        pool: &mut IdlePool,
        resolver: &DnsResolver,
    ) {
        if self.conn.is_none() {
            return;
        }

        if event.is_readable() {
            let conn = self.conn.as_mut().unwrap();
            if let Some(data) = conn.do_read() {
                self.recv_buffer.extend_from_slice(data.as_slice());
                self.decode();
            }
        }

        if event.is_writable() {
            let data = self.send_buffer.split();
            let conn = self.conn.as_mut().unwrap();
            if !data.is_empty() {
                conn.write_session(data.as_ref());
            }
            conn.established();
            conn.do_send();
        }

        if let Some(conn) = &self.conn {
            if conn.is_shutdown() {
                self.reset(poll, pool, resolver);
            }
        }
    }

    fn reset(&mut self, poll: &Poll, pool: &mut IdlePool, resolver: &DnsResolver) {
        if let Some(conn) = &mut self.conn {
            conn.shutdown();
        }
        self.conn.take();
        self.initialize(poll, resolver, pool);
    }

    fn send_remote_ip(&mut self, ip: &IpAddr) {
        match ip {
            IpAddr::V4(ip) => {
                self.send_buffer.put_u8(proto::IPV4);
                self.send_buffer.extend_from_slice(ip.octets().as_slice());
            }
            IpAddr::V6(ip) => {
                self.send_buffer.put_u8(proto::IPV6);
                self.send_buffer.extend_from_slice(ip.octets().as_slice());
            }
        }
        if let Some(conn) = &mut self.conn {
            if conn.write_session(self.send_buffer.split().as_ref()) {
                conn.do_send();
            }
        }
    }

    pub fn check(&mut self, ip: IpAddr) {
        if self.check_sender.is_none() {
            return;
        }

        if let Some(pr) = self.set.get(&ip) {
            if pr.is_no_bypass() || pr.last_time.elapsed() < self.timeout {
                return;
            }
        }

        self.send_remote_ip(&ip);

        if let Err(err) = self.check_sender.as_ref().unwrap().send(ip) {
            log::error!("send ip:{} to check routine failed:{}", ip, err);
        } else {
            let pr = self.set.entry(ip).or_default();
            pr.last_time = Instant::now();
            pr.sent = false;
        }
    }

    pub fn update(&mut self) {
        if self.resp_receiver.is_none() {
            return;
        }
        while let Ok((ip, ping, lost)) = self.resp_receiver.as_mut().unwrap().try_recv() {
            if let Some(pr) = self.set.get_mut(&ip) {
                pr.local_lost = lost.min(u8::MAX - 1);
                pr.local_ping = ping.min(u16::MAX - 1);
            } else {
                log::error!("ip:{} not found in set", ip);
            }
        }

        let cond = CONDITION.read();
        if cond.is_err() {
            return;
        }

        let cond: Condition = cond.unwrap().clone();

        let mut ips1 = Vec::new();
        let mut ips0 = Vec::new();
        for (key, group) in &self.set.iter().group_by(|(_ip, pr)| {
            if pr.is_complete() {
                if pr.sent || pr.is_no_bypass() {
                    2 //already sent
                } else {
                    1 //should send
                }
            } else {
                0 //not complete
            }
        }) {
            if key == 1 {
                ips1 = group.map(|(ip, _)| ip.clone()).collect();
            } else if key == 0 {
                ips0 = group
                    .filter_map(|(ip, pr)| {
                        if !pr.is_no_bypass() && pr.last_time.elapsed().as_secs() > 100 {
                            Some(ip.clone())
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }

        ips0.iter().for_each(|ip| {
            self.send_remote_ip(ip);
            self.set.get_mut(ip).unwrap().last_time = Instant::now();
        });

        ips1.iter().for_each(|ip| {
            let pr = self.set.get_mut(ip).unwrap();
            pr.sent = true;
            let mut bypass = false;
            let proxy_ping = cond.ping + pr.remote_ping;
            let proxy_lost =
                100 - ((100.0 - cond.lost as f32) * (100.0 - pr.remote_lost as f32) / 100.0) as u8;

            // Blocked ip may be faked, so the ping value may be good. This is the case we should exclude first.
            if pr.remote_ping < self.ping_threshold && pr.local_ping < self.ping_threshold {
                bypass = false;
            } else {
                if pr.local_ping < proxy_ping + 5 && pr.local_lost < proxy_lost + 2 {
                    bypass = true;
                }
            }


            if let Err(err) = self
                .ipset_sender
                .as_ref()
                .unwrap()
                .send((ip.clone(), bypass))
            {
                log::error!("send {} to ipset routine failed:{}", ip, err);
            } else {
                log::error!(
                    "ip:{:?}, local_ping:{}, local_lost:{}, remote_ping:{}, remote_lost:{}, proxy_ping:{}, proxy_lost:{}, bypass:{}",
                    ip,
                    pr.local_ping,
                    pr.local_lost,
                    pr.remote_ping,
                    pr.remote_lost,
                    proxy_ping,
                    proxy_lost,
                    bypass
                );
            }
        });

        let mut next_check = Instant::now();
        if self.next_check < next_check {
            next_check += self.timeout;
            let mut ips = Vec::new();
            for (k, v) in &self.set {
                if v.is_no_bypass() {
                    continue;
                }
                let due_time = v.last_time + self.timeout;
                if due_time <= self.next_check {
                    ips.push(k.clone());
                } else if next_check > due_time {
                    next_check = due_time;
                }
            }
            self.next_check = next_check;
            for ip in ips {
                self.check(ip);
            }
        }
    }

    fn decode(&mut self) {
        while !self.recv_buffer.is_empty() {
            let (ip, ping, lost): (IpAddr, _, _) = match self.recv_buffer.as_ref()[0] {
                proto::IPV4 => {
                    if self.recv_buffer.len() < 8 {
                        break;
                    }
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&self.recv_buffer.as_ref()[1..5]);
                    self.recv_buffer.advance(5);
                    let ping = self.recv_buffer.get_u16();
                    let lost = self.recv_buffer.get_u8();
                    let ip = Ipv4Addr::from(octets);
                    (ip.into(), ping, lost)
                }
                proto::IPV6 => {
                    if self.recv_buffer.len() < 20 {
                        break;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&self.recv_buffer.as_ref()[1..17]);
                    self.recv_buffer.advance(17);
                    let ping = self.recv_buffer.get_u16();
                    let lost = self.recv_buffer.get_u8();
                    let ip = Ipv6Addr::from(octets);
                    (ip.into(), ping, lost)
                }
                _ => unreachable!("invalid address type:{}", self.recv_buffer.as_ref()[0]),
            };
            if let Some(pr) = self.set.get_mut(&ip) {
                pr.remote_lost = lost.min(u8::MAX - 1);
                pr.remote_ping = ping.min(u16::MAX - 1);
            } else {
                log::error!("ip:{} not found in set", ip);
            }
        }
    }
}
