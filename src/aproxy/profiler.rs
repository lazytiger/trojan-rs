use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use bytes::{Buf, BufMut, BytesMut};
use dns_lookup::lookup_host;
use itertools::Itertools;
use rand::random;
use ringbuf::{HeapRb, Rb};
use rustls::{ClientConfig, ClientConnection, ServerName};
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    spawn,
    sync::mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use tokio_rustls::{TlsClientReadHalf, TlsClientStream};

use crate::{config::OPTIONS, proto, proto::TrojanRequest, types};

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
    let mut client = Client::new(&config).unwrap();
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
        if received != 100 {
            // recreate a client if any error occur, otherwise pinger would stuck for the error, maybe some error in surge
            client = Client::new(&config).unwrap();
        }
        log::error!(
            "current proxy server status, ip:{} ping:{}, lost:{}",
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
        log::error!(
            "average proxy server status, ip:{} ping:{}, lost:{}",
            ip,
            avg_ping,
            avg_lost,
        );

        if let Err(err) = CONDITION.write().map(|mut cond| {
            cond.lost = avg_lost as u8;
            cond.ping = avg_ping as u16;
        }) {
            log::error!("write on condition failed:{}", err);
        }
    }
}

pub fn start_check_server(host: String, timeout: u64, ip_timeout: u64) {
    spawn(check_server(host, timeout, ip_timeout));
}

enum SelectReturn {
    LocalResponse(Option<(IpAddr, u16, u8)>),
    RemoteResponse(Option<(IpAddr, u16, u8)>),
    Request(Option<IpAddr>),
}

impl SelectReturn {
    fn is_request(&self) -> bool {
        if let SelectReturn::Request(_) = self {
            true
        } else {
            false
        }
    }
}

pub async fn run_profiler(
    receiver: Option<UnboundedReceiver<IpAddr>>,
    sender: Option<UnboundedSender<IpAddr>>,
    server_name: ServerName,
    config: Arc<ClientConfig>,
) -> types::Result<()> {
    if receiver.is_none() {
        return Ok(());
    }
    let mut receiver = receiver.unwrap();
    let sender = sender.unwrap();
    let timeout = Duration::from_secs(OPTIONS.proxy_args().bypass_timeout);
    let ping_threshold = OPTIONS.proxy_args().ping_threshold;
    let bypass_ipset = OPTIONS.proxy_args().bypass_ipset.clone();
    let nobypass_ipset = OPTIONS.proxy_args().no_bypass_ipset.clone();
    let (req_sender, req_receiver) = mpsc::unbounded_channel();
    let (resp_sender, mut resp_receiver) = mpsc::unbounded_channel();
    let (ipset_sender, ipset_receiver) = mpsc::unbounded_channel();
    spawn(start_check_routine(
        req_receiver,
        resp_sender,
        ipset_receiver,
        bypass_ipset,
        nobypass_ipset,
    ));

    let mut request = BytesMut::new();
    let addr = SocketAddr::V4(SocketAddrV4::new(0.into(), 0));
    TrojanRequest::generate(&mut request, proto::PING, &addr);

    let mut set = HashMap::<IpAddr, PingResult>::new();

    let remote = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await?;
    let session = ClientConnection::new(config.clone(), server_name.clone())?;
    let remote = TlsClientStream::new(remote, session);
    let (mut reader, mut writer) = remote.into_split();

    let mut send_buffer = BytesMut::new();
    let mut next_check = Instant::now();

    let (remote_resp_sender, mut remote_resp_receiver) = mpsc::unbounded_channel();
    let mut reconnect = writer.write_all(request.as_ref()).await.is_err();
    if !reconnect {
        spawn(start_remote_response(reader, remote_resp_sender));
    } else {
        let _ = writer.shutdown().await;
    }
    loop {
        let ret = tokio::select! {
            ret = receiver.recv() => {
                SelectReturn::Request(ret)
            },
            ret = resp_receiver.recv() => {
                SelectReturn::LocalResponse(ret)
            }
            ret = remote_resp_receiver.recv() => {
                SelectReturn::RemoteResponse(ret)
            }
        };
        match ret {
            SelectReturn::LocalResponse(resp) => {
                let (ip, ping, lost) = resp.unwrap();
                if let Some(pr) = set.get_mut(&ip) {
                    pr.local_lost = lost.min(u8::MAX - 1);
                    pr.local_ping = ping.min(u16::MAX - 1);
                } else {
                    log::error!("ip:{} not found in set", ip);
                }
            }
            SelectReturn::RemoteResponse(resp) => {
                let (ip, ping, lost) = resp.unwrap();
                if ip.is_unspecified() && ping == 0 && lost == 0 {
                    log::error!("remote server connection is closed, reconnect now");
                    reconnect = true;
                } else {
                    if let Some(pr) = set.get_mut(&ip) {
                        pr.remote_lost = lost.min(u8::MAX - 1);
                        pr.remote_ping = ping.min(u16::MAX - 1);
                    } else {
                        log::error!("ip:{} not found in set", ip);
                    }
                }
            }
            SelectReturn::Request(req) => {
                let ip = req.unwrap();
                if let Some(pr) = set.get(&ip) {
                    if pr.is_no_bypass() || pr.last_time.elapsed() < timeout {
                        continue;
                    }
                }

                match ip {
                    IpAddr::V4(ip) => {
                        send_buffer.put_u8(proto::IPV4);
                        send_buffer.extend_from_slice(ip.octets().as_slice());
                    }
                    IpAddr::V6(ip) => {
                        send_buffer.put_u8(proto::IPV6);
                        send_buffer.extend_from_slice(ip.octets().as_slice());
                    }
                }

                if writer.write_all(send_buffer.as_ref()).await.is_err() {
                    log::error!("send ping request to server failed, reconnect now");
                    reconnect = true;
                }

                if let Err(err) = req_sender.send(ip) {
                    log::error!("send ip:{} to check routine failed:{}", ip, err);
                } else {
                    let pr = set.entry(ip).or_default();
                    pr.last_time = Instant::now();
                    pr.sent = false;
                }
            }
        }

        if reconnect {
            let _ = writer.shutdown().await;
            if let Ok(remote) = TcpStream::connect(OPTIONS.back_addr.as_ref().unwrap()).await {
                let session = ClientConnection::new(config.clone(), server_name.clone())?;
                let remote = TlsClientStream::new(remote, session);
                (reader, writer) = remote.into_split();
                reconnect = writer.write_all(request.as_ref()).await.is_err();
                if !reconnect {
                    let (sender, receiver) = mpsc::unbounded_channel();
                    remote_resp_receiver = receiver;
                    spawn(start_remote_response(reader, sender));
                } else {
                    log::error!("reconnect send handshake to remote ping server failed");
                    let _ = writer.shutdown().await;
                }
            } else {
                log::error!("reconnect to remote ping server failed");
            }
        }

        if ret.is_request() {
            continue;
        }

        let cond = CONDITION.read();
        if cond.is_err() {
            continue;
        }

        let cond: Condition = cond.unwrap().clone();

        let mut ips1 = Vec::new();
        let mut ips0 = Vec::new();
        for (key, group) in &set.iter().group_by(|(_ip, pr)| {
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
            let _ = sender.send(*ip);
            set.get_mut(ip).unwrap().last_time = Instant::now();
        });

        ips1.iter().for_each(|ip| {
            let pr = set.get_mut(ip).unwrap();
            pr.sent = true;
            let mut bypass = false;
            let proxy_ping = cond.ping + pr.remote_ping;
            let proxy_lost =
                100 - ((100.0 - cond.lost as f32) * (100.0 - pr.remote_lost as f32) / 100.0) as u8;

            // Blocked ip may be faked, so the ping value may be good. This is the case we should exclude first.
            if pr.remote_ping < ping_threshold && pr.local_ping < ping_threshold {
                bypass = false;
            } else {
                if pr.local_ping < proxy_ping + 5 && pr.local_lost < proxy_lost + 2 {
                    bypass = true;
                }
            }


            if let Err(err) = ipset_sender.send((ip.clone(), bypass)) {
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

        let mut now = Instant::now();
        if next_check < now {
            now += timeout;
            let mut ips = Vec::new();
            for (k, v) in &set {
                if v.is_no_bypass() {
                    continue;
                }
                let due_time = v.last_time + timeout;
                if due_time <= next_check {
                    ips.push(k.clone());
                } else if next_check > due_time {
                    next_check = due_time;
                }
            }
            next_check = now;
            for ip in ips {
                let _ = sender.send(ip);
            }
        }
    }
}

async fn start_remote_response(
    mut reader: TlsClientReadHalf,
    sender: UnboundedSender<(IpAddr, u16, u8)>,
) -> types::Result<()> {
    log::error!("remote check routine started");
    let mut recv_buffer = BytesMut::new();
    loop {
        match reader.read_buf(&mut recv_buffer).await {
            Ok(0) | Err(_) => {
                let _ = sender.send((IpAddr::V4(Ipv4Addr::from(0u32)), 0u16, 0u8));
                break;
            }
            Ok(n) => {
                log::info!("get {} bytes from remote", n);
            }
        }
        while !recv_buffer.is_empty() {
            let resp = match recv_buffer.as_ref()[0] {
                proto::IPV4 => {
                    if recv_buffer.len() < 8 {
                        break;
                    }
                    let mut octets = [0u8; 4];
                    octets.copy_from_slice(&recv_buffer.as_ref()[1..5]);
                    recv_buffer.advance(5);
                    let ping = recv_buffer.get_u16();
                    let lost = recv_buffer.get_u8();
                    let ip = Ipv4Addr::from(octets);
                    (ip.into(), ping, lost)
                }
                proto::IPV6 => {
                    if recv_buffer.len() < 20 {
                        break;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&recv_buffer.as_ref()[1..17]);
                    recv_buffer.advance(17);
                    let ping = recv_buffer.get_u16();
                    let lost = recv_buffer.get_u8();
                    let ip = Ipv6Addr::from(octets);
                    (ip.into(), ping, lost)
                }
                _ => unreachable!("invalid address type:{}", recv_buffer.as_ref()[0]),
            };
            let _ = sender.send(resp);
            log::info!("get remote response:{:?}", resp);
        }
    }
    log::error!("remote check routine exit");
    Ok(())
}
