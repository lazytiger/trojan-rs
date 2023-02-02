use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    thread,
    time::Duration,
};

use bytes::{Buf, BufMut, BytesMut};
use mio::Poll;
use surge_ping::{Client, ConfigBuilder, PingIdentifier, PingSequence, ICMP};
use tokio::{
    runtime::Builder,
    sync::{
        mpsc,
        mpsc::{UnboundedReceiver, UnboundedSender},
    },
};

use crate::{
    proto,
    server::{stat::Statistics, tls_server::Backend},
    status::{ConnStatus, StatusProvider},
    tls_conn::TlsConn,
};

pub struct PingResult {
    ip: IpAddr,
    lost: u8,
    ping: u16,
}

pub struct PingBackend {
    status: ConnStatus,
    recv_buffer: BytesMut,
    send_buffer: BytesMut,
    timeout: Duration,
    req_sender: UnboundedSender<IpAddr>,
    resp_receiver: UnboundedReceiver<PingResult>,
}

impl PingBackend {
    pub fn new() -> PingBackend {
        let (req_sender, req_receiver) = mpsc::unbounded_channel();
        let (resp_sender, resp_receiver) = mpsc::unbounded_channel();
        thread::spawn(|| {
            let runtime = Builder::new_multi_thread().enable_all().build().unwrap();
            runtime.block_on(start_check_routine(req_receiver, resp_sender));
            log::info!("check thread stopped");
        });
        Self {
            send_buffer: Default::default(),
            recv_buffer: Default::default(),
            status: ConnStatus::Established,
            timeout: Duration::from_secs(u64::MAX),
            req_sender,
            resp_receiver,
        }
    }
}

async fn start_check_routine(
    mut receiver: UnboundedReceiver<IpAddr>,
    sender: UnboundedSender<PingResult>,
) {
    let config = ConfigBuilder::default().kind(ICMP::V4).build();
    let client4 = Arc::new(Client::new(&config).unwrap());
    let config = ConfigBuilder::default().kind(ICMP::V6).build();
    let client6 = Arc::new(Client::new(&config).unwrap());
    let mut id = 0u16;
    while let Some(ip) = receiver.recv().await {
        if ip.is_unspecified() {
            log::error!("closing check routine now");
            receiver.close();
            break;
        }
        let client = match ip {
            IpAddr::V4(_) => client4.clone(),
            IpAddr::V6(_) => client6.clone(),
        };
        tokio::spawn(do_check(ip, id, client.clone(), sender.clone()));
        id = id.wrapping_add(1);
    }
}

async fn do_check(ip: IpAddr, id: u16, client: Arc<Client>, sender: UnboundedSender<PingResult>) {
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
    if let Err(err) = sender.send(PingResult {
        ip,
        lost: lost_ratio,
        ping: avg_cost as u16,
    }) {
        log::error!("send result failed:{}", err);
    }
}

impl Backend for PingBackend {
    fn dispatch(&mut self, data: &[u8], _stats: &mut Statistics) {
        self.recv_buffer.extend_from_slice(data);
        while !self.recv_buffer.is_empty() {
            let addr: IpAddr = match self.recv_buffer.as_ref()[0] {
                proto::IPV4 => {
                    if self.recv_buffer.len() < 5 {
                        break;
                    }
                    let mut data = [0u8; 4];
                    data.copy_from_slice(&self.recv_buffer.as_ref()[1..5]);
                    self.recv_buffer.advance(5);
                    Ipv4Addr::from(data).into()
                }
                proto::IPV6 => {
                    if self.recv_buffer.len() < 17 {
                        break;
                    }
                    let mut data = [0u8; 16];
                    data.copy_from_slice(&self.recv_buffer.as_ref()[1..17]);
                    self.recv_buffer.advance(17);
                    Ipv6Addr::from(data).into()
                }
                _ => {
                    self.shutdown();
                    break;
                }
            };
            if addr.is_unspecified() {
                log::error!("invalid request, unspecified address found");
                self.shutdown();
                break;
            }
            if let Err(err) = self.req_sender.send(addr) {
                log::error!("send req_sender failed:{}", err);
                self.shutdown();
                break;
            }
        }
    }

    fn get_timeout(&self) -> Duration {
        self.timeout
    }

    fn writable(&self) -> bool {
        self.alive()
    }

    fn do_read(&mut self, conn: &mut TlsConn, _stats: &mut Statistics) {
        while let Ok(pr) = self.resp_receiver.try_recv() {
            match pr.ip {
                IpAddr::V4(ip) => {
                    self.send_buffer.put_u8(proto::IPV4);
                    self.send_buffer.extend_from_slice(ip.octets().as_slice());
                }
                IpAddr::V6(ip) => {
                    self.send_buffer.put_u8(proto::IPV6);
                    self.send_buffer.extend_from_slice(ip.octets().as_slice())
                }
            };
            self.send_buffer.put_u16(pr.ping);
            self.send_buffer.put_u8(pr.lost);
        }
        if self.send_buffer.is_empty() {
            return;
        }
        let data = self.send_buffer.split();
        if !conn.write_session(data.as_ref()) {
            self.set_status(ConnStatus::PeerClosed);
        }
    }

    fn dst_ip(&self) -> Option<IpAddr> {
        None
    }
}

impl StatusProvider for PingBackend {
    fn set_status(&mut self, status: ConnStatus) {
        if matches!(status, ConnStatus::Shutdown) {
            if let Err(err) = self.req_sender.send(Ipv4Addr::new(0, 0, 0, 0).into()) {
                log::error!("stop sender failed:{}", err);
            }
            self.resp_receiver.close();
        }
        self.status = status;
    }

    fn get_status(&self) -> ConnStatus {
        self.status
    }

    fn close_conn(&mut self) -> bool {
        true
    }

    fn deregister(&mut self, _poll: &Poll) -> bool {
        true
    }

    fn finish_send(&mut self) -> bool {
        self.send_buffer.is_empty()
    }
}
