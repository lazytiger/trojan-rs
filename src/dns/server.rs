use crate::{
    dns::{
        adapter::get_adapter_ip, add_route_with_gw, domain::DomainMap, DNS_LOCAL, DNS_POISONED,
        DNS_TRUSTED,
    },
    proto::MAX_PACKET_SIZE,
    OPTIONS,
};
use crossbeam::channel::{unbounded, Sender};
use itertools::Itertools;
use mio::{event::Event, net::UdpSocket, Interest, Poll, Token};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, ErrorKind},
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant},
};
use trust_dns_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{DNSClass, Name, RData, Record, RecordType},
    serialize::binary::BinDecodable,
};

pub struct DnsServer {
    listener: UdpSocket,
    trusted: UdpSocket,
    poisoned: UdpSocket,
    buffer: Vec<u8>,
    arp_data: Vec<u8>,
    blocked_domains: DomainMap,
    store: HashMap<String, QueryResult>,
    sender: Sender<String>,
    ptr_name: String,
}

struct QueryResult {
    addresses: Vec<SocketAddr>,
    response: Vec<u8>,
    expire_time: Instant,
}

impl DnsServer {
    pub fn new() -> Self {
        let default_addr = "0.0.0.0:0".to_owned();
        let gateway = get_adapter_ip(OPTIONS.dns_args().tun_name.as_str()).unwrap();
        add_route_with_gw(
            OPTIONS.dns_args().trusted_dns.as_str(),
            "255.255.255.255",
            gateway.as_str(),
        );
        let (sender, receiver) = unbounded::<String>();
        let _ = std::thread::spawn(move || {
            log::debug!("add route started");
            while let Ok(ip) = receiver.recv() {
                add_route_with_gw(ip.as_str(), "255.255.255.255", gateway.as_str());
                log::info!("add ip {} to route table", ip);
            }
            log::error!("add route quit");
        });

        Self {
            sender,
            listener: UdpSocket::bind(
                OPTIONS
                    .dns_args()
                    .dns_listen_address
                    .as_str()
                    .parse()
                    .unwrap(),
            )
            .unwrap(),
            trusted: UdpSocket::bind(default_addr.as_str().parse().unwrap()).unwrap(),
            poisoned: UdpSocket::bind(default_addr.as_str().parse().unwrap()).unwrap(),
            buffer: vec![0; MAX_PACKET_SIZE],
            blocked_domains: DomainMap::new(),
            arp_data: vec![],
            store: HashMap::new(),
            ptr_name: String::new(),
        }
    }

    pub fn setup(&mut self, poll: &Poll) {
        let trusted_dns = OPTIONS.dns_args().trusted_dns.clone() + ":53";
        let poisoned_dns = OPTIONS.dns_args().poisoned_dns.clone() + ":53";
        self.trusted
            .connect(trusted_dns.as_str().parse().unwrap())
            .unwrap();
        self.poisoned
            .connect(poisoned_dns.as_str().parse().unwrap())
            .unwrap();
        poll.registry()
            .register(&mut self.trusted, Token(DNS_TRUSTED), Interest::READABLE)
            .unwrap();
        poll.registry()
            .register(&mut self.poisoned, Token(DNS_POISONED), Interest::READABLE)
            .unwrap();
        poll.registry()
            .register(&mut self.listener, Token(DNS_LOCAL), Interest::READABLE)
            .unwrap();

        let mut domain_map = DomainMap::new();
        let file = File::open(OPTIONS.dns_args().blocked_domain_list.as_str()).unwrap();
        let reader = BufReader::new(file);
        reader.lines().for_each(|line| {
            if let Ok(line) = line {
                domain_map.add_domain(line.as_str());
            }
        });

        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        message.set_id(1);
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_response_code(ResponseCode::NoError);
        let mut query = Query::new();
        let address: String = self
            .listener
            .local_addr()
            .unwrap()
            .ip()
            .to_string()
            .split('.')
            .rev()
            .join(".");
        let name = address + ".in-addr.arpa.";
        self.ptr_name = name.clone();
        let name = Name::from_str(name.as_str()).unwrap();
        query.set_name(name.clone());
        query.set_query_type(RecordType::PTR);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        let mut record = Record::new();
        record.set_name(name);
        record.set_record_type(RecordType::PTR);
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(20567);
        record.set_rdata(RData::PTR(Name::from_str("trojan.dns").unwrap()));
        message.add_answer(record);
        self.arp_data = message.to_vec().unwrap();
    }

    pub fn ready(&mut self, event: &Event, poll: &Poll) {
        match event.token() {
            Token(DNS_LOCAL) => {
                self.dispatch_local(poll);
            }
            Token(DNS_TRUSTED) => {
                self.dispatch_trusted(poll);
            }
            Token(DNS_POISONED) => {
                self.dispatch_poisoned(poll);
            }
            _ => unreachable!(),
        }
    }

    fn dispatch_local(&mut self, poll: &Poll) {
        let now = Instant::now();
        loop {
            match self.listener.recv_from(self.buffer.as_mut_slice()) {
                Ok((length, from)) => {
                    let data = &self.buffer.as_slice()[..length];
                    if let Ok(message) = Message::from_bytes(data) {
                        if message.query_count() == 1 {
                            let query = &message.queries()[0];
                            let name = query.name().to_utf8();
                            if query.query_type() == RecordType::PTR && name == self.ptr_name {
                                log::debug!("found ptr query");
                                if let Err(err) =
                                    self.listener.send_to(self.arp_data.as_slice(), from)
                                {
                                    log::error!("send response to {} failed:{}", from, err);
                                }
                                continue;
                            }
                            log::debug!("found query for:{}", name);
                            let key = Self::get_message_key(&message);
                            if let Some(result) = self.store.get(&key) {
                                if !result.response.is_empty() && result.expire_time > now {
                                    log::debug!("query found in cache, send now");
                                    if let Err(err) =
                                        self.listener.send_to(result.response.as_slice(), from)
                                    {
                                        log::error!("send response to {} failed:{}", from, err);
                                    }
                                    continue;
                                }
                            }
                            if self.is_blocked(&name) {
                                self.trusted.send(data).unwrap();
                                log::info!("domain:{} is blocked", name);
                            } else {
                                log::info!("domain:{} is not blocked", name);
                                self.poisoned.send(data).unwrap();
                            }
                            self.add_request(key, from);
                        } else {
                            log::error!(
                                "query count:{} found in message:{:?}",
                                message.query_count(),
                                message
                            );
                        }
                    } else {
                        log::error!("invalid request message received from {}", from);
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    log::error!("dns request recv failed:{}", err);
                    poll.registry()
                        .reregister(&mut self.listener, Token(DNS_LOCAL), Interest::READABLE)
                        .unwrap();
                    break;
                }
            }
        }
    }

    fn get_message_key(message: &Message) -> String {
        let query = &message.queries()[0];
        let name = query.name().to_utf8();
        name + "|" + query.query_type().to_string().as_str()
    }

    fn dispatch_server(
        recv_socket: &UdpSocket,
        send_socket: &UdpSocket,
        buffer: &mut [u8],
        store: &mut HashMap<String, QueryResult>,
        sender: &Sender<String>,
    ) -> bool {
        let now = Instant::now();
        loop {
            match recv_socket.recv_from(buffer) {
                Ok((length, from)) => {
                    let data = &buffer[..length];
                    if let Ok(message) = Message::from_bytes(data) {
                        let name = Self::get_message_key(&message);
                        if let Some(result) = store.get_mut(&name) {
                            for address in &result.addresses {
                                if let Err(err) = send_socket.send_to(data, *address) {
                                    log::error!("send to {} failed:{}", address, err);
                                } else {
                                    log::debug!("send response to {}", address);
                                }
                            }
                            let mut timeout = 0;
                            for record in message.answers() {
                                timeout = record.ttl();
                                if let Some(addr) = record.rdata().to_ip_addr() {
                                    if let Err(err) = sender.try_send(addr.to_string()) {
                                        log::error!("send to add route thread failed:{}", err);
                                    } else {
                                        log::debug!(
                                            "got response {} -> {}, expire in {} seconds",
                                            name,
                                            addr,
                                            timeout,
                                        );
                                    }
                                }
                            }
                            result.expire_time = now + Duration::new(timeout as u64, 0);
                            result.addresses.clear();
                            result.response.clear();
                            result.response.extend_from_slice(data);
                        } else {
                            log::error!("key:{} not found in store", name);
                        }
                    } else {
                        log::error!("invalid response message received from {}", from);
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => {
                    log::error!(
                        "dns response from:{:?} recv failed:{}",
                        recv_socket.local_addr(),
                        err
                    );
                    return false;
                }
            }
        }
        true
    }

    fn dispatch_trusted(&mut self, poll: &Poll) {
        if !Self::dispatch_server(
            &self.trusted,
            &self.listener,
            self.buffer.as_mut_slice(),
            &mut self.store,
            &self.sender,
        ) {
            poll.registry()
                .reregister(&mut self.trusted, Token(DNS_TRUSTED), Interest::READABLE)
                .unwrap();
        }
    }

    fn dispatch_poisoned(&mut self, poll: &Poll) {
        if !Self::dispatch_server(
            &self.poisoned,
            &self.listener,
            self.buffer.as_mut_slice(),
            &mut self.store,
            &self.sender,
        ) {
            poll.registry()
                .reregister(&mut self.poisoned, Token(DNS_POISONED), Interest::READABLE)
                .unwrap();
        }
    }

    fn is_blocked(&self, name: &String) -> bool {
        self.blocked_domains.contains(name.as_str())
    }
    fn add_request(&mut self, name: String, address: SocketAddr) {
        let result = if let Some(result) = self.store.get_mut(&name) {
            result
        } else {
            self.store.insert(
                name.clone(),
                QueryResult {
                    addresses: vec![],
                    response: vec![],
                    expire_time: Instant::now()
                        + Duration::new(OPTIONS.dns_args().dns_cache_time, 0),
                },
            );
            self.store.get_mut(&name).unwrap()
        };
        result.addresses.push(address);
    }
}
