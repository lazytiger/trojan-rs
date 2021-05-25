use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    thread::sleep,
    time::{Duration, Instant},
};

use clap::Clap;
use crypto::{digest::Digest, sha2::Sha224};
use trust_dns_resolver::Resolver;

pub struct DnsEntry {
    pub address: IpAddr,
    pub expired_time: Instant,
}

#[derive(Clap)]
#[clap(
    version = "0.6",
    author = "Hoping White",
    about = "A trojan implementation using rust"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub mode: Mode,
    #[clap(short, long, help = "log file path")]
    pub log_file: Option<String>,
    #[clap(
        short = "a",
        long,
        help = "listen address for server, format like 0.0.0.0:443"
    )]
    pub local_addr: String,
    #[clap(short, long, help = "passwords for negotiation")]
    password: String,
    #[clap(
        short = "L",
        long,
        default_value = "2",
        help = "log level, 0 for trace, 1 for debug, 2 for info, 3 for warning, 4 for error, 5 for off"
    )]
    pub log_level: u8,
    #[clap(short, long, default_value = "1", help = "set marker used by tproxy")]
    pub marker: u8,
    #[clap(
        short,
        long,
        default_value = "60",
        help = "time in seconds before closing an inactive udp connection"
    )]
    pub udp_idle_timeout: u64,
    #[clap(
        short,
        long,
        default_value = "600",
        help = "time in seconds before closing an inactive tcp connection"
    )]
    pub tcp_idle_timeout: u64,
    #[clap(skip)]
    dns_cache_duration: Duration,
    #[clap(skip)]
    sha_pass: String,
    #[clap(skip)]
    pub pass_len: usize,
    #[clap(skip)]
    pub back_addr: Option<SocketAddr>,
    #[clap(skip)]
    pub dns_cache: HashMap<String, DnsEntry>,
    #[clap(skip)]
    pub udp_header_len: usize,
    #[clap(skip)]
    pub empty_addr: Option<SocketAddr>,
    #[clap(skip)]
    pub udp_idle_duration: Duration,
    #[clap(skip)]
    pub tcp_idle_duration: Duration,
}

#[derive(Clap)]
pub enum Mode {
    #[clap(name = "proxy", about = "run in proxy mode")]
    Proxy(ProxyArgs),
    #[clap(name = "server", about = "run in server mode")]
    Server(ServerArgs),
}

#[derive(Clap)]
pub struct ProxyArgs {
    #[clap(short = "H", long, help = "trojan server hostname")]
    pub hostname: String,
    #[clap(short = "o", long, default_value = "443", help = "trojan server port")]
    pub port: u16,
    #[clap(
        short = "P",
        long,
        default_value = "0",
        help = "pool size, 0 for disable"
    )]
    pub pool_size: usize,
}

#[derive(Clap)]
pub struct ServerArgs {
    #[clap(
        short,
        long,
        help = "certificate file path, This should contain PEM-format certificates in the right order (the first certificate should certify KEYFILE, the last should be a root CA"
    )]
    pub cert: String,
    #[clap(
        short,
        long,
        help = "private key file path,  This should be a RSA private key or PKCS8-encoded private key, in PEM format."
    )]
    pub key: String,
    #[clap(
        short,
        long,
        default_value = "127.0.0.1:80",
        help = "http backend server address"
    )]
    pub remote_addr: String,
    #[clap(
        short,
        long,
        default_value = "300",
        help = "time in seconds for dns query cache"
    )]
    dns_cache_time: u64,
    #[clap(short = "n", long, help = "alpn protocol supported")]
    pub alpn: Vec<String>,
}

impl Opts {
    pub fn server_args(&self) -> &ServerArgs {
        match self.mode {
            Mode::Server(ref args) => args,
            _ => panic!("not in server mode"),
        }
    }

    pub fn proxy_args(&self) -> &ProxyArgs {
        match self.mode {
            Mode::Proxy(ref args) => args,
            _ => panic!("not in proxy mode"),
        }
    }

    pub fn setup(&mut self) {
        match self.mode {
            Mode::Server(ref args) => {
                let back_addr: SocketAddr = args.remote_addr.parse().unwrap();
                self.back_addr = Some(back_addr);
                self.dns_cache_duration = Duration::new(args.dns_cache_time, 0);
            }
            Mode::Proxy(ref args) => {
                let mut hostname = args.hostname.clone();
                if !hostname.ends_with('.') {
                    hostname.push('.');
                }
                let resolver = Resolver::from_system_conf().unwrap();
                for i in 0..10 {
                    if let Ok(response) = resolver.lookup_ip(hostname.as_str()) {
                        for ip in response.iter() {
                            if ip.is_ipv4() {
                                self.back_addr.replace(SocketAddr::new(ip, args.port));
                                break;
                            } else if self.back_addr.is_none() {
                                self.back_addr.replace(SocketAddr::new(ip, args.port));
                            }
                        }
                    }
                    if self.back_addr.is_none() {
                        sleep(Duration::new(i + 1, 0));
                    } else {
                        break;
                    }
                }
                if self.back_addr.is_none() {
                    panic!("resolve host {} failed", hostname);
                }

                log::info!("server address is {}", self.back_addr.as_ref().unwrap());
            }
        }
        let empty_addr = if self.back_addr.as_ref().unwrap().is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        self.empty_addr.replace(empty_addr);
        self.udp_idle_duration = Duration::new(self.udp_idle_timeout, 0);
        self.tcp_idle_duration = Duration::new(self.tcp_idle_timeout, 0);
        self.digest_pass();
    }

    fn digest_pass(&mut self) {
        let mut encoder = Sha224::new();
        encoder.reset();
        encoder.input(self.password.as_bytes());
        let result = encoder.result_str();
        self.pass_len = result.len();
        log::info!(
            "sha224({}) = {}, length = {}",
            self.password,
            result,
            self.pass_len
        );
        self.sha_pass = result;
    }

    pub fn check_pass(&self, pass: &str) -> Option<&String> {
        if self.sha_pass.eq(pass) {
            Some(&self.password)
        } else {
            None
        }
    }

    pub fn get_pass(&self) -> &String {
        &self.sha_pass
    }

    pub fn update_dns(&mut self, domain: String, address: IpAddr) {
        log::trace!("update dns cache, {} = {}", domain, address);
        let expired_time = Instant::now() + self.dns_cache_duration;
        self.dns_cache.insert(
            domain,
            DnsEntry {
                address,
                expired_time,
            },
        );
    }

    pub fn query_dns(&mut self, domain: &str) -> Option<IpAddr> {
        if let Some(entry) = self.dns_cache.get(domain) {
            log::debug!("found {} = {} in dns cache", domain, entry.address);
            if entry.expired_time > Instant::now() {
                return Some(entry.address);
            } else {
                log::info!("domain {} expired, remove from cache", domain);
                let _ = self.dns_cache.remove(domain);
            }
        }
        None
    }
}

pub fn setup_logger(logfile: &Option<String>, level: u8) {
    let level = match level {
        0x00 => log::LevelFilter::Trace,
        0x01 => log::LevelFilter::Debug,
        0x02 => log::LevelFilter::Info,
        0x03 => log::LevelFilter::Warn,
        0x04 => log::LevelFilter::Error,
        _ => log::LevelFilter::Off,
    };
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}:{}][{}]{}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.6f]"),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                message
            ))
        })
        .level(level);
    if logfile.is_some() {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let path = std::path::Path::new(logfile.as_ref().unwrap().as_str());
                builder = builder.chain(fern::log_reopen(path, Some(libc::SIGUSR2)).unwrap());
            } else {
                builder = builder.chain(fern::log_file(logfile.as_ref().unwrap()).unwrap());
            }
        }
    } else {
        builder = builder.chain(std::io::stdout());
    }
    builder.apply().unwrap();
}
