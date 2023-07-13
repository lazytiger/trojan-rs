use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    thread::sleep,
    time::Duration,
};

use clap::Parser;
use sha2::{Digest, Sha224};

use crate::{
    types::TrojanError,
    utils::{get_system_dns, resolve},
};

#[derive(Parser)]
#[clap(
    version,
    author = "Hoping White",
    about = "A trojan implementation using rust"
)]
pub struct Opts {
    #[clap(subcommand)]
    pub mode: Mode,

    /// Log file path
    #[clap(short, long, default_value = "")]
    pub log_file: String,

    /// Listen address for server, format like 0.0.0.0:443
    #[clap(short = 'a', long)]
    pub local_addr: String,

    /// passwords for negotiation
    #[clap(short, long)]
    pub password: String,

    /// Log level, 0 for trace, 1 for debug, 2 for info, 3 for warning, 4 for error, 5 for off
    #[clap(short = 'L', long, default_value = "2")]
    pub log_level: u8,

    /// Time in seconds before closing an inactive udp connection
    #[clap(short, long, default_value = "60")]
    pub udp_idle_timeout: u64,

    /// Time in seconds before closing an inactive tcp connection
    #[clap(short, long, default_value = "600")]
    pub tcp_idle_timeout: u64,

    #[clap(skip)]
    sha_pass: String,
    #[clap(skip)]
    pub system_dns: String,
    #[clap(skip)]
    pub pass_len: usize,
    #[clap(skip)]
    pub back_addr: Option<SocketAddr>,
    #[clap(skip)]
    pub udp_header_len: usize,
    #[clap(skip)]
    pub empty_addr: Option<SocketAddr>,
    #[clap(skip)]
    pub udp_idle_duration: Duration,
    #[clap(skip)]
    pub tcp_idle_duration: Duration,
}

#[derive(Parser)]
pub enum Mode {
    #[clap(version, name = "proxy", about = "run in synchronous proxy mode")]
    Proxy(ProxyArgs),
    #[clap(version, name = "aproxy", about = "run in asynchronous proxy mode")]
    Aproxy(ProxyArgs),
    #[clap(version, name = "server", about = "run in synchronous server mode")]
    Server(ServerArgs),
    #[clap(version, name = "aserver", about = "run in asynchronous server mode")]
    Aserver(ServerArgs),
    #[clap(
        version,
        name = "wintun",
        about = "run in synchronous windows tun mode"
    )]
    Wintun(WintunArgs),
    #[clap(
        version,
        name = "awintun",
        about = "run in asynchronous windows tun mode"
    )]
    Awintun(WintunArgs),
    #[clap(version, name = "dns", about = "run in dns mode")]
    Dns(DnsArgs),
}

#[derive(Parser, Debug)]
pub struct WintunArgs {
    /// Native wintun.dll file location
    #[clap(short, long, default_value = "wintun/bin/amd64/wintun.dll")]
    pub wintun: String,

    /// Tunnel device name
    #[clap(short, long)]
    pub name: String,

    /// status file for speed
    #[clap(short, long, default_value = "logs\\wintun.status")]
    pub status_file: String,

    /// Max packet count in buffer for network
    #[clap(short, long, default_value = "1024000")]
    pub buffer_size: usize,

    /// Trojan server hostname
    #[clap(short = 'H', long)]
    pub hostname: String,

    /// Trojan server port
    #[clap(short = 'o', long, default_value = "443")]
    pub port: u16,

    /// Pool size, 0 for disable
    #[clap(short = 'P', long, default_value = "0")]
    pub pool_size: usize,

    /// Maximum transmit unit
    #[clap(short, long, default_value = "1500")]
    pub mtu: usize,

    /// Metadata size for UDP RX buffer
    #[clap(long, default_value = "200")]
    pub udp_rx_meta_size: usize,

    /// Data size for UDP RX buffer
    #[clap(long, default_value = "10240")]
    pub udp_rx_buffer_size: usize,

    /// Metadata size for UDP TX buffer
    #[clap(long, default_value = "10000")]
    pub udp_tx_meta_size: usize,

    /// Data size for UDP TX buffer
    #[clap(long, default_value = "1024000")]
    pub udp_tx_buffer_size: usize,

    /// Data size for TCP RX buffer
    #[clap(long, default_value = "102400")]
    pub tcp_rx_buffer_size: usize,

    /// Data size for TCP TX buffer
    #[clap(long, default_value = "102400")]
    pub tcp_tx_buffer_size: usize,

    /// Ip set in CIDR format to route through this tunnel
    #[clap(long)]
    pub route_ipset: Option<String>,

    /// Should reverse the ipset
    #[clap(long)]
    pub inverse_route: bool,

    /// DNS server address used for query trojan server ip
    #[clap(long)]
    pub dns_server_addr: Option<String>,
}

#[derive(Parser)]
pub struct ProxyArgs {
    /// Trojan server hostname
    #[clap(short = 'H', long)]
    pub hostname: String,

    /// Trojan server port
    #[clap(short = 'o', long, default_value = "443")]
    pub port: u16,

    /// Pool size, 0 for disable
    #[clap(short = 'P', long, default_value = "0")]
    pub pool_size: usize,

    /// Enable bypass check
    #[clap(short = 'e', long, default_value = "false")]
    pub enable_bypass: bool,

    /// Bypass timeout for check server.
    #[clap(short = 't', long, default_value = "3600")]
    pub bypass_timeout: u64,

    /// ipset name which should not be bypassed.
    #[clap(short = 'n', long, default_value = "gfwlist")]
    pub no_bypass_ipset: String,

    /// bypass ipset name
    #[clap(short = 'i', long, default_value = "byplist")]
    pub bypass_ipset: String,

    /// ping time below this should be considered in proxy side
    #[clap(long, default_value = "70")]
    pub ping_threshold: u16,
}

#[derive(Parser)]
pub struct DnsArgs {
    /// Tunnel name used for transparent proxy
    #[clap(short = 'n', long)]
    pub tun_name: String,

    /// Domain list which should be resolved through safe DNS
    #[clap(long, default_value = "ipset/domain.txt")]
    pub blocked_domain_list: String,

    /// Listen address for DNS server, like 127.0.0.1:53
    #[clap(long, default_value = "127.0.0.1:53")]
    pub dns_listen_address: String,

    /// Trusted DNS server
    #[clap(long, default_value = "8.8.8.8")]
    pub trusted_dns: String,

    /// Poisoned DNS server
    #[clap(long, default_value = "114.114.114.114")]
    pub poisoned_dns: String,

    /// DNS cache timeout
    #[clap(long, default_value = "600")]
    pub dns_cache_time: u64,

    /// Flag for adding route table for resolved IPs
    #[clap(long)]
    pub add_route: bool,

    /// Custom host file, like /etc/hosts
    #[clap(long)]
    pub hosts: String,
}

#[derive(Parser)]
pub struct ServerArgs {
    /// Certificate file path, This should contain PEM-format certificates in the right order (the first certificate should certify KEYFILE, the last should be a root CA
    #[clap(short, long)]
    pub cert: String,

    /// Private key file path,  This should be a RSA private key or PKCS8-encoded private key, in PEM format.
    #[clap(short, long)]
    pub key: String,

    /// Http backend server address
    #[clap(short, long, default_value = "127.0.0.1:80")]
    pub remote_addr: String,

    /// Time in seconds for dns query cache
    #[clap(short, long, default_value = "300")]
    pub dns_cache_time: u64,

    /// Check client auth
    #[clap(short, long)]
    pub check_auth: bool,

    #[clap(short, long, default_value = "/var/log/trojan.status")]
    pub status_file: String,

    #[clap(short = 'm', long, default_value = "100")]
    pub status_limit: usize,

    /// ALPN protocol supported
    #[clap(short = 'n', long)]
    pub alpn: Vec<String>,

    /// Disable udp hole punch, if enabled, a udp packet from remote will be discarded if no packet send
    /// from this socket before or at least 30 seconds before.
    #[clap(short = 'D', long)]
    pub disable_udp_hole: bool,

    /// Timeout for cached result.
    #[clap(long, default_value = "600")]
    pub cached_ping_timeout: u64,
}

impl Opts {
    pub fn server_args(&self) -> &ServerArgs {
        match self.mode {
            Mode::Server(ref args) | Mode::Aserver(ref args) => args,
            _ => panic!("not in server mode"),
        }
    }

    pub fn proxy_args(&self) -> &ProxyArgs {
        match self.mode {
            Mode::Proxy(ref args) | Mode::Aproxy(ref args) => args,
            _ => panic!("not in proxy mode"),
        }
    }

    #[allow(dead_code)]
    pub fn wintun_args(&self) -> &WintunArgs {
        match self.mode {
            Mode::Wintun(ref args) | Mode::Awintun(ref args) => args,
            _ => panic!("not in wintun mode"),
        }
    }

    #[allow(dead_code)]
    pub fn dns_args(&self) -> &DnsArgs {
        match self.mode {
            Mode::Dns(ref args) => args,
            _ => panic!("not in dns mode"),
        }
    }

    fn resolve(&mut self, hostname: String, port: u16, dns_server: Option<&str>) {
        for i in 0..10 {
            if let Ok(response) = if let Some(dns_server) = dns_server {
                resolve(hostname.as_str(), dns_server)
            } else {
                dns_lookup::lookup_host(hostname.as_str()).map_err(|_| TrojanError::Dummy(()))
            } {
                for ip in response {
                    if ip.is_ipv4() {
                        self.back_addr.replace(SocketAddr::new(ip, port));
                        break;
                    } else if self.back_addr.is_none() {
                        self.back_addr.replace(SocketAddr::new(ip, port));
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

    pub fn setup(&mut self) {
        match self.mode {
            Mode::Server(ref args) | Mode::Aserver(ref args) => {
                let back_addr: SocketAddr = args.remote_addr.parse().unwrap();
                self.back_addr = Some(back_addr);
                self.system_dns = get_system_dns().unwrap_or("127.0.0.53".to_string())
            }
            Mode::Proxy(ref args) | Mode::Aproxy(ref args) => {
                let hostname = args.hostname.clone();
                let port = args.port;
                self.resolve(hostname, port, None);
            }
            Mode::Wintun(ref args) | Mode::Awintun(ref args) => {
                let hostname = args.hostname.clone();
                let port = args.port;
                let dns_server = args.dns_server_addr.clone();
                self.resolve(hostname, port, dns_server.as_deref());
            }
            Mode::Dns(_) => {}
        }
        if self.back_addr.is_some() {
            let empty_addr = if self.back_addr.as_ref().unwrap().is_ipv4() {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
            };
            self.empty_addr.replace(empty_addr);
        }
        self.udp_idle_duration = Duration::new(self.udp_idle_timeout, 0);
        self.tcp_idle_duration = Duration::new(self.tcp_idle_timeout, 0);
        self.digest_pass();
    }

    fn digest_pass(&mut self) {
        let mut encoder = Sha224::new();
        encoder.update(self.password.as_bytes());
        let result = encoder.finalize();
        let result = hex::encode(result.as_slice());
        self.pass_len = result.len();
        println!(
            "sha224({}) = {}, length = {}",
            self.password, result, self.pass_len
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
}

pub fn setup_logger(logfile: &str, level: u8) -> crate::types::Result<()> {
    let path = Path::new(logfile);
    if path.exists() {
        let mut suffix = 1;
        loop {
            let new_file = logfile.to_string() + "." + suffix.to_string().as_str();
            let path = Path::new(new_file.as_str());
            if !path.exists() {
                std::fs::rename(logfile, new_file.as_str())?;
                break;
            } else {
                suffix += 1;
            }
        }
    }
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
    if !logfile.is_empty() {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let path = std::path::Path::new(logfile);
                builder = builder.chain(fern::log_reopen(path, Some(libc::SIGUSR2)).unwrap());
            } else {
                builder = builder.chain(fern::log_file(logfile).unwrap());
            }
        }
    } else {
        builder = builder.chain(std::io::stdout());
    }
    builder.apply()?;
    Ok(())
}

lazy_static::lazy_static! {
    pub static ref OPTIONS:Opts = {
        let mut opts = Opts::parse();
        opts.setup();
        opts
    };
}
