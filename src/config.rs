use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    thread::sleep,
    time::Duration,
};

use clap::Parser;
use crypto::{digest::Digest, sha2::Sha224};

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
    #[clap(short, long)]
    pub log_file: Option<String>,

    /// Listen address for server, format like 0.0.0.0:443
    #[clap(short = 'a', long)]
    pub local_addr: String,

    /// passwords for negotiation
    #[clap(short, long)]
    password: String,

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
    #[clap(version, name = "proxy", about = "run in proxy mode")]
    Proxy(ProxyArgs),
    #[clap(version, name = "server", about = "run in server mode")]
    Server(ServerArgs),
    #[clap(version, name = "wintun", about = "run in windows tun mode")]
    Wintun(WintunArgs),
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
    #[clap(long, default_value = "1024000")]
    pub tcp_tx_buffer_size: usize,
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
}

#[derive(Parser)]
pub struct DnsArgs {
    /// Tunnel name used for transparent proxy
    #[clap(short = 'n', long)]
    pub tun_name: String,

    /// Add white ip list
    #[clap(long)]
    pub white_ip_list: Option<String>,

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

    /// ALPN protocol supported
    #[clap(short = 'n', long)]
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

    #[allow(dead_code)]
    pub fn wintun_args(&self) -> &WintunArgs {
        match self.mode {
            Mode::Wintun(ref args) => args,
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

    fn resolve(&mut self, hostname: String, port: u16) {
        for i in 0..10 {
            if let Ok(response) = dns_lookup::lookup_host(hostname.as_str()) {
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
            Mode::Server(ref args) => {
                let back_addr: SocketAddr = args.remote_addr.parse().unwrap();
                self.back_addr = Some(back_addr);
            }
            Mode::Proxy(ref args) => {
                let hostname = args.hostname.clone();
                let port = args.port;
                self.resolve(hostname, port);
            }
            Mode::Wintun(ref args) => {
                let hostname = args.hostname.clone();
                let port = args.port;
                self.resolve(hostname, port);
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

lazy_static::lazy_static! {
    pub static ref OPTIONS:Opts = {
        let mut opts = Opts::parse();
        opts.setup();
        opts
    };
}
