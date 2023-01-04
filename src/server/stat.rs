use std::{
    collections::{HashMap, HashSet},
    fs::OpenOptions,
    io::Write,
    net::IpAddr,
};

pub struct Statistics {
    conns: HashMap<IpAddr, TrafficData>,
}

#[derive(Default)]
struct TrafficData {
    tcp_rx: usize,
    tcp_tx: usize,
    udp_rx: usize,
    udp_tx: usize,
    sources: HashSet<IpAddr>,
}

impl TrafficData {
    fn all(&self) -> usize {
        self.tcp_rx + self.tcp_tx + self.udp_rx + self.udp_tx
    }
}

macro_rules! add {
    ($self:ident, $field:ident, $bytes:ident, $dst:ident, $source:ident) => {
        match $dst {
            Some(ip) => {
                if ip.is_loopback() {
                    return;
                }
            }
            None => return,
        }
        let data = $self.conns.entry($dst.unwrap()).or_default();
        if let Some(source) = $source {
            data.sources.insert(source);
        }
        data.$field += $bytes;
    };
}

impl Statistics {
    pub fn new() -> Statistics {
        Self {
            conns: Default::default(),
        }
    }

    pub fn add_tcp_rx(&mut self, bytes: usize, dst: Option<IpAddr>, source: Option<IpAddr>) {
        add!(self, tcp_rx, bytes, dst, source);
    }

    pub fn add_tcp_tx(&mut self, bytes: usize, dst: Option<IpAddr>, source: Option<IpAddr>) {
        add!(self, tcp_tx, bytes, dst, source);
    }

    pub fn add_udp_rx(&mut self, bytes: usize, dst: Option<IpAddr>, source: Option<IpAddr>) {
        add!(self, udp_rx, bytes, dst, source);
    }

    pub fn add_udp_tx(&mut self, bytes: usize, dst: Option<IpAddr>, source: Option<IpAddr>) {
        add!(self, udp_tx, bytes, dst, source);
    }

    pub fn save(&self, file: &str, limit: usize) {
        let mut oo = OpenOptions::new();
        oo.write(true);
        oo.truncate(true);
        oo.create(true);
        match oo.open(file).map(|mut file| -> Result<(), std::io::Error> {
            let mut conns: Vec<_> = self.conns.iter().collect();
            let limit = if limit == 0 { conns.len() } else { limit };
            conns.sort_by(|(_, data1), (_, data2)| data1.all().cmp(&data2.all()).reverse());
            for (ip, data) in conns.iter().take(limit) {
                write!(
                    &mut file,
                    "{} {} {} {} {} {}",
                    data.all(),
                    data.tcp_rx,
                    data.tcp_tx,
                    data.udp_rx,
                    data.udp_tx,
                    ip,
                )?;
                for ip in &data.sources {
                    write!(&mut file, " {}", ip)?;
                }
                writeln!(&mut file)?;
            }
            Ok(())
        }) {
            Ok(Err(err)) | Err(err) => {
                log::error!("save file:{} failed:{}", file, err);
            }
            _ => {}
        }
    }
}
