use crate::dns::add_route_with_if;
use std::{
    cmp::Ordering,
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    ops::Not,
};

pub struct IPSet {
    data: Vec<CIDR>,
}

struct CIDR {
    ip: u32,
    prefix: u32,
}

impl CIDR {
    fn new(ip: u32, prefix: u32) -> Self {
        let mut item = Self { ip, prefix };
        item.ip &= item.mask();
        item
    }
    fn range(&self) -> (u32, u32) {
        (self.ip, self.ip + !self.mask())
    }
    fn mask(&self) -> u32 {
        !((1 << (32 - self.prefix)) - 1)
    }
    fn ip_mask(&self) -> (Ipv4Addr, Ipv4Addr) {
        let ip = Ipv4Addr::from(self.ip);
        let mask = Ipv4Addr::from(!((1 << (32 - self.prefix)) - 1));
        (ip, mask)
    }
}

impl Eq for CIDR {}

impl PartialEq<Self> for CIDR {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.prefix == other.prefix
    }
}

impl PartialOrd<Self> for CIDR {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.ip.partial_cmp(&other.ip) {
            Some(Ordering::Equal) => other.prefix.partial_cmp(&self.prefix),
            result => result,
        }
    }
}

impl Ord for CIDR {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.ip.cmp(&other.ip) {
            Ordering::Equal => other.prefix.cmp(&self.prefix),
            result => result,
        }
    }
}

impl IPSet {
    pub fn with_file(file: &str) -> crate::types::Result<Self> {
        let mut ipset = Self::new();
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        reader.lines().for_each(|line| {
            if let Ok(line) = line {
                ipset.add_str(line.as_str());
            }
        });
        ipset.add_str("0.0.0.0/8");
        ipset.add_str("10.0.0.0/8");
        ipset.add_str("127.0.0.0/8");
        ipset.add_str("169.254.0.0/16");
        ipset.add_str("172.16.0.0/12");
        ipset.add_str("192.168.0.0/16");
        ipset.add_str("224.0.0.0/4");
        ipset.add_str("240.0.0.0/4");
        ipset.add_str("255.255.255.255/32");
        ipset.build();

        Ok(ipset)
    }

    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn add(&mut self, ip: u32, prefix: u32) {
        self.data.push(CIDR::new(ip, prefix))
    }

    pub fn add_str(&mut self, line: &str) {
        let mut rows = line.split('/');
        let ip: Ipv4Addr = rows.next().unwrap().parse().unwrap();
        let prefix: u32 = rows.next().unwrap().parse().unwrap();
        self.add(ip.into(), prefix);
    }

    pub fn add_range(&mut self, left: u32, right: u32) {
        let cidrs = range_to_cidr(left, right);
        self.data.extend(cidrs);
    }

    pub fn build(&mut self) {
        self.data.sort();
    }

    pub fn add_route(&self, index: u32) {
        for item in &self.data {
            let (ip, mask) = item.ip_mask();
            add_route_with_if(ip.to_string().as_str(), mask.to_string().as_str(), index);
        }
    }
}

impl Not for IPSet {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        self.data.sort();
        let mut set = Self::new();
        let mut r = 0;
        for item in &self.data {
            let (left, right) = item.range();
            if left == 0 || left - 1 == r {
                r = right;
            } else {
                if r < u32::MAX {
                    set.add_range(r + 1, left - 1);
                }
                r = right;
            }
        }
        set.data.sort();
        set
    }
}

fn range_to_cidr(mut left: u32, mut right: u32) -> Vec<CIDR> {
    let mut cidrs = Vec::new();
    if left == right {
        cidrs.push(CIDR::new(left, 32));
        return cidrs;
    }

    loop {
        let shift = right.trailing_ones();
        let prefix = 32 - shift;
        let r = right & !((1 << shift) - 1);
        if left <= r {
            cidrs.push(CIDR::new(r, prefix));
            right = r - 1;
        } else {
            break;
        }
    }
    while left <= right {
        let shift = left.trailing_zeros();
        let prefix = 32 - shift;
        cidrs.push(CIDR::new(left, prefix));
        left += 1 << shift;
    }
    cidrs.sort();
    cidrs
}

#[allow(dead_code)]
#[allow(unused_imports)]
mod tests {
    use crate::wintun::ipset::{range_to_cidr, IPSet};
    use std::{fs::File, io::Write, net::Ipv4Addr};

    #[test]
    fn test_ipset_create() {
        let ipset = IPSet::with_file("ipset/ipset_cidr.txt").unwrap();
        let mut file = File::create("route1.bat").unwrap();
        for item in &ipset.data {
            let (left, right) = item.range();
            let ip = Ipv4Addr::from(item.ip);
            let mask = Ipv4Addr::from(!((1 << (32 - item.prefix)) - 1));
            write!(
                file,
                "{} - {}, {} {} {}\r\n",
                left, right, ip, mask, item.prefix
            )
            .unwrap();
        }
        let ipset = !ipset;
        let mut last = 0;
        for item in &ipset.data {
            let (left, right) = item.range();
            if left < last {
                println!("{}, {} | {}", last, left, Ipv4Addr::from(left));
            }
            last = right;
        }
        let mut file = File::create("route2.bat").unwrap();
        for item in &ipset.data {
            let (left, right) = item.range();
            let ip = Ipv4Addr::from(item.ip);
            let mask = Ipv4Addr::from(!((1 << (32 - item.prefix)) - 1));
            write!(
                file,
                "{} - {}, {} {} {}\r\n",
                left, right, ip, mask, item.prefix
            )
            .unwrap();
        }
    }

    fn my_range_to_cidr(left: u32, right: u32) {
        println!(
            "{}, {}, {} - {}",
            left,
            right,
            Ipv4Addr::from(left),
            Ipv4Addr::from(right)
        );
        for item in range_to_cidr(left, right) {
            let (ip, mask) = item.ip_mask();
            let (left, right) = item.range();
            println!("{}, {}, {} {} {}", left, right, ip, mask, item.prefix);
        }
    }

    #[test]
    fn test_iprange() {
        my_range_to_cidr(190365721, 190365722);
    }
}
