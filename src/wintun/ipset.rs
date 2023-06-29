use std::{
    cmp::Ordering,
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    ops::Not,
};

use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::{types::Result, wintun::route::route_add_with_if};

//TODO ipv6
pub fn is_private(endpoint: IpEndpoint) -> bool {
    if let IpAddress::Ipv4(ip) = endpoint.addr {
        endpoint.port == 0
            || ip.is_unspecified() //0.0.0.0/8
            || ip.0[0] == 10 //10.0.0.0/8
            || ip.is_loopback() //127.0.0.0/8
            || ip.is_link_local() //169.254.0.0/16
            || ip.0[0] == 172 && ip.0[1] & 0xf0 == 16 //172.16.0.0/12
            || ip.0[0] == 192 && ip.0[1] == 168 //192.168.0.0/16
            || ip.is_multicast() //224.0.0.0/4
            || ip.0[0] & 0xf0 == 240 // 240.0.0.0/4
            || ip.is_broadcast() //255.255.255.255/32
    } else {
        true
    }
}

pub struct IPSet {
    data: Vec<Cidr>,
}

struct Cidr {
    ip: u32,
    prefix: u32,
}

impl Cidr {
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
        let mask = Ipv4Addr::from(self.mask());
        (ip, mask)
    }
}

impl Eq for Cidr {}

impl PartialEq<Self> for Cidr {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.prefix == other.prefix
    }
}

impl PartialOrd<Self> for Cidr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.ip.partial_cmp(&other.ip) {
            Some(Ordering::Equal) => other.prefix.partial_cmp(&self.prefix),
            result => result,
        }
    }
}

impl Ord for Cidr {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.ip.cmp(&other.ip) {
            Ordering::Equal => other.prefix.cmp(&self.prefix),
            result => result,
        }
    }
}

impl IPSet {
    pub fn with_file(file: &str, inverse: bool) -> crate::types::Result<Self> {
        let mut ipset = Self::new();
        let file = File::open(file)?;
        let reader = BufReader::new(file);
        reader.lines().for_each(|line| {
            if let Ok(line) = line {
                ipset.add_str(line.as_str());
            }
        });
        if inverse {
            ipset.add_str("0.0.0.0/8");
            ipset.add_str("10.0.0.0/8");
            ipset.add_str("127.0.0.0/8");
            ipset.add_str("169.254.0.0/16");
            ipset.add_str("172.16.0.0/12");
            ipset.add_str("192.168.0.0/16");
            ipset.add_str("224.0.0.0/4");
            ipset.add_str("240.0.0.0/4");
            ipset.add_str("255.255.255.255/32");
            Ok(!ipset)
        } else {
            ipset.build();
            Ok(ipset)
        }
    }

    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn add(&mut self, ip: u32, prefix: u32) {
        self.data.push(Cidr::new(ip, prefix))
    }

    pub fn add_str(&mut self, line: &str) {
        let mut rows = line.split('/');
        let ip: Ipv4Addr = rows.next().unwrap().parse().unwrap();
        let prefix: u32 = rows.next().unwrap().parse().unwrap();
        self.add(ip.into(), prefix);
    }

    pub fn add_range(&mut self, left: u32, right: u32) {
        if left > right {
            return;
        }
        let cidrs = range_to_cidr(left, right);
        self.data.extend(cidrs);
    }

    pub fn build(&mut self) {
        self.data.sort();
    }

    pub fn add_route(&self, index: u32) -> Result<()> {
        for item in &self.data {
            route_add_with_if(item.ip, item.mask(), 0, index)?;
        }
        Ok(())
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
            if left > 0 && r < u32::MAX {
                set.add_range(r + 1, left - 1);
            }
            r = right;
        }
        if r < u32::MAX {
            set.add_range(r + 1, u32::MAX);
        }
        set.data.sort();
        set
    }
}

/// check with https://www.ipaddressguide.com/cidr
fn range_to_cidr(mut left: u32, mut right: u32) -> Vec<Cidr> {
    let mut cidrs = Vec::new();
    if left == right {
        cidrs.push(Cidr::new(left, 32));
        return cidrs;
    }

    loop {
        let shift = right.trailing_ones();
        let prefix = 32 - shift;
        let ip = right & !((1 << shift) - 1);
        if left <= ip {
            cidrs.push(Cidr::new(ip, prefix));
            right = ip - 1;
        } else {
            break;
        }
    }
    while left <= right {
        let shift = left.trailing_zeros();
        let prefix = 32 - shift;
        cidrs.push(Cidr::new(left, prefix));
        left += 1 << shift;
    }
    cidrs.sort();
    cidrs
}

#[allow(dead_code)]
#[allow(unused_imports)]
mod tests {
    use std::{fs::File, io::Write, net::Ipv4Addr, sync::Mutex, time::Instant};

    use crate::wintun::ipset::{range_to_cidr, IPSet};

    #[test]
    fn test_names() {
        let name = "www.reddit.com.";
        let split: Vec<_> = name.split(".").collect();
        let len = if name.ends_with(".") {
            split.len() - 1
        } else {
            split.len()
        };
        for i in 0..len - 1 {
            let name = split.as_slice()[i..len].join(".");
            println!("name:{}", name);
        }
    }

    #[test]
    fn test_mutex() {
        let mutex = Mutex::new(File::create("test.log").unwrap());
        let now = Instant::now();
        for _ in 0..10000 {
            if let Ok(mut lock) = mutex.lock() {
                lock.write(b"hello, world").unwrap();
            }
        }
        println!("{}", now.elapsed().as_micros());

        let now = Instant::now();
        let mut file = File::create("test.log").unwrap();
        for _ in 0..10000 {
            file.write(b"hello, world").unwrap();
        }
        println!("{}", now.elapsed().as_micros());
    }

    #[test]
    fn test_ipset_reverse() {
        let ipset = IPSet::with_file("ipset/ipset24.txt", true).unwrap();
        let mut file = File::create("test24.txt").unwrap();
        for (_, item) in ipset.data.iter().enumerate() {
            let ip: Ipv4Addr = item.ip.into();
            write!(&mut file, "<item>{}/{}</item>\r\n", ip, item.prefix).unwrap();
        }
    }

    #[test]
    fn test_ipset_create() {
        let ipset = IPSet::with_file("ipset/ipset_cidr.txt", false).unwrap();
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
        my_range_to_cidr(190365721, 190365947);
    }
}
