use std::{
    cmp::Ordering,
    fs::File,
    io::{BufRead, BufReader},
    net::Ipv4Addr,
    ops::Not,
};

use smoltcp::wire::{IpAddress, IpEndpoint};

use crate::wintun::route::RouteSpec;

//TODO ipv6
pub fn is_private(endpoint: IpEndpoint) -> bool {
    if let IpAddress::Ipv4(ip) = endpoint.addr {
        let octets = ip.octets();
        endpoint.port == 0
            || ip.is_unspecified() //0.0.0.0/8
            || octets[0] == 10 //10.0.0.0/8
            || ip.is_loopback() //127.0.0.0/8
            || ip.is_link_local() //169.254.0.0/16
            || octets[0] == 172 && octets[1] & 0xf0 == 16 //172.16.0.0/12
            || octets[0] == 192 && octets[1] == 168 //192.168.0.0/16
            || ip.is_multicast() //224.0.0.0/4
            || octets[0] & 0xf0 == 240 // 240.0.0.0/4
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
        if self.prefix == 0 {
            0
        } else {
            !((1 << (32 - self.prefix)) - 1)
        }
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
            ipset.add_reserved_ranges();
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

    pub fn route_specs_with_gateway(&self, gateway: u32, index: u32, routes: &mut Vec<RouteSpec>) {
        routes.extend(
            self.data
                .iter()
                .map(|item| RouteSpec::new(item.ip, item.mask(), gateway, index)),
        );
    }

    pub fn add_reserved_ranges(&mut self) {
        self.add_str("0.0.0.0/8");
        self.add_str("10.0.0.0/8");
        self.add_str("127.0.0.0/8");
        self.add_str("169.254.0.0/16");
        self.add_str("172.16.0.0/12");
        self.add_str("192.168.0.0/16");
        self.add_str("224.0.0.0/4");
        self.add_str("240.0.0.0/4");
        self.add_str("255.255.255.255/32");
    }
}

impl Not for IPSet {
    type Output = Self;

    fn not(mut self) -> Self::Output {
        self.data.sort();
        let mut set = Self::new();
        let mut next = 0u64;
        for item in &self.data {
            let (left, right) = item.range();
            let left = left as u64;
            let right = right as u64;
            if left > next {
                set.add_range(next as u32, (left - 1) as u32);
            }
            if right >= next {
                next = right + 1;
            }
            if next > u32::MAX as u64 {
                break;
            }
        }
        if next <= u32::MAX as u64 {
            set.add_range(next as u32, u32::MAX);
        }
        set.data.sort();
        set
    }
}

/// check with https://www.ipaddressguide.com/cidr
fn range_to_cidr(left: u32, right: u32) -> Vec<Cidr> {
    let mut cidrs = Vec::new();
    if left == right {
        cidrs.push(Cidr::new(left, 32));
        return cidrs;
    }

    let mut current = left as u64;
    let end = right as u64;
    while current <= end {
        let mut block_bits = if current == 0 {
            32
        } else {
            (current as u32).trailing_zeros()
        };
        while (1u64 << block_bits) > end - current + 1 {
            block_bits -= 1;
        }
        cidrs.push(Cidr::new(current as u32, 32 - block_bits));
        current += 1u64 << block_bits;
    }
    cidrs.sort();
    cidrs
}

#[allow(dead_code)]
#[allow(unused_imports)]
mod tests {
    use std::{fs::File, io::Write, net::Ipv4Addr, sync::Mutex, time::Instant};

    use crate::wintun::ipset::{range_to_cidr, IPSet};

    fn contains(ipset: &IPSet, ip: &str) -> bool {
        let ip: u32 = ip.parse::<Ipv4Addr>().unwrap().into();
        ipset.data.iter().any(|item| {
            let (left, right) = item.range();
            left <= ip && ip <= right
        })
    }

    fn china_ipset_from_apnic_fixture() -> IPSet {
        let mut ipset = IPSet::new();
        for line in include_str!("../../tests/fixtures/apnic-cn-ipv4.txt").lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                ipset.add_str(line);
            }
        }
        ipset.build();
        ipset
    }

    fn assert_no_ranges_overlap(left: &IPSet, right: &IPSet) {
        let mut i = 0;
        let mut j = 0;
        while i < left.data.len() && j < right.data.len() {
            let (left_start, left_end) = left.data[i].range();
            let (right_start, right_end) = right.data[j].range();
            assert!(
                left_end < right_start || right_end < left_start,
                "overlap found: {}/{} intersects {}/{}",
                Ipv4Addr::from(left.data[i].ip),
                left.data[i].prefix,
                Ipv4Addr::from(right.data[j].ip),
                right.data[j].prefix
            );
            if left_end < right_end {
                i += 1;
            } else {
                j += 1;
            }
        }
    }

    #[test]
    fn test_inverse_apnic_china_ipv4_excludes_every_china_range() {
        let china = china_ipset_from_apnic_fixture();
        assert!(china.data.len() > 8000);

        let mut inverse = !china_ipset_from_apnic_fixture();
        inverse.build();

        assert_no_ranges_overlap(&china, &inverse);
    }

    #[test]
    fn test_ipset_reverse_ignores_nested_ranges() {
        let mut ipset = IPSet::new();
        ipset.add_str("1.0.0.0/8");
        ipset.add_str("1.1.0.0/16");
        ipset.add_str("2.0.0.0/8");

        let reversed = !ipset;

        assert!(!contains(&reversed, "1.2.3.4"));
        assert!(contains(&reversed, "3.0.0.1"));
    }

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
