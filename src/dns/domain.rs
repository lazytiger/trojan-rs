use std::collections::HashSet;

pub struct DomainMap {
    domains: HashSet<String>,
}

impl DomainMap {
    pub fn new() -> Self {
        Self {
            domains: HashSet::new(),
        }
    }

    pub fn add_domain(&mut self, domain: impl Into<String>) {
        self.domains.insert(domain.into());
    }

    pub fn contains(&self, domain: &str) -> bool {
        let items: Vec<_> = domain.split('.').collect();
        let end_index = if domain.ends_with('.') {
            items.len() - 1
        } else {
            items.len()
        };
        for i in 0..end_index - 1 {
            let domain = items.as_slice()[i..end_index].join(".");
            if self.domains.contains(&domain) {
                return true;
            }
        }
        false
    }
}

mod tests {
    #![allow(unused_imports)]
    extern crate test;

    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };
    use test::Bencher;

    use crate::dns::domain::DomainMap;

    #[test]
    fn test_contains() {
        let mut domain_map = DomainMap::new();
        let file = File::open("ipset/domain.txt").unwrap();
        let reader = BufReader::new(file);
        reader.lines().for_each(|line| {
            if let Ok(line) = line {
                domain_map.add_domain(line.as_str());
            }
        });
        assert!(domain_map.contains("ab.youtube.com."));
        assert!(domain_map.contains("ab.youtube.com"));
        assert!(domain_map.contains("ab.google.com"));
        assert!(domain_map.contains("ab.google.cn"));
    }

    #[bench]
    fn bench_contains(b: &mut Bencher) {
        let mut domain_map = DomainMap::new();
        let file = File::open("ipset/domain.txt").unwrap();
        let reader = BufReader::new(file);
        reader.lines().for_each(|line| {
            if let Ok(line) = line {
                domain_map.add_domain(line.as_str());
            }
        });
        b.iter(|| {
            domain_map.contains("google.com");
        });
    }
}
