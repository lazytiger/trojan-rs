use std::collections::HashMap;

pub struct DomainMap {
    map: HashMap<String, Option<DomainMap>>,
}

impl DomainMap {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn add_domain(&mut self, domain: &str) {
        let mut iter = domain.split('.').rev();
        if domain.ends_with('.') {
            let _ = iter.next();
        }
        if let Some(first) = iter.next() {
            if self.map.get_mut(first).is_none() {
                self.map.insert(first.into(), None);
            }
            let mut current = self.map.get_mut(first).unwrap();
            for name in iter {
                if current.is_none() {
                    current.replace(DomainMap::new());
                }
                let map = current.as_mut().unwrap();
                if map.map.get_mut(name).is_none() {
                    map.map.insert(name.into(), None);
                }
                current = map.map.get_mut(name).unwrap();
            }
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        let mut current = self;
        let mut iter = domain.split('.').rev();
        if domain.ends_with('.') {
            let _ = iter.next();
        }
        for name in iter {
            if let Some(map) = current.map.get(name) {
                if map.is_none() {
                    return true;
                }
                current = map.as_ref().unwrap();
            } else {
                return false;
            }
        }
        true
    }
}

#[allow(unused_imports)]
mod tests {
    use crate::dns::domain::DomainMap;

    #[test]
    fn test() {
        let mut domain_map = DomainMap::new();
        domain_map.add_domain("talk.google.com.");
        domain_map.add_domain("github.com.");
        domain_map.add_domain("gmail.com.");
        assert!(domain_map.contains("google.com."));
        assert!(domain_map.contains("google.com."));
        assert!(!domain_map.contains("babeltime.com."));
    }
}
