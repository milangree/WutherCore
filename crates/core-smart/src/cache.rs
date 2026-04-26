//! domain_best / asn_best / region_best / negative —— §6.6 简化实现。

use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Debug)]
pub struct DomainBest {
    map: DashMap<String, (String, Instant)>,
    ttl: Duration,
}

impl DomainBest {
    pub fn new(ttl: Duration) -> Self {
        Self { map: DashMap::new(), ttl }
    }

    pub fn key(group: &str, etld: &str) -> String {
        format!("{group}|{etld}")
    }

    pub fn get(&self, key: &str) -> Option<String> {
        let entry = self.map.get(key)?;
        if entry.1.elapsed() > self.ttl {
            return None;
        }
        Some(entry.0.clone())
    }

    pub fn put(&self, key: &str, node: &str) {
        self.map.insert(key.to_string(), (node.to_string(), Instant::now()));
    }
}

#[derive(Debug)]
pub struct NegativeCache {
    /// node -> (until, reason)
    map: DashMap<String, (Instant, String)>,
}

impl Default for NegativeCache {
    fn default() -> Self {
        Self { map: DashMap::new() }
    }
}

impl NegativeCache {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cool(&self, node: &str, dur: Duration, reason: impl Into<String>) {
        self.map
            .insert(node.to_string(), (Instant::now() + dur, reason.into()));
    }
    pub fn is_cool(&self, node: &str) -> Option<String> {
        let entry = self.map.get(node)?;
        if entry.0 > Instant::now() {
            Some(entry.1.clone())
        } else {
            None
        }
    }
}
