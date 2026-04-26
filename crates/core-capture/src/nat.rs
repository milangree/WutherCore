//! NAT 表 —— TUN/TProxy 通用：连接 5-tuple ⇄ 原始目标 + Fake host 反查。
//!
//! §8.4 性能：sharded NAT（DashMap 已经分片）；老化使用 LRU + TTL。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

#[derive(Debug, Clone)]
pub struct NatEntry {
    pub source: SocketAddr,
    pub original_dst: SocketAddr,
    pub fake_host: Option<String>,
    pub network: &'static str,
    pub created_at: Instant,
    pub last_seen: Instant,
}

#[derive(Debug)]
pub struct NatTable {
    map: DashMap<u64, NatEntry>,
    ttl: Duration,
    next_id: parking_lot::Mutex<u64>,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(Duration::from_secs(120))
    }
}

impl NatTable {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: DashMap::new(),
            ttl,
            next_id: parking_lot::Mutex::new(1),
        }
    }

    pub fn insert(&self, entry: NatEntry) -> u64 {
        let id = {
            let mut g = self.next_id.lock();
            let id = *g;
            *g = g.wrapping_add(1);
            id
        };
        self.map.insert(id, entry);
        id
    }

    pub fn touch(&self, id: u64) {
        if let Some(mut e) = self.map.get_mut(&id) {
            e.last_seen = Instant::now();
        }
    }

    pub fn remove(&self, id: u64) -> Option<NatEntry> {
        self.map.remove(&id).map(|(_, v)| v)
    }

    pub fn get(&self, id: u64) -> Option<NatEntry> {
        self.map.get(&id).map(|e| e.clone())
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// 周期性回收。返回被清理条数。
    pub fn purge(&self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut removed = 0;
        self.map.retain(|_, e| {
            let alive = now.duration_since(e.last_seen) < ttl;
            if !alive {
                removed += 1;
            }
            alive
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> NatEntry {
        NatEntry {
            source: "127.0.0.1:1000".parse().unwrap(),
            original_dst: "1.1.1.1:443".parse().unwrap(),
            fake_host: None,
            network: "tcp",
            created_at: Instant::now(),
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn insert_and_get() {
        let t = NatTable::default();
        let id = t.insert(entry());
        assert!(t.get(id).is_some());
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn purge_expired() {
        let t = NatTable::new(Duration::from_millis(20));
        let _id = t.insert(entry());
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(t.purge(), 1);
        assert_eq!(t.len(), 0);
    }
}
