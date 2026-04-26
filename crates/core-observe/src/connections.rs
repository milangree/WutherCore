use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionEntry {
    pub id: u64,
    pub inbound: String,
    pub host: String,
    pub port: u16,
    pub network: String,
    pub rule: String,
    pub outbound: String,
    pub started_at: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Default)]
pub struct ConnectionTable {
    next: AtomicU64,
    entries: DashMap<u64, ConnectionEntry>,
}

impl ConnectionTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn open(&self, mut entry: ConnectionEntry) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        entry.id = id;
        self.entries.insert(id, entry);
        id
    }

    pub fn close(&self, id: u64) {
        self.entries.remove(&id);
    }

    pub fn list(&self) -> Vec<ConnectionEntry> {
        self.entries.iter().map(|e| e.value().clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}
