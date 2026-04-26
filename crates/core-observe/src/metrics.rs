use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct Metrics {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub dns_queries: AtomicU64,
    pub route_decisions: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add_up(&self, n: u64) {
        self.bytes_up.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_down(&self, n: u64) {
        self.bytes_down.fetch_add(n, Ordering::Relaxed);
    }

    pub fn inc_connection(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connection(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_dns(&self) {
        self.dns_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_route(&self) {
        self.route_decisions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "bytes_up": self.bytes_up.load(Ordering::Relaxed),
            "bytes_down": self.bytes_down.load(Ordering::Relaxed),
            "connections_total": self.connections_total.load(Ordering::Relaxed),
            "connections_active": self.connections_active.load(Ordering::Relaxed),
            "dns_queries": self.dns_queries.load(Ordering::Relaxed),
            "route_decisions": self.route_decisions.load(Ordering::Relaxed),
        })
    }
}
