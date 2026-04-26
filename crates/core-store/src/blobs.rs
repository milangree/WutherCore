//! 持久化的值结构体 —— 所有 blob 都使用 serde JSON 序列化。

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeStatsBlob {
    pub samples: u32,
    pub success_ewma: f64,
    pub p50_latency_ms: f64,
    pub jitter_ms: f64,
    pub timeout_rate: f64,
    /// 最近一次失败相对于 UNIX_EPOCH 的秒数；None 表示无。
    pub last_failure_secs: Option<u64>,
    pub last_error: Option<String>,
    pub last_used_secs: Option<u64>,
    /// URLTest 历史 —— (epoch_ms, delay_ms)，最多 8 条；
    /// 写法保留向后兼容（旧库不存在该字段时 serde::default 给空 Vec）。
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub time_ms: u64,
    pub delay_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBestBlob {
    pub node: String,
    pub set_at_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeBlob {
    pub until_secs: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedMetaBlob {
    pub last_success_secs: Option<u64>,
    pub last_attempt_secs: Option<u64>,
    pub last_node_count: u32,
    pub last_bytes: u64,
    pub last_etag: Option<String>,
    pub last_error: Option<String>,
}

/// DNS 缓存持久化条目。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsCacheBlob {
    /// IP 列表（原始字符串，便于 v4/v6 同表）
    pub ips: Vec<String>,
    /// 过期 epoch_secs；启动时若 < now 则丢弃
    pub expire_secs: u64,
    pub origin: String,
}
