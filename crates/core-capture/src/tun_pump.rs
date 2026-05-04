//! TUN pump 公共基础 —— `system_dispatch` 和 `tun_dispatch` 共用的
//! packet 读取、解析、分发、流量统计逻辑。消除两套 dispatcher 的代码重复。

use std::time::{Duration, Instant};

pub(crate) const TUN_IDLE_LOG_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const TUN_TRAFFIC_SUMMARY_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const TUN_FRAME_FORMAT_TTL: Duration = Duration::from_secs(30 * 60);
pub(crate) const TUN_FRAME_FORMAT_MAX_ENTRIES: usize = 16_384;
/// Maximum segments per batch read. Must accommodate the largest possible GSO
/// segment split: 64KB / 1460B MSS ≈ 45 segments. Set to 64 for headroom.
/// Previously 8, which caused packet drops on high-throughput downloads.
pub(crate) const PUMP_BATCH_N: usize = 64;

#[derive(Debug, Clone)]
pub(crate) struct TrafficLog {
    pub started_at: Instant,
    pub last_idle_report_at: Option<Instant>,
    pub last_summary_at: Instant,
    pub last_summary_packets: u64,
    pub read_packets: u64,
    pub read_bytes: u64,
    pub tcp_packets: u64,
    pub udp_packets: u64,
    pub other_packets: u64,
    pub dns_packets: u64,
    pub dropped_packets: u64,
    pub unparsable_packets: u64,
    unparsable_logged: u64,
}

impl TrafficLog {
    pub fn new(now: Instant) -> Self {
        Self {
            started_at: now,
            last_idle_report_at: None,
            last_summary_at: now,
            last_summary_packets: 0,
            read_packets: 0,
            read_bytes: 0,
            tcp_packets: 0,
            udp_packets: 0,
            other_packets: 0,
            dns_packets: 0,
            dropped_packets: 0,
            unparsable_packets: 0,
            unparsable_logged: 0,
        }
    }

    pub fn record_read(&mut self, bytes: usize) -> bool {
        self.read_packets += 1;
        self.read_bytes += bytes as u64;
        self.read_packets == 1
    }
    pub fn record_tcp(&mut self) {
        self.tcp_packets += 1;
    }
    pub fn record_udp(&mut self) {
        self.udp_packets += 1;
    }
    pub fn record_other(&mut self) {
        self.other_packets += 1;
    }
    pub fn record_dns(&mut self) {
        self.dns_packets += 1;
    }
    pub fn record_drop(&mut self) {
        self.dropped_packets += 1;
    }
    pub fn record_unparsable(&mut self) {
        self.unparsable_packets += 1;
        self.record_drop();
    }
    pub fn should_log_unparsable_detail(&mut self) -> bool {
        self.unparsable_logged += 1;
        self.unparsable_logged <= 8 || self.unparsable_logged % 100 == 0
    }

    pub fn idle_warning_due(&mut self, now: Instant, interval: Duration) -> bool {
        if self.read_packets != 0 || now.duration_since(self.started_at) < interval {
            return false;
        }
        if self
            .last_idle_report_at
            .is_some_and(|last| now.duration_since(last) < interval)
        {
            return false;
        }
        self.last_idle_report_at = Some(now);
        true
    }

    pub fn summary_due(&mut self, now: Instant, interval: Duration) -> bool {
        if self.read_packets == self.last_summary_packets {
            return false;
        }
        if now.duration_since(self.last_summary_at) < interval {
            return false;
        }
        self.last_summary_at = now;
        self.last_summary_packets = self.read_packets;
        true
    }

    /// 人类可读的周期摘要（对标 mihomo 的流量统计日志）。
    pub fn format_summary(&self, iface: &str) -> String {
        let elapsed = Instant::now().duration_since(self.started_at).as_secs();
        format!(
            "[TUN {}] {}s | {} pkts ({}) | TCP {} | UDP {} | DNS {} | drop {} | err {}",
            iface,
            elapsed,
            self.read_packets,
            format_bytes(self.read_bytes),
            self.tcp_packets,
            self.udp_packets,
            self.dns_packets,
            self.dropped_packets,
            self.unparsable_packets,
        )
    }
}

/// 人类可读的字节数格式化。
pub(crate) fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// mihomo 风格的连接日志行（对标 `[TCP] src --> dst match RULE(payload) using Proxy`）。
pub(crate) fn format_session_line(
    network: &str,
    src: &str,
    host: &str,
    port: u16,
    rule: &str,
    rule_payload: &str,
    outbound: &str,
    chains: &[String],
    inner: bool,
) -> String {
    let src_label = if inner { "WutherCore" } else { src };
    let proxy = if chains.len() > 1 {
        chains.join(" >> ")
    } else {
        outbound.to_string()
    };
    if rule.is_empty() {
        format!("[{}] {} --> {}:{} using {}", network.to_uppercase(), src_label, host, port, proxy)
    } else if rule_payload.is_empty() {
        format!(
            "[{}] {} --> {}:{} match {} using {}",
            network.to_uppercase(), src_label, host, port, rule, proxy
        )
    } else {
        format!(
            "[{}] {} --> {}:{} match {}({}) using {}",
            network.to_uppercase(), src_label, host, port, rule, rule_payload, proxy
        )
    }
}
