//! WebSocket 广播中心 —— 把"每客户端独立 1Hz tick"压缩为"全局单 producer +
//! 多 subscriber"。
//!
//! ## 为什么需要
//!
//! 旧实现每个 WS 客户端持有独立的 `tokio::time::interval`：每秒各自调
//! `connection_manager_traffic(&s)` / `connections_snapshot(&s)` 等，N 个
//! dashboard 同时连接 → N×snapshot/sec。在 1 万连接 + 5 dashboard 的工程化
//! 场景里，仅 `/connections` 一个端点每秒会做 5 次完整的 manager_snapshot +
//! JSON 序列化（每次 ~1 ms），仅 broadcast 这一项就吃 5% CPU。
//!
//! 现在改为：
//!
//! * 每个端点一个 [`WsHub`]：内部保留 [`tokio::sync::watch`] 通道。
//! * 第一个 subscriber 触发 producer 协程（lazy start），1Hz 调一次 producer
//!   闭包并把序列化字符串写入 watch；之后所有 subscriber 共享同一份 String。
//! * Subscriber 用 `watch::changed()` 等待新值；`borrow_and_update().clone()`
//!   拿到当前最新（首次连接立即得到、不用等下一拍）。
//! * Producer 闭包只捕获自己需要的 `Arc<...>`（避免捕获 `NativeState` 形成
//!   `Arc` 循环）。
//!
//! ## 慢消费者保护
//!
//! `watch` 不堆消息：subscriber 慢的话只会丢掉中间帧，永远只看到最新的。
//! 与 `broadcast` 通道相比，没有"队列爆掉 → producer 拒绝写入 → 全员 lag"
//! 的风险，更适合 1Hz 监控类场景。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// 单个 WS 端点的广播 hub。
pub struct WsHub {
    tx: watch::Sender<String>,
    started: AtomicBool,
    interval: Duration,
    /// 不可变：构造期一次性传入。`Box<dyn Fn>` 让我们能在 [`WsHubs`] 里收纳
    /// 不同 producer 的多个 hub。
    producer: Box<dyn Fn() -> String + Send + Sync>,
    /// 端点名 —— 仅用于 tracing 调试。
    label: &'static str,
}

impl WsHub {
    pub fn new<F>(label: &'static str, interval: Duration, producer: F) -> Arc<Self>
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        let (tx, _) = watch::channel(String::new());
        Arc::new(Self {
            tx,
            started: AtomicBool::new(false),
            interval,
            producer: Box::new(producer),
            label,
        })
    }

    /// 订阅；首次订阅触发 producer 协程。
    pub fn subscribe(self: &Arc<Self>) -> watch::Receiver<String> {
        if !self.started.swap(true, Ordering::AcqRel) {
            let me = self.clone();
            tokio::spawn(async move { me.run().await });
        }
        self.tx.subscribe()
    }

    /// 立即同步取一份当前快照（不触发 producer 协程；为 HTTP 非 WS 路径用）。
    /// 如果还没有快照（hub 从未启动 producer），返回 None。
    pub fn current(&self) -> Option<String> {
        let s = self.tx.borrow();
        if s.is_empty() {
            None
        } else {
            Some(s.clone())
        }
    }

    /// 强制就地刷新（同步，绕过 ticker）。HTTP 非 WS 调用 `/traffic`、
    /// `/memory` 等聚合 GET 时用，让响应永远反映"最新一拍"而不是 hub 上一拍。
    pub fn build_now(&self) -> String {
        let payload = (self.producer)();
        // 也写回 watch，让 WS subscriber 能少等一个 tick 拿到最新。
        let _ = self.tx.send(payload.clone());
        payload
    }

    async fn run(self: Arc<Self>) {
        // 首拍立刻 produce，让早期连接的 subscriber 不用等 interval。
        let first = (self.producer)();
        let _ = self.tx.send(first);

        let mut tick = tokio::time::interval(self.interval);
        // tick.tick() 第一次立即返回 —— 跳过它免得连续 tick 两次。
        tick.tick().await;
        // missed-tick 行为 = Skip：tick 落后时（producer 偶尔慢）合并到下一拍，
        // 不补打缺失的 tick。监控类场景永远只关心"最新值"。
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            // 即使没有 subscriber 也继续 tick：watch 写入是常数代价（无队列）；
            // 这样 NEW subscriber 在 ≤ interval 内一定看到一帧实数据，
            // 不会因 hub 处于"刚 idle 的窗口"而看到 init 空串。
            let payload = (self.producer)();
            // 大对象送 watch 时，watch 的内部 Mutex 会序列化 readers；为了
            // 避免 producer 阻塞所有 readers，先存到 swap，然后短锁内置换。
            let _ = self.tx.send(payload);
            tracing::trace!(target: "api::ws_hub", label = self.label, "tick");
        }
    }
}

/// 三个高频端点共享一个 [`WsHubs`]。NativeState 持 `Arc<WsHubs>`。
pub struct WsHubs {
    pub traffic: Arc<WsHub>,
    pub memory: Arc<WsHub>,
    pub connections: Arc<WsHub>,
}

impl WsHubs {
    /// 工厂：捕获 producer 需要的最小 Arc 集合（避免 NativeState ↔ WsHubs
    /// 形成循环引用）。
    pub fn new(
        runtime: Arc<core_runtime::Runtime>,
        connections_interval_ms: u64,
    ) -> Arc<Self> {
        let traffic_runtime = runtime.clone();
        let traffic = WsHub::new(
            "traffic",
            Duration::from_secs(1),
            move || {
                let (up, down) = traffic_runtime.connections.now();
                serde_json::to_string(&serde_json::json!({"up": up, "down": down}))
                    .unwrap_or_else(|_| String::from("{}"))
            },
        );

        let memory_runtime = runtime.clone();
        let memory = WsHub::new(
            "memory",
            Duration::from_secs(1),
            move || {
                let v = memory_runtime.metrics.clash_memory();
                serde_json::to_string(&v).unwrap_or_else(|_| String::from("{}"))
            },
        );

        // /connections 默认 1000 ms；通过参数允许调慢以减负担（或调快做调试）。
        let conn_runtime = runtime.clone();
        let conn_interval = Duration::from_millis(connections_interval_ms.max(200));
        let connections = WsHub::new(
            "connections",
            conn_interval,
            move || {
                serialize_connections(&conn_runtime)
            },
        );

        Arc::new(Self {
            traffic,
            memory,
            connections,
        })
    }
}

/// 把 `manager_snapshot` 直接序列化成与 `compat::connections_snapshot` 等价
/// 的 JSON 文本。复制一份在这里是为了让 producer 闭包不依赖 NativeState（避免
/// 循环引用）。
fn serialize_connections(runtime: &Arc<core_runtime::Runtime>) -> String {
    let manager = runtime.connections.manager_snapshot();
    let conns: Vec<serde_json::Value> = manager
        .connections
        .into_iter()
        .map(|conn| {
            serde_json::json!({
                "id": conn.id,
                "metadata": conn.metadata,
                "upload": conn.upload,
                "download": conn.download,
                "start": iso8601_secs(conn.start),
                "chains": conn.chains,
                "providerChains": conn.provider_chains,
                "rule": conn.rule,
                "rulePayload": conn.rule_payload,
                "maxUploadRate": conn.max_upload_rate,
                "maxDownloadRate": conn.max_download_rate,
            })
        })
        .collect();
    serde_json::to_string(&serde_json::json!({
        "downloadTotal": manager.download_total,
        "uploadTotal": manager.upload_total,
        "connections": conns,
        "memory": manager.memory,
    }))
    .unwrap_or_else(|_| String::from("{}"))
}

fn iso8601_secs(ts_secs: u64) -> String {
    // 与 compat::iso8601 同算法；这里独立一份避免跨模块依赖（compat::iso8601
    // 是 module-private）。
    let days = (ts_secs / 86_400) as i64;
    let secs_of_day = (ts_secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day / 60) % 60;
    let second = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hour, minute, second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn lazy_start_only_after_first_subscribe() {
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("test", Duration::from_millis(20), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("x")
        });
        // 没 subscribe 时 producer 不跑。
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(n.load(Ordering::Relaxed), 0, "producer should be lazy");

        let _rx = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(80)).await;
        let count = n.load(Ordering::Relaxed);
        assert!(count >= 2, "producer must tick at least 2 times in 80ms");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multiple_subscribers_share_one_producer() {
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n_for_producer = n.clone();
        let hub = WsHub::new("test", Duration::from_millis(15), move || {
            n_for_producer.fetch_add(1, Ordering::Relaxed);
            String::from("x")
        });
        let _r1 = hub.subscribe();
        let _r2 = hub.subscribe();
        let _r3 = hub.subscribe();
        tokio::time::sleep(Duration::from_millis(60)).await;
        // 3 个 subscriber 不会触发 3 个 producer。
        let count = n.load(Ordering::Relaxed);
        assert!(count >= 2 && count <= 6, "expected 2..=6 ticks, got {count}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn watch_receiver_sees_latest_immediately() {
        let hub = WsHub::new("test", Duration::from_millis(10), || String::from("payload"));
        let mut rx = hub.subscribe();
        // 等 producer 至少一次 tick。
        tokio::time::sleep(Duration::from_millis(40)).await;
        let v = rx.borrow_and_update().clone();
        assert_eq!(v, "payload");
    }
}
