//! 全局日志广播总线 —— Clash `/logs` WebSocket 兼容。
//!
//! tracing 的 layer 会把每条事件转成 [`LogEvent`] 推入 broadcast；
//! API 层订阅后流式发送给 dashboard。
//!
//! 容量 256 —— Yacd / metacubexd 默认 1s/帧拉取，很难塞满；满时旧消息覆盖。
//! 同时保留最近 N 条历史，Dashboard 晚于内核启动连接时仍能看到启动诊断。

use std::collections::VecDeque;

use parking_lot::Mutex;
use serde::Serialize;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize)]
pub struct LogEvent {
    /// "debug" / "info" / "warning" / "error" / "silent"
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

#[derive(Debug, Clone)]
pub struct LogBus {
    tx: broadcast::Sender<LogEvent>,
    history: std::sync::Arc<Mutex<VecDeque<LogEvent>>>,
    capacity: usize,
}

impl LogBus {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(1));
        Self {
            tx,
            history: std::sync::Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }
    pub fn subscribe(&self) -> broadcast::Receiver<LogEvent> {
        self.tx.subscribe()
    }
    /// 原子地拿一份历史 + 注册订阅者。
    ///
    /// 与 `push` 共享同一把 history 锁，保证：
    /// - snapshot 之后才发生的 push 一定能进入 broadcast（不丢）
    /// - snapshot 之前已发生的 push 永远不会进入 broadcast（不重）
    pub fn subscribe_with_history(&self) -> (Vec<LogEvent>, broadcast::Receiver<LogEvent>) {
        let history = self.history.lock();
        let snapshot: Vec<LogEvent> = history.iter().cloned().collect();
        let rx = self.tx.subscribe();
        drop(history);
        (snapshot, rx)
    }
    pub fn push(&self, level: impl Into<String>, payload: impl Into<String>) {
        let event = LogEvent {
            level: level.into(),
            payload: payload.into(),
        };
        // 持锁内完成 history.push_back + tx.send，
        // 与 subscribe_with_history 串行化，避免双投递窗口。
        let mut history = self.history.lock();
        if self.capacity > 0 {
            while history.len() >= self.capacity {
                history.pop_front();
            }
            history.push_back(event.clone());
        }
        let _ = self.tx.send(event);
        drop(history);
    }
    pub fn snapshot(&self) -> Vec<LogEvent> {
        self.history.lock().iter().cloned().collect()
    }
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for LogBus {
    fn default() -> Self {
        Self::new(256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_returns_recent_events_in_order() {
        let bus = LogBus::new(2);
        bus.push("info", "first");
        bus.push("warning", "second");
        bus.push("error", "third");

        let got = bus.snapshot();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].payload, "second");
        assert_eq!(got[1].payload, "third");
    }

    #[test]
    fn zero_capacity_keeps_no_history_but_still_broadcasts() {
        let bus = LogBus::new(0);
        let mut rx = bus.subscribe();
        bus.push("info", "live");

        assert!(bus.snapshot().is_empty());
        assert_eq!(rx.try_recv().unwrap().payload, "live");
    }

    #[test]
    fn subscribe_with_history_is_exclusive_with_live_stream() {
        // 在 subscribe 之前推送的事件只走 history；之后推送的只走 broadcast。
        let bus = LogBus::new(8);
        bus.push("info", "before");

        let (history, mut rx) = bus.subscribe_with_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].payload, "before");

        bus.push("info", "after");
        let live = rx.try_recv().unwrap();
        assert_eq!(live.payload, "after");
        // 不应再有重复的 "before"。
        assert!(rx.try_recv().is_err());
    }
}
