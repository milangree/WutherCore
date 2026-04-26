//! FeedManager —— 编排多个 feed：冷启动拉一次 → 周期刷新 → 推送给 sink。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use core_config::model::FeedDetail;
use core_config::node_uri::ParsedNode;
use parking_lot::RwLock;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::cache::FeedDiskCache;
use crate::fetcher::fetch_feed;
use crate::parser::{apply_filter_rename, parse_feed_payload, FormatHint};

/// 一次刷新结果。
#[derive(Debug, Clone)]
pub struct FeedUpdate {
    pub name: String,
    pub nodes: Vec<ParsedNode>,
    pub from_cache: bool,
    pub raw_bytes: usize,
}

/// 节点接收方 —— 由 Runtime 实现，把新节点列表注册到 outbound + groups。
#[async_trait]
pub trait FeedSink: Send + Sync {
    async fn on_update(&self, update: FeedUpdate);
}

#[derive(Default)]
pub struct FeedManager {
    feeds: BTreeMap<String, FeedDetail>,
    cache: Option<FeedDiskCache>,
    sink: RwLock<Option<Arc<dyn FeedSink>>>,
    handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
    snapshots: RwLock<BTreeMap<String, Vec<ParsedNode>>>,
}

impl FeedManager {
    pub fn new(feeds: BTreeMap<String, FeedDetail>, cache: Option<FeedDiskCache>) -> Arc<Self> {
        Arc::new(Self {
            feeds,
            cache,
            sink: RwLock::new(None),
            handles: parking_lot::Mutex::new(Vec::new()),
            snapshots: RwLock::new(BTreeMap::new()),
        })
    }

    pub fn set_sink(self: &Arc<Self>, sink: Arc<dyn FeedSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn snapshot(&self, name: &str) -> Option<Vec<ParsedNode>> {
        self.snapshots.read().get(name).cloned()
    }

    pub fn all_nodes(&self) -> Vec<ParsedNode> {
        self.snapshots
            .read()
            .values()
            .flat_map(|v| v.clone())
            .collect()
    }

    /// 启动：每个 feed 一个独立协程，先拉一次再按 every 调度。
    pub fn start(self: Arc<Self>) {
        for (name, detail) in self.feeds.clone() {
            let me = self.clone();
            let name_owned = name.clone();
            let detail_owned = detail.clone();
            let handle = tokio::spawn(async move {
                me.run_one(name_owned, detail_owned).await;
            });
            self.handles.lock().push(handle);
        }
    }

    pub fn stop(&self) {
        for h in self.handles.lock().drain(..) {
            h.abort();
        }
    }

    /// 单 feed 主循环。
    async fn run_one(self: Arc<Self>, name: String, detail: FeedDetail) {
        let timeout = Duration::from_secs(30);
        loop {
            let result = self.refresh_once(&name, &detail, timeout).await;
            match result {
                Ok(update) => {
                    info!(
                        target: "feeds",
                        name = %name,
                        nodes = update.nodes.len(),
                        bytes = update.raw_bytes,
                        from_cache = update.from_cache,
                        "feed updated"
                    );
                    self.snapshots.write().insert(name.clone(), update.nodes.clone());
                    let sink = { self.sink.read().clone() };
                    if let Some(sink) = sink {
                        sink.on_update(update).await;
                    }
                }
                Err(e) => warn!(target: "feeds", name = %name, error = %e, "feed refresh failed"),
            }
            let next = clamp_interval(detail.every);
            tokio::time::sleep(next).await;
        }
    }

    /// 一次完整刷新（不含等待）。
    pub async fn refresh_once(
        &self,
        name: &str,
        detail: &FeedDetail,
        timeout: Duration,
    ) -> Result<FeedUpdate, String> {
        let raw = match fetch_feed(&detail.url, timeout).await {
            Ok(b) => {
                if let Some(cache) = &self.cache {
                    cache.save(name, &b);
                }
                b
            }
            Err(e) => {
                warn!(target: "feeds", name, error = %e, "online fetch failed; trying disk cache");
                let cache = self
                    .cache
                    .as_ref()
                    .and_then(|c| c.load(name))
                    .ok_or_else(|| format!("{e}"))?;
                let nodes = self.parse_with_filter(detail, &cache);
                return Ok(FeedUpdate {
                    name: name.to_string(),
                    nodes,
                    from_cache: true,
                    raw_bytes: cache.len(),
                });
            }
        };

        let nodes = self.parse_with_filter(detail, &raw);
        Ok(FeedUpdate {
            name: name.to_string(),
            nodes,
            from_cache: false,
            raw_bytes: raw.len(),
        })
    }

    fn parse_with_filter(&self, detail: &FeedDetail, raw: &[u8]) -> Vec<ParsedNode> {
        let parsed = parse_feed_payload(raw, FormatHint::Auto);
        apply_filter_rename(detail, parsed)
    }
}

fn clamp_interval(d: Duration) -> Duration {
    let min = Duration::from_secs(5 * 60);
    let max = Duration::from_secs(30 * 24 * 3600);
    if d < min { min } else if d > max { max } else { d }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::{FeedFilter, FeedRename};

    fn detail() -> FeedDetail {
        FeedDetail {
            url: "file://./this/should/not/exist".into(),
            every: Duration::from_secs(3600),
            via: "direct".into(),
            keep: FeedFilter::default(),
            drop: FeedFilter::default(),
            rename: FeedRename::default(),
        }
    }

    #[tokio::test]
    async fn refresh_falls_back_to_cache_when_fetch_fails() {
        let dir = std::env::temp_dir().join(format!(
            "rpkernel-feeds-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let cache = FeedDiskCache::new(&dir).unwrap();
        let payload = b"ss://YWVzLTI1Ni1nY206cGFzcw==@1.1.1.1:8388#FromCache";
        cache.save("airport", payload);

        let mgr = FeedManager::new(BTreeMap::new(), Some(cache));
        let update = mgr
            .refresh_once("airport", &detail(), Duration::from_millis(500))
            .await
            .unwrap();
        assert!(update.from_cache);
        assert_eq!(update.nodes.len(), 1);
        assert_eq!(update.nodes[0].name, "FromCache");
    }
}
