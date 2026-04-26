//! 规则集编排：拉取 → 解析 → 编译 → 推送给索引；后台周期刷新。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::fetch::fetch_ruleset;
use crate::format::detect_format;
use crate::matcher::{RulesetIndex, RulesetMatcher};
use crate::parser::parse_ruleset;
use crate::spec::RulesetSpec;

#[derive(Debug, Clone)]
pub struct RulesetUpdate {
    pub name: String,
    pub size: usize,
    pub from_cache: bool,
}

pub trait RulesetSink: Send + Sync {
    fn on_update(&self, update: RulesetUpdate);
}

pub struct RulesetManager {
    sets: BTreeMap<String, RulesetSpec>,
    cache_dir: Option<PathBuf>,
    index: Arc<RulesetIndex>,
    sink: RwLock<Option<Arc<dyn RulesetSink>>>,
    handles: parking_lot::Mutex<Vec<JoinHandle<()>>>,
}

impl RulesetManager {
    pub fn new(
        sets: BTreeMap<String, RulesetSpec>,
        cache_dir: Option<PathBuf>,
        index: Arc<RulesetIndex>,
    ) -> Arc<Self> {
        if let Some(d) = &cache_dir {
            let _ = std::fs::create_dir_all(d);
        }
        Arc::new(Self {
            sets,
            cache_dir,
            index,
            sink: RwLock::new(None),
            handles: parking_lot::Mutex::new(Vec::new()),
        })
    }

    pub fn set_sink(self: &Arc<Self>, sink: Arc<dyn RulesetSink>) {
        *self.sink.write() = Some(sink);
    }

    pub fn index(&self) -> Arc<RulesetIndex> { self.index.clone() }

    /// 启动：每个规则集独立后台协程。
    pub fn start(self: Arc<Self>) {
        // 启动时先做一次同步（payload 内联立刻命中；远程异步开始拉）
        for (name, spec) in &self.sets {
            if !spec.payload.is_empty() {
                let entries = self.parse_inline(spec);
                let m = Arc::new(RulesetMatcher::compile(name.clone(), entries));
                self.index.insert(m.clone());
                if let Some(sink) = self.sink.read().clone() {
                    sink.on_update(RulesetUpdate { name: name.clone(), size: m.stats().domains, from_cache: false });
                }
                info!(target: "ruleset", name, source = "inline", "compiled");
            }
        }
        for (name, spec) in self.sets.clone() {
            if !spec.payload.is_empty() && spec.url.is_none() && spec.path.is_none() {
                continue;
            }
            let me = self.clone();
            let handle = tokio::spawn(async move {
                me.run_one(name, spec).await;
            });
            self.handles.lock().push(handle);
        }
    }

    pub fn stop(&self) {
        for h in self.handles.lock().drain(..) {
            h.abort();
        }
    }

    fn parse_inline(&self, spec: &RulesetSpec) -> Vec<crate::matcher::ClassicalEntry> {
        spec.payload
            .iter()
            .filter_map(|s| crate::parser::txt::parse_line(s))
            .collect()
    }

    async fn run_one(self: Arc<Self>, name: String, spec: RulesetSpec) {
        loop {
            match self.refresh_once(&name, &spec).await {
                Ok(update) => {
                    info!(target: "ruleset", name = %name, size = update.size, from_cache = update.from_cache, "compiled");
                    if let Some(sink) = self.sink.read().clone() {
                        sink.on_update(update);
                    }
                }
                Err(e) => warn!(target: "ruleset", name = %name, error = %e, "refresh failed"),
            }
            tokio::time::sleep(clamp_interval(spec.every)).await;
        }
    }

    /// 一次完整的拉取 + 解析 + 编译 + 入索引。
    pub async fn refresh_once(&self, name: &str, spec: &RulesetSpec) -> Result<RulesetUpdate, String> {
        let timeout = Duration::from_secs(30);
        let src = spec.url.as_deref().or(spec.path.as_deref());
        let body = match src {
            Some(s) => match fetch_ruleset(s, timeout).await {
                Ok(b) => {
                    if let Some(d) = &self.cache_dir {
                        let p = d.join(safe_name(name));
                        let _ = std::fs::write(&p, &b);
                    }
                    b
                }
                Err(e) => {
                    warn!(target: "ruleset", name, error = %e, "online fetch failed; trying cache");
                    self.cache_dir
                        .as_ref()
                        .and_then(|d| std::fs::read(d.join(safe_name(name))).ok())
                        .ok_or_else(|| format!("{e}"))?
                }
            },
            None => {
                let entries: Vec<_> = self.parse_inline(spec);
                let m = Arc::new(RulesetMatcher::compile(name.to_string(), entries));
                let stats = m.stats();
                let total = stats.domains + stats.suffixes + stats.cidr_v4 + stats.cidr_v6;
                self.index.insert(m);
                return Ok(RulesetUpdate { name: name.to_string(), size: total, from_cache: false });
            }
        };

        let format = detect_format(spec.format.as_deref(), src, &body);
        debug!(target: "ruleset", name, ?format, bytes = body.len(), "parse");
        let entries = parse_ruleset(format, &body).map_err(|e| e.to_string())?;
        let total = entries.len();
        let m = Arc::new(RulesetMatcher::compile(name.to_string(), entries));
        self.index.insert(m);
        Ok(RulesetUpdate { name: name.to_string(), size: total, from_cache: false })
    }
}

fn clamp_interval(d: Duration) -> Duration {
    let min = Duration::from_secs(5 * 60);
    let max = Duration::from_secs(30 * 24 * 3600);
    if d < min { min } else if d > max { max } else { d }
}

fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn inline_payload_compiles_immediately() {
        let mut sets = BTreeMap::new();
        sets.insert(
            "my-direct".to_string(),
            RulesetSpec {
                url: None,
                path: None,
                payload: vec![
                    "DOMAIN-SUFFIX,example.com".into(),
                    "+.qq.com".into(),
                    "10.0.0.0/8".into(),
                ],
                r#type: crate::spec::RulesetType::Mixed,
                format: None,
                every: Duration::from_secs(3600),
                via: "direct".into(),
            },
        );
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(sets, None, idx.clone());
        mgr.clone().start();
        // 内联立刻命中
        let m = idx.get("my-direct").unwrap();
        assert!(m.matches("a.example.com", None, None, None));
        assert!(m.matches("im.qq.com", None, None, None));
        assert!(m.matches("", "10.1.2.3".parse().ok(), None, None));
        mgr.stop();
    }

    #[tokio::test]
    async fn refresh_local_yaml_works() {
        let dir = std::env::temp_dir().join(format!(
            "rpkernel-ruleset-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("test.yaml");
        std::fs::write(&p, b"payload:\n  - DOMAIN-SUFFIX,test.com\n  - 192.168.0.0/16\n").unwrap();
        let mut sets = BTreeMap::new();
        sets.insert(
            "rs1".into(),
            RulesetSpec {
                url: None,
                path: Some(p.display().to_string()),
                payload: vec![],
                r#type: crate::spec::RulesetType::Mixed,
                format: Some("yaml".into()),
                every: Duration::from_secs(3600),
                via: "direct".into(),
            },
        );
        let idx = RulesetIndex::new();
        let mgr = RulesetManager::new(sets.clone(), Some(dir), idx.clone());
        let spec = sets.get("rs1").unwrap().clone();
        let upd = mgr.refresh_once("rs1", &spec).await.unwrap();
        assert_eq!(upd.size, 2);
        let m = idx.get("rs1").unwrap();
        assert!(m.matches("a.test.com", None, None, None));
        assert!(m.matches("", "192.168.5.10".parse().ok(), None, None));
    }
}
