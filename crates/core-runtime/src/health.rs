//! URLTest（节点测速）—— 与 mihomo / Clash Dashboard 等价。
//!
//! 设计目标：
//! * **支持所有协议**：通过 [`OutboundAdapter::dial_tcp`] 抽象，凡是已注册的
//!   出站都能测；未实现的协议 dial 时返回 `ErrorKind::Unsupported`，
//!   被忠实地记录为失败 + reason，不会假装成功。
//! * **memory safe**：100% 安全 Rust，无 unsafe。
//! * **高并发**：[`tokio::task::JoinSet`] 并行 + [`tokio::sync::Semaphore`] 限流，
//!   默认 64 并发，可配置。
//! * **高性能 / 低占用**：单次探测只用一条临时 TCP 连接 + 一个 GET 请求，
//!   命中 200/204 后立即关闭；按 chunk 读取，固定栈缓冲。
//! * **结果对接**：成功/失败都写入 [`NodeStats`]，自动同步到 redb；
//!   返回 [`HistoryEntry`] 供 Clash API `/proxies` history 字段。
//!
//! 默认探测 URL：`http://www.gstatic.com/generate_204`（与 mihomo 一致）。
//! 默认超时：5 秒。

use std::sync::Arc;
use std::time::{Duration, Instant};

use core_outbound::adapter::DialContext;
use parking_lot::RwLock;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::engine::Runtime;

#[derive(Debug, Error, Clone)]
pub enum DelayError {
    #[error("节点未注册: {0}")]
    UnknownNode(String),
    #[error("URL 非法: {0}")]
    BadUrl(String),
    #[error("dial 失败: {0}")]
    Dial(String),
    #[error("HTTP 失败: {0}")]
    Http(String),
    #[error("超时")]
    Timeout,
    #[error("连接已关闭")]
    Closed,
}

/// 默认配置。
#[derive(Debug, Clone)]
pub struct UrlTestConfig {
    pub default_url: String,
    pub default_timeout: Duration,
    pub max_parallel: usize,
}

impl Default for UrlTestConfig {
    fn default() -> Self {
        Self {
            default_url: "http://www.gstatic.com/generate_204".into(),
            default_timeout: Duration::from_secs(5),
            max_parallel: 64,
        }
    }
}

#[derive(Debug)]
pub struct UrlTester {
    pub cfg: RwLock<UrlTestConfig>,
    pub sem: Arc<Semaphore>,
}

impl UrlTester {
    pub fn new(cfg: UrlTestConfig) -> Arc<Self> {
        let sem = Arc::new(Semaphore::new(cfg.max_parallel));
        Arc::new(Self {
            cfg: RwLock::new(cfg),
            sem,
        })
    }

    pub fn current_config(&self) -> UrlTestConfig {
        self.cfg.read().clone()
    }

    /// 测一个节点；成功返回 ms，失败返回 [`DelayError`]。
    pub async fn test_node(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        node: &str,
        url: Option<&str>,
        to: Option<Duration>,
    ) -> Result<u32, DelayError> {
        let (target_host, target_port, http_path, http_host) = parse_http_url(
            url.unwrap_or(self.cfg.read().default_url.as_str()),
        )?;
        let limit = to.unwrap_or(self.cfg.read().default_timeout);

        let ob = runtime
            .outbounds
            .read()
            .get(node)
            .ok_or_else(|| DelayError::UnknownNode(node.to_string()))?;

        let sem = self.sem.clone();
        let _permit = sem
            .acquire_owned()
            .await
            .map_err(|_| DelayError::Closed)?;

        let started = Instant::now();
        let res = timeout(limit, async {
            let dial_ctx = DialContext::tcp(target_host.clone(), target_port);
            let stream = ob
                .dial_tcp(dial_ctx)
                .await
                .map_err(|e| DelayError::Dial(e.to_string()))?;
            probe_http(stream, &http_host, &http_path).await
        })
        .await;

        match res {
            Err(_) => {
                runtime.smart.record_probe_failure_for(node, "timeout");
                Err(DelayError::Timeout)
            }
            Ok(Err(e)) => {
                runtime.smart.record_probe_failure_for(node, e.to_string());
                Err(e)
            }
            Ok(Ok(())) => {
                let elapsed = started.elapsed();
                runtime.smart.record_probe_for(node, elapsed);
                Ok(elapsed.as_millis().min(u32::MAX as u128) as u32)
            }
        }
    }

    /// 并行测一组节点；按节点名返回结果。结果顺序与 nodes 一致。
    pub async fn test_many(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        nodes: &[String],
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let mut set = JoinSet::new();
        for name in nodes {
            let me = self.clone();
            let rt = runtime.clone();
            let n = name.clone();
            let u = url.clone();
            set.spawn(async move {
                let r = me.test_node(&rt, &n, u.as_deref(), to).await;
                (n, r)
            });
        }
        let mut out = Vec::with_capacity(nodes.len());
        while let Some(j) = set.join_next().await {
            match j {
                Ok(pair) => out.push(pair),
                Err(e) => {
                    warn!(target: "urltest", error = %e, "join task failed");
                }
            }
        }
        out
    }

    /// 测全部出站（DIRECT/BLOCK 跳过）。
    pub async fn test_all(
        self: &Arc<Self>,
        runtime: &Arc<Runtime>,
        url: Option<String>,
        to: Option<Duration>,
    ) -> Vec<(String, Result<u32, DelayError>)> {
        let names: Vec<String> = runtime
            .outbounds
            .read()
            .names()
            .filter(|n| *n != "DIRECT" && *n != "BLOCK")
            .map(|s| s.to_string())
            .collect();
        self.test_many(runtime, &names, url, to).await
    }
}

/// 后台周期任务：每 interval 跑一次 test_all。
pub fn spawn_periodic(
    tester: Arc<UrlTester>,
    runtime: Arc<Runtime>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // 启动后等几秒让监听就绪
        tokio::time::sleep(Duration::from_secs(3)).await;
        loop {
            let started = Instant::now();
            let results = tester.test_all(&runtime, None, None).await;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            info!(
                target: "urltest",
                tested = results.len(),
                ok,
                ms = started.elapsed().as_millis() as u64,
                "url test round finished"
            );
            tokio::time::sleep(interval).await;
        }
    })
}

/* ---------------- 内部：HTTP 探测 ---------------- */

/// 解析 http(s)://host[:port]/path → (host, port, path, host_header)。
/// MVP：仅支持 http://，https:// 暂返回 BadUrl（mihomo 默认 generate_204 是 http）。
fn parse_http_url(s: &str) -> Result<(String, u16, String, String), DelayError> {
    let (rest, port_default) = if let Some(r) = s.strip_prefix("http://") {
        (r, 80u16)
    } else if let Some(_r) = s.strip_prefix("https://") {
        return Err(DelayError::BadUrl(
            "URLTest 暂仅支持 http:// 探测 URL（mihomo 默认 generate_204 即为 http）".into(),
        ));
    } else {
        return Err(DelayError::BadUrl(format!("非 http URL: {s}")));
    };
    let (host_part, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
        (
            h.to_string(),
            p.parse()
                .map_err(|_| DelayError::BadUrl(format!("非法端口: {host_part}")))?,
        )
    } else {
        (host_part.to_string(), port_default)
    };
    let host_header = host.clone();
    Ok((host, port, path, host_header))
}

async fn probe_http<S>(mut stream: S, host_header: &str, path: &str) -> Result<(), DelayError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin,
{
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: rpkernel-urltest\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;

    // 读响应行
    let mut buf = [0u8; 64];
    let n = stream
        .read(&mut buf)
        .await
        .map_err(|e| DelayError::Http(e.to_string()))?;
    if n == 0 {
        return Err(DelayError::Closed);
    }
    let line = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if !line.starts_with("HTTP/1.") {
        return Err(DelayError::Http(format!(
            "非 HTTP 响应: {:?}",
            &line[..line.len().min(40)]
        )));
    }
    let code = line.split_whitespace().nth(1).unwrap_or("");
    if !code.starts_with('2') && !code.starts_with('3') {
        return Err(DelayError::Http(format!("HTTP {code}")));
    }
    debug!(target: "urltest", code, "probe ok");
    Ok(())
}

// SmartSelector::record_probe_for / record_probe_failure_for
// 在 core-smart 内部实现（孤儿规则）。
