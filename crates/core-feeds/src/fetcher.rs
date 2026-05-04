//! 实际拉取订阅 —— HTTP/HTTPS/file/本地路径。

use std::sync::OnceLock;
use std::time::Duration;

use thiserror::Error;
use tracing::{debug, warn};

static SHARED_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn set_shared_http_client(client: reqwest::Client) {
    let _ = SHARED_CLIENT.set(client);
}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP 请求失败: {0}")]
    Http(String),
    #[error("非 2xx 状态: {0}")]
    Status(u16),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("URL 非法: {0}")]
    BadUrl(String),
}

/// 默认 UA —— 模拟主流客户端，避免被机场屏蔽。
pub const DEFAULT_UA: &str = concat!(
    "WutherCore/",
    env!("CARGO_PKG_VERSION"),
    " (clash-meta-compatible)"
);

/// 抓取一次订阅原文。
pub async fn fetch_feed(url: &str, timeout: Duration) -> Result<Vec<u8>, FetchError> {
    if url.starts_with("file://") {
        let path = url.trim_start_matches("file://");
        debug!(target: "feeds", path, "fetch from file");
        return Ok(std::fs::read(path)?);
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        // 本地路径
        if std::path::Path::new(url).exists() {
            return Ok(std::fs::read(url)?);
        }
        return Err(FetchError::BadUrl(url.into()));
    }

    let client = if let Some(c) = SHARED_CLIENT.get() {
        c.clone()
    } else {
        reqwest::Client::builder()
            .user_agent(DEFAULT_UA)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .gzip(true)
            .brotli(true)
            .build()
            .map_err(|e| FetchError::Http(e.to_string()))?
    };

    debug!(target: "feeds", url, "fetch http");
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        warn!(target: "feeds", url, code, "feed http error");
        return Err(FetchError::Status(code));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| FetchError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}
