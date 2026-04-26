//! 规则集抓取 —— 与 core-feeds 同构（HTTP/HTTPS/file/本地路径）。

use std::time::Duration;

use thiserror::Error;
use tracing::debug;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP: {0}")]
    Http(String),
    #[error("HTTP 状态: {0}")]
    Status(u16),
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[error("URL 非法: {0}")]
    BadUrl(String),
}

pub async fn fetch_ruleset(src: &str, timeout: Duration) -> Result<Vec<u8>, FetchError> {
    if src.starts_with("file://") {
        return Ok(std::fs::read(src.trim_start_matches("file://"))?);
    }
    if !(src.starts_with("http://") || src.starts_with("https://")) {
        if std::path::Path::new(src).exists() {
            return Ok(std::fs::read(src)?);
        }
        return Err(FetchError::BadUrl(src.into()));
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("RPKernel-ruleset/", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .gzip(true)
        .brotli(true)
        .build()
        .map_err(|e| FetchError::Http(e.to_string()))?;
    debug!(target: "ruleset::fetch", url = src, "fetch");
    let resp = client.get(src).send().await.map_err(|e| FetchError::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(FetchError::Status(resp.status().as_u16()));
    }
    let bytes = resp.bytes().await.map_err(|e| FetchError::Http(e.to_string()))?;
    Ok(bytes.to_vec())
}
