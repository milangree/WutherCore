//! DNS 上游抽象：所有具体实现（系统 / DoH / DoT / UDP）都通过同一个 trait 接入 group。

use std::net::IpAddr;

use async_trait::async_trait;
use thiserror::Error;

pub mod system;
pub mod hickory;

#[derive(Debug, Error, Clone)]
pub enum DnsError {
    #[error("解析失败: {0}")]
    Failed(String),
    #[error("查询超时")]
    Timeout,
    #[error("空响应")]
    Empty,
    #[error("被策略拒绝: {0}")]
    Rejected(String),
}

#[async_trait]
pub trait DnsUpstream: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;
    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError>;

    /// 此 server 默认 EDNS0 client_subnet 提示。
    /// rule 级 [`crate::policy::QueryOptions::client_subnet`] 优先级更高 —— 当 rule 提供时覆盖此默认。
    /// 与 sing-box `dns.servers[].client_subnet` 一一对应。
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> { None }
}
