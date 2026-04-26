use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// 协议能力 —— Smart 选择时使用。
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub tcp: bool,
    pub udp: bool,
    pub ipv6: bool,
    pub multiplex: bool,
}

#[derive(Debug, Clone)]
pub struct DialContext {
    pub host: String,
    pub port: u16,
    pub network: &'static str, // "tcp" or "udp"
}

impl DialContext {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: "tcp",
        }
    }

    pub fn udp(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            network: "udp",
        }
    }
}

/// 抽象出"读 + 写 + Send"的代理流。
pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ProxyStream for T {}

pub type BoxedStream = Pin<Box<dyn ProxyStream>>;

#[async_trait]
pub trait OutboundAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn protocol(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: false,
            ipv6: true,
            multiplex: false,
        }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream>;
}

pub type SharedOutbound = Arc<dyn OutboundAdapter>;
