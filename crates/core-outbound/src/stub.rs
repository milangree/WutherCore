//! 暂未实现的协议占位 —— dial 时返回明确错误。M2 阶段会逐协议替换为真实实现。

use std::sync::Arc;

use async_trait::async_trait;

use crate::adapter::{BoxedStream, DialContext, OutboundAdapter};

#[derive(Debug, Clone)]
pub struct StubOutbound {
    pub name: String,
    pub protocol: &'static str,
}

impl StubOutbound {
    pub fn new(name: impl Into<String>, protocol: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            protocol,
        })
    }
}

#[async_trait]
impl OutboundAdapter for StubOutbound {
    fn name(&self) -> &str {
        &self.name
    }
    fn protocol(&self) -> &'static str {
        self.protocol
    }
    async fn dial_tcp(&self, _ctx: DialContext) -> std::io::Result<BoxedStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("协议 {} 尚未实现 (节点 {})", self.protocol, self.name),
        ))
    }
}
