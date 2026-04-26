use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};

#[derive(Debug, Default)]
pub struct DirectOutbound;

impl DirectOutbound {
    pub fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

#[async_trait]
impl OutboundAdapter for DirectOutbound {
    fn name(&self) -> &str {
        "DIRECT"
    }
    fn protocol(&self) -> &'static str {
        "direct"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            udp: true,
            ipv6: true,
            multiplex: false,
        }
    }
    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let target = format!("{}:{}", ctx.host, ctx.port);
        let stream = TcpStream::connect(target).await?;
        let _ = stream.set_nodelay(true);
        Ok(Box::pin(stream))
    }
}
