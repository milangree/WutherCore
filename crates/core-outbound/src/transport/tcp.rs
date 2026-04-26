use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::adapter::BoxedStream;
use crate::transport::Transport;

#[derive(Debug, Default)]
pub struct TcpTransport;

#[async_trait]
impl Transport for TcpTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let s = TcpStream::connect((host, port)).await?;
        let _ = s.set_nodelay(true);
        Ok(Box::pin(s))
    }
}
