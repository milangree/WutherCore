//! Trojan 出站 —— 与 mihomo / trojan-go 互通。
//!
//! 协议（[reference](https://trojan-gfw.github.io/trojan/protocol)）：
//! 1. 通过 TLS 连到服务器（必须启用 TLS）；
//! 2. 客户端发送：
//!    `hex(SHA-224(password)) [56B] || CRLF || CMD(1) || ATYP || ADDR || PORT || CRLF || payload`
//!    其中 CMD = 0x01 (CONNECT) / 0x03 (UDP ASSOCIATE)；ATYP/ADDR/PORT 与 SOCKS5 相同。
//! 3. 之后双向就是裸 payload。

use async_trait::async_trait;
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::proto::addr::encode_socks_addr;
use crate::transport::{tls::TlsTransport, TlsOptions, Transport};

#[derive(Debug, Clone)]
pub struct TrojanOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
}

impl TrojanOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        password: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            password: password.into(),
            sni: None,
            insecure: false,
            alpn: vec![],
        }
    }
}

#[async_trait]
impl OutboundAdapter for TrojanOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "trojan" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: true, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let tls = TlsTransport::new(TlsOptions {
            enabled: true,
            sni: self.sni.clone(),
            insecure: self.insecure,
            alpn: self.alpn.clone(),
        });
        let mut stream = tls.connect(&self.host, self.port).await?;

        // hex(sha224(password))
        let mut h = Sha224::new();
        h.update(self.password.as_bytes());
        let hash = h.finalize();
        let hex_hash = hex_encode(&hash); // 56 chars

        // 头部：hash + CRLF + CMD(0x01) + ATYP+ADDR+PORT + CRLF
        let target = encode_socks_addr(&ctx.host, ctx.port);
        let mut header = Vec::with_capacity(56 + 2 + 1 + target.len() + 2);
        header.extend_from_slice(hex_hash.as_bytes());
        header.extend_from_slice(b"\r\n");
        header.push(0x01); // CONNECT
        header.extend_from_slice(&target);
        header.extend_from_slice(b"\r\n");
        stream.write_all(&header).await?;
        Ok(stream)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(TABLE[(*b >> 4) as usize] as char);
        s.push(TABLE[(*b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_hex_is_56_chars() {
        let mut h = Sha224::new();
        h.update(b"hello");
        let s = hex_encode(&h.finalize());
        assert_eq!(s.len(), 56);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
