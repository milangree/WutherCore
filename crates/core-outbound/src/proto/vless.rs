//! VLESS 出站（无加密版本，over TLS / TCP / WS） —— 与 mihomo / xray 互通。
//!
//! 协议头部（[reference](https://xtls.github.io/development/protocols/vless.html)）：
//! `Version(1) || UUID(16) || AddonsLen(1) || Addons || Cmd(1) || Port(2 BE) || ATYP(1) || ADDR`
//! * Version = 0x00（VLESS 当前版本）。
//! * Cmd     = 0x01 (TCP) / 0x02 (UDP) / 0x03 (Mux)。
//! * ATYP/ADDR 与 VMess 一致：0x01 IPv4 / 0x02 Domain (1B len + N) / 0x03 IPv6。
//!
//! 服务器响应：`Version(1) || AddonsLen(1) || Addons`，之后双向裸 payload。

use async_trait::async_trait;
use bytes::BufMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::transport::{tcp::TcpTransport, tls::TlsTransport, ws::WsTransport, TlsOptions, Transport, WsOptions};

#[derive(Debug, Clone, Default)]
pub struct VlessOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub uuid: Uuid,
    pub tls: bool,
    pub sni: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    pub ws: Option<WsOptions>,
}

impl VlessOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        uuid: Uuid,
    ) -> Self {
        Self {
            name: name.into(),
            host: host.into(),
            port,
            uuid,
            ..Default::default()
        }
    }
}

#[async_trait]
impl OutboundAdapter for VlessOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "vless" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: false, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        // 选择传输：ws 优先；否则 tls/tcp。
        let stream: BoxedStream = if let Some(ws) = self.ws.as_ref().filter(|w| w.enabled) {
            WsTransport::new(ws.clone(), self.tls)
                .connect(&self.host, self.port).await?
        } else if self.tls {
            TlsTransport::new(TlsOptions {
                enabled: true,
                sni: self.sni.clone(),
                insecure: self.insecure,
                alpn: self.alpn.clone(),
            })
            .connect(&self.host, self.port).await?
        } else {
            TcpTransport::default().connect(&self.host, self.port).await?
        };

        let mut stream = stream;
        let mut buf = Vec::with_capacity(64);
        buf.put_u8(0x00); // version
        buf.extend_from_slice(self.uuid.as_bytes());
        buf.put_u8(0x00); // addons length = 0
        buf.put_u8(0x01); // CONNECT (TCP)
        buf.put_u16(ctx.port);
        // ATYP + ADDR（注意：VLESS 的 ATYP 编码与 SOCKS5 不同：1=IPv4 2=Domain 3=IPv6）
        if let Ok(ip) = ctx.host.parse::<std::net::Ipv4Addr>() {
            buf.put_u8(0x01);
            buf.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = ctx.host.parse::<std::net::Ipv6Addr>() {
            buf.put_u8(0x03);
            buf.extend_from_slice(&ip.octets());
        } else {
            buf.put_u8(0x02);
            buf.put_u8(ctx.host.len().min(255) as u8);
            buf.extend_from_slice(ctx.host.as_bytes());
        }
        stream.write_all(&buf).await?;

        // 读取 server 响应：Version(1) + AddonsLen(1) + Addons
        let mut resp_head = [0u8; 2];
        stream.read_exact(&mut resp_head).await?;
        if resp_head[1] > 0 {
            let mut addons = vec![0u8; resp_head[1] as usize];
            stream.read_exact(&mut addons).await?;
        }
        Ok(stream)
    }
}
