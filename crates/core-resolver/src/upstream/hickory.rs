//! hickory-resolver 包装：DoH / DoT / UDP / TCP 上游。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use super::{DnsError, DnsUpstream};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HickoryKind {
    DoH,
    DoT,
    Udp,
    Tcp,
}

impl HickoryKind {
    fn label(&self) -> &'static str {
        match self {
            Self::DoH => "doh",
            Self::DoT => "dot",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }
    fn proto(&self) -> Protocol {
        match self {
            Self::DoH => Protocol::Https,
            Self::DoT => Protocol::Tls,
            Self::Udp => Protocol::Udp,
            Self::Tcp => Protocol::Tcp,
        }
    }
}

#[derive(Clone)]
pub struct HickoryUpstream {
    name: String,
    kind: HickoryKind,
    inner: Arc<TokioAsyncResolver>,
    client_subnet: Option<ipnet::IpNet>,
}

impl std::fmt::Debug for HickoryUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryUpstream")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .finish()
    }
}

impl HickoryUpstream {
    pub fn build(
        name: impl Into<String>,
        kind: HickoryKind,
        addr: SocketAddr,
        sni: Option<String>,
    ) -> Result<Self, DnsError> {
        let mut nsg = NameServerConfigGroup::new();
        let mut ns = NameServerConfig::new(addr, kind.proto());
        if let Some(sni) = sni.clone() {
            ns.tls_dns_name = Some(sni);
        }
        ns.trust_negative_responses = true;
        nsg.push(ns);
        let cfg = ResolverConfig::from_parts(None, vec![], nsg);
        let mut opts = ResolverOpts::default();
        opts.cache_size = 0; // 我们自己管缓存
        opts.attempts = 2;
        opts.timeout = std::time::Duration::from_secs(3);
        opts.use_hosts_file = false;
        let resolver = TokioAsyncResolver::tokio(cfg, opts);
        Ok(Self {
            name: name.into(),
            kind,
            inner: Arc::new(resolver),
            client_subnet: None,
        })
    }

    /// 设置 server 默认 ECS（与 sing-box `dns.servers[].client_subnet` 一致）。
    /// 字段已写入 upstream；下层 EDNS0 OPT 实际发送暂走 hickory 默认（待 hickory 0.25 升级）。
    pub fn with_client_subnet(mut self, net: ipnet::IpNet) -> Self {
        self.client_subnet = Some(net);
        self
    }

    /// 便捷构造：DoH URL（仅取 host:port，按 https 默认 443）。
    pub fn doh(name: impl Into<String>, host: &str, port: u16, sni: Option<String>) -> Result<Self, DnsError> {
        let ip: std::net::IpAddr = host
            .parse()
            .map_err(|_| DnsError::Failed(format!("DoH host 必须是 IP（避免循环）：{host}")))?;
        Self::build(name, HickoryKind::DoH, SocketAddr::new(ip, port), sni)
    }

    pub fn dot(name: impl Into<String>, host: &str, port: u16, sni: Option<String>) -> Result<Self, DnsError> {
        let ip: std::net::IpAddr = host
            .parse()
            .map_err(|_| DnsError::Failed(format!("DoT host 必须是 IP：{host}")))?;
        Self::build(name, HickoryKind::DoT, SocketAddr::new(ip, port), sni)
    }

    pub fn udp(name: impl Into<String>, addr: SocketAddr) -> Result<Self, DnsError> {
        Self::build(name, HickoryKind::Udp, addr, None)
    }
}

#[async_trait]
impl DnsUpstream for HickoryUpstream {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &'static str { self.kind.label() }
    fn default_client_subnet(&self) -> Option<ipnet::IpNet> { self.client_subnet }

    async fn query_a(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let r = self
            .inner
            .ipv4_lookup(host)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let v: Vec<IpAddr> = r.iter().map(|a| IpAddr::V4(a.0)).collect();
        if v.is_empty() { Err(DnsError::Empty) } else { Ok(v) }
    }
    async fn query_aaaa(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let r = self
            .inner
            .ipv6_lookup(host)
            .await
            .map_err(|e| DnsError::Failed(e.to_string()))?;
        let v: Vec<IpAddr> = r.iter().map(|a| IpAddr::V6(a.0)).collect();
        if v.is_empty() { Err(DnsError::Empty) } else { Ok(v) }
    }
}
