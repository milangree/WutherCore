//! 订阅格式解析 + 过滤/重命名。

use base64::Engine;
use core_config::model::FeedDetail;
use core_config::node_uri::{parse_uri, NodeProtocol, ParsedNode};
use serde::Deserialize;
use tracing::{debug, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatHint {
    Auto,
    Base64,
    ClashYaml,
    PlainUri,
    Sip008,
}

/// 主入口：尝试自动嗅探格式并解析为节点列表。
pub fn parse_feed_payload(raw: &[u8], hint: FormatHint) -> Vec<ParsedNode> {
    // 先尝试 UTF-8。订阅几乎都是文本。
    let text = String::from_utf8_lossy(raw).into_owned();
    let trimmed = text.trim();

    let actual = match hint {
        FormatHint::Auto => sniff(trimmed),
        other => other,
    };
    debug!(target: "feeds::parser", ?actual, len = trimmed.len(), "parse feed");

    let mut nodes = match actual {
        FormatHint::Base64 => parse_base64(trimmed),
        FormatHint::ClashYaml => parse_clash_yaml(trimmed),
        FormatHint::PlainUri => parse_plain(trimmed),
        FormatHint::Sip008 => parse_sip008(trimmed),
        FormatHint::Auto => Vec::new(),
    };

    // 失败回退：base64 失败试 plain，反之亦然。
    if nodes.is_empty() && actual != FormatHint::PlainUri {
        let alt = parse_plain(trimmed);
        if !alt.is_empty() {
            nodes = alt;
        }
    }
    if nodes.is_empty() && actual != FormatHint::ClashYaml && trimmed.contains("proxies:") {
        nodes = parse_clash_yaml(trimmed);
    }
    nodes
}

fn sniff(s: &str) -> FormatHint {
    if s.starts_with('{') && s.contains("\"servers\"") {
        return FormatHint::Sip008;
    }
    if s.contains("proxies:") || s.starts_with("proxies:") {
        return FormatHint::ClashYaml;
    }
    if s.contains("://") {
        return FormatHint::PlainUri;
    }
    // 默认按 base64 尝试
    FormatHint::Base64
}

fn parse_plain(s: &str) -> Vec<ParsedNode> {
    s.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| match parse_uri(l) {
            Ok(n) => Some(n),
            Err(e) => {
                debug!(target: "feeds::parser", line = l, error = %e, "skip bad uri");
                None
            }
        })
        .collect()
}

fn parse_base64(s: &str) -> Vec<ParsedNode> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    let cleaned = s.replace(['\n', '\r', ' '], "");
    let decoded = URL_SAFE_NO_PAD
        .decode(cleaned.trim_end_matches('='))
        .ok()
        .or_else(|| STANDARD.decode(&cleaned).ok());
    match decoded {
        Some(bytes) => parse_plain(&String::from_utf8_lossy(&bytes)),
        None => Vec::new(),
    }
}

#[derive(Deserialize)]
struct ClashRoot {
    #[serde(default)]
    proxies: Vec<serde_yaml::Value>,
}

fn parse_clash_yaml(s: &str) -> Vec<ParsedNode> {
    let root: ClashRoot = match serde_yaml::from_str(s) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "feeds::parser", error = %e, "clash yaml parse failed");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(root.proxies.len());
    for v in root.proxies {
        let map = match v.as_mapping() {
            Some(m) => m,
            None => continue,
        };
        if let Some(node) = clash_proxy_to_node(map) {
            out.push(node);
        }
    }
    out
}

fn clash_proxy_to_node(m: &serde_yaml::Mapping) -> Option<ParsedNode> {
    let g = |k: &str| m.get(&serde_yaml::Value::String(k.into())).cloned();
    let str_g = |k: &str| g(k).and_then(|v| v.as_str().map(String::from));
    let u64_g = |k: &str| {
        g(k).and_then(|v| {
            v.as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        })
    };

    let name = str_g("name")?;
    let kind = str_g("type")?;
    let host = str_g("server")?;
    let port = u64_g("port")? as u16;

    let proto = match kind.as_str() {
        "ss" => NodeProtocol::Shadowsocks,
        "ssr" => NodeProtocol::ShadowsocksR,
        "vmess" => NodeProtocol::Vmess,
        "vless" => NodeProtocol::Vless,
        "trojan" => NodeProtocol::Trojan,
        "hysteria" => NodeProtocol::Hysteria,
        "hysteria2" | "hy2" => NodeProtocol::Hysteria2,
        "tuic" => NodeProtocol::Tuic,
        "wireguard" => NodeProtocol::Wireguard,
        "ssh" => NodeProtocol::Ssh,
        "snell" => NodeProtocol::Snell,
        "http" => NodeProtocol::Http,
        "socks5" | "socks" => NodeProtocol::Socks5,
        other => NodeProtocol::Other(other.into()),
    };
    let mut node = ParsedNode::new(name, proto.clone(), host, port);
    node.password = str_g("password");
    node.uuid = str_g("uuid");
    node.method = str_g("cipher").or_else(|| str_g("method"));
    node.tls = g("tls").and_then(|v| v.as_bool()).unwrap_or(false)
        || matches!(proto, NodeProtocol::Trojan | NodeProtocol::Hysteria2 | NodeProtocol::Tuic);
    node.sni = str_g("sni").or_else(|| str_g("servername"));
    if let Some(net) = str_g("network") {
        node.transport = net;
    }
    if let Some(udp) = g("udp").and_then(|v| v.as_bool()) {
        node.udp = udp;
    }
    Some(node)
}

#[derive(Deserialize)]
struct Sip008 {
    servers: Vec<Sip008Server>,
}
#[derive(Deserialize)]
struct Sip008Server {
    remarks: Option<String>,
    server: String,
    server_port: u16,
    method: String,
    password: String,
}

fn parse_sip008(s: &str) -> Vec<ParsedNode> {
    let r: Sip008 = match serde_json::from_str(s) {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "feeds::parser", error = %e, "sip008 parse failed");
            return Vec::new();
        }
    };
    r.servers
        .into_iter()
        .map(|s| {
            let mut n = ParsedNode::new(
                s.remarks.unwrap_or_else(|| format!("ss-{}", s.server)),
                NodeProtocol::Shadowsocks,
                s.server,
                s.server_port,
            );
            n.method = Some(s.method);
            n.password = Some(s.password);
            n
        })
        .collect()
}

/* ---------------- 过滤 / 重命名 ---------------- */

pub fn apply_filter_rename(detail: &FeedDetail, mut nodes: Vec<ParsedNode>) -> Vec<ParsedNode> {
    // drop 优先级 > keep
    if !detail.drop.name_has.is_empty() {
        let drops = detail.drop.name_has.clone();
        nodes.retain(|n| !drops.iter().any(|d| n.name.contains(d)));
    }
    if !detail.keep.name_has.is_empty() {
        let keeps = detail.keep.name_has.clone();
        nodes.retain(|n| keeps.iter().any(|k| n.name.contains(k)));
    }
    if let Some(prefix) = detail.rename.add_prefix.as_ref() {
        for n in &mut nodes {
            if !n.name.starts_with(prefix) {
                n.name = format!("{prefix}{}", n.name);
            }
        }
    }
    if !detail.rename.remove.is_empty() {
        for n in &mut nodes {
            for r in &detail.rename.remove {
                if !r.is_empty() {
                    n.name = n.name.replace(r, "");
                }
            }
            n.name = n.name.trim().to_string();
        }
    }
    // 名称去重（保留先到的）
    let mut seen = std::collections::HashSet::new();
    nodes.retain(|n| seen.insert(n.name.clone()));
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::model::{FeedDetail, FeedFilter, FeedRename};
    use std::time::Duration;

    fn detail() -> FeedDetail {
        FeedDetail {
            url: String::new(),
            every: Duration::from_secs(3600),
            via: "direct".into(),
            keep: FeedFilter::default(),
            drop: FeedFilter::default(),
            rename: FeedRename::default(),
        }
    }

    #[test]
    fn parse_plain_uri() {
        let s = "trojan://pwd@example.com:443?sni=example.com#HK-1\nss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#JP-1\n";
        let nodes = parse_feed_payload(s.as_bytes(), FormatHint::PlainUri);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "HK-1");
        assert_eq!(nodes[1].name, "JP-1");
    }

    #[test]
    fn parse_base64_subscription() {
        let inner = "trojan://pwd@example.com:443?sni=example.com#HK-1\nss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#JP-1";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let nodes = parse_feed_payload(b64.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn parse_clash_yaml_proxies() {
        let yaml = r#"
proxies:
  - name: HK-1
    type: trojan
    server: example.com
    port: 443
    password: pwd
    sni: example.com
  - name: JP-1
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pwd
"#;
        let nodes = parse_feed_payload(yaml.as_bytes(), FormatHint::Auto);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].protocol, NodeProtocol::Trojan);
        assert_eq!(nodes[1].method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn keep_drop_rename_dedup() {
        let nodes = parse_feed_payload(
            (b"trojan://pwd@a:443#HK-1x\n\
              trojan://pwd@b:443#JP-2x\n\
              trojan://pwd@c:443#US-3x\n\
              trojan://pwd@d:443#Expire-2026").as_ref(),
            FormatHint::PlainUri,
        );
        assert_eq!(nodes.len(), 4);
        let mut d = detail();
        d.keep.name_has = vec!["HK".into(), "JP".into(), "US".into()];
        d.drop.name_has = vec!["Expire".into()];
        d.rename.remove = vec!["x".into()];
        d.rename.add_prefix = Some("B-".into());
        let out = apply_filter_rename(&d, nodes);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].name, "B-HK-1");
        assert_eq!(out[2].name, "B-US-3");
    }
}
