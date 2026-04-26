//! 出站注册表 —— 把 [`ParsedNode`] 转化为 [`Arc<dyn OutboundAdapter>`]。
//!
//! 内置规则：direct / block 自动注册；其它协议按 [`NodeProtocol`] 选择。

use std::collections::BTreeMap;
use std::sync::Arc;

use core_config::node_uri::{NodeProtocol, ParsedNode};

use crate::adapter::SharedOutbound;
use crate::block::BlockOutbound;
use crate::direct::DirectOutbound;
use crate::http::HttpOutbound;
use crate::proto::shadowsocks::{ShadowsocksOutbound, SsCipher};
use crate::proto::trojan::TrojanOutbound;
use crate::proto::vless::VlessOutbound;
use crate::socks5::Socks5Outbound;
use crate::stub::StubOutbound;
use crate::transport::WsOptions;

pub type ResolveFn = Arc<dyn Fn(&str) -> Option<SharedOutbound> + Send + Sync>;

#[derive(Default)]
pub struct OutboundRegistry {
    map: BTreeMap<String, SharedOutbound>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        let mut s = Self::default();
        s.insert("DIRECT", DirectOutbound::new());
        s.insert("BLOCK", BlockOutbound::new());
        s
    }

    pub fn insert(&mut self, name: impl Into<String>, ob: SharedOutbound) {
        self.map.insert(name.into(), ob);
    }

    pub fn get(&self, name: &str) -> Option<SharedOutbound> {
        self.map.get(name).cloned()
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.map.keys().map(|s| s.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &SharedOutbound)> {
        self.map.iter().map(|(k, v)| (k.as_str(), v))
    }
}

/// 把 [`ParsedNode`] 数组注册为一组出站。
pub fn register_nodes(reg: &mut OutboundRegistry, nodes: &[ParsedNode]) {
    for node in nodes {
        let ob = build_outbound(node);
        reg.insert(node.name.clone(), ob);
    }
}

pub fn build_outbound(node: &ParsedNode) -> SharedOutbound {
    match node.protocol {
        NodeProtocol::Direct => DirectOutbound::new(),
        NodeProtocol::Block => BlockOutbound::new(),
        NodeProtocol::Http => {
            let mut ob = HttpOutbound::new(&node.name, &node.host, node.port);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }
        NodeProtocol::Socks5 => {
            let mut ob = Socks5Outbound::new(&node.name, &node.host, node.port);
            if let (Some(u), Some(p)) = (node.user.clone(), node.password.clone()) {
                ob = ob.with_auth(u, p);
            }
            ob.into_arc()
        }
        NodeProtocol::Shadowsocks => {
            // 解析 cipher 与 password；非 AEAD/未知 cipher 走 stub
            let method = node.method.as_deref().unwrap_or("aes-256-gcm");
            let pwd = node.password.as_deref().unwrap_or("");
            match SsCipher::parse(method) {
                Some(c) if !pwd.is_empty() => Arc::new(ShadowsocksOutbound::new(
                    &node.name, &node.host, node.port, c, pwd,
                )),
                _ => StubOutbound::new(node.name.clone(), "shadowsocks(unknown-cipher)"),
            }
        }
        NodeProtocol::Trojan => {
            let pwd = node.password.clone().unwrap_or_default();
            let mut ob = TrojanOutbound::new(&node.name, &node.host, node.port, pwd);
            ob.sni = node.sni.clone().or(Some(node.host.clone()));
            ob.insecure = node.params.get("allowInsecure").map(|v| v == "1" || v == "true").unwrap_or(false);
            if let Some(alpn) = node.params.get("alpn") {
                ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
            }
            Arc::new(ob)
        }
        NodeProtocol::Vless => {
            let uuid = node
                .uuid
                .as_deref()
                .and_then(|s| uuid::Uuid::parse_str(s).ok())
                .unwrap_or_else(uuid::Uuid::nil);
            let mut ob = VlessOutbound::new(&node.name, &node.host, node.port, uuid);
            ob.tls = node.tls;
            ob.sni = node.sni.clone().or(Some(node.host.clone()));
            ob.insecure = node.params.get("allowInsecure").map(|v| v == "1" || v == "true").unwrap_or(false);
            if let Some(alpn) = node.params.get("alpn") {
                ob.alpn = alpn.split(',').map(|s| s.trim().to_string()).collect();
            }
            if node.transport == "ws" {
                ob.ws = Some(WsOptions {
                    enabled: true,
                    path: node.params.get("path").cloned().unwrap_or_else(|| "/".into()),
                    host: node.params.get("host").cloned(),
                    headers: vec![],
                });
            }
            Arc::new(ob)
        }
        ref other => StubOutbound::new(node.name.clone(), proto_static_name(other)),
    }
}

fn proto_static_name(p: &NodeProtocol) -> &'static str {
    match p {
        NodeProtocol::Shadowsocks => "shadowsocks",
        NodeProtocol::ShadowsocksR => "shadowsocksr",
        NodeProtocol::Vmess => "vmess",
        NodeProtocol::Vless => "vless",
        NodeProtocol::Trojan => "trojan",
        NodeProtocol::Hysteria => "hysteria",
        NodeProtocol::Hysteria2 => "hysteria2",
        NodeProtocol::Tuic => "tuic",
        NodeProtocol::Wireguard => "wireguard",
        NodeProtocol::Ssh => "ssh",
        NodeProtocol::Snell => "snell",
        NodeProtocol::AnyTls => "anytls",
        NodeProtocol::Mieru => "mieru",
        NodeProtocol::Sudoku => "sudoku",
        NodeProtocol::TrustTunnel => "trusttunnel",
        _ => "stub",
    }
}
