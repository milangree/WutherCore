//! Mihomo 配置迁移工具 —— §13.3。
//!
//! MVP：把 mihomo 的 `port`/`socks-port`/`mixed-port`/`proxy-providers`/
//! `proxies` 等字段映射为 Friendly YAML。完整字段映射会在 M6 完善。

use std::collections::BTreeMap;

use serde_yaml::Value;

use crate::error::{ConfigError, ConfigResult};

/// 把 Mihomo YAML 文本转换为 Friendly YAML 文本。
pub fn migrate_mihomo(text: &str) -> ConfigResult<String> {
    let m: Value = serde_yaml::from_str(text)?;
    let m = m.as_mapping().ok_or_else(|| {
        ConfigError::invalid("Mihomo YAML 顶层必须是 mapping").hint("请检查文件是否为 YAML object")
    })?;

    let mut friendly = serde_yaml::Mapping::new();
    friendly.insert("version".into(), 1.into());
    friendly.insert("profile".into(), "desktop".into());

    // listen
    let mut listen = serde_yaml::Mapping::new();
    if let Some(p) = m
        .get(&Value::String("mixed-port".into()))
        .and_then(Value::as_u64)
    {
        listen.insert("local".into(), (p as u64).into());
    } else if let Some(p) = m.get(&Value::String("port".into())).and_then(Value::as_u64) {
        listen.insert("local".into(), (p as u64).into());
    }
    if let Some(controller) = m
        .get(&Value::String("external-controller".into()))
        .and_then(Value::as_str)
    {
        listen.insert("panel".into(), Value::String(controller.into()));
    }
    if !listen.is_empty() {
        friendly.insert("listen".into(), Value::Mapping(listen));
    }

    // feeds 来自 proxy-providers
    let mut feeds = BTreeMap::new();
    if let Some(providers) = m
        .get(&Value::String("proxy-providers".into()))
        .and_then(Value::as_mapping)
    {
        for (k, v) in providers {
            if let (Some(name), Some(url)) = (
                k.as_str(),
                v.as_mapping()
                    .and_then(|m| m.get(&Value::String("url".into())))
                    .and_then(Value::as_str),
            ) {
                feeds.insert(name.to_string(), url.to_string());
            }
        }
    }
    if !feeds.is_empty() {
        let mut map = serde_yaml::Mapping::new();
        for (k, v) in feeds {
            map.insert(Value::String(k), Value::String(v));
        }
        friendly.insert("feeds".into(), Value::Mapping(map));
    }

    // proxies -> nodes
    let mut nodes = Vec::new();
    if let Some(proxies) = m
        .get(&Value::String("proxies".into()))
        .and_then(Value::as_sequence)
    {
        for p in proxies {
            if let Some(map) = p.as_mapping() {
                if let Some(name) = map
                    .get(&Value::String("name".into()))
                    .and_then(Value::as_str)
                {
                    if let Some(uri) = mihomo_proxy_to_uri(map) {
                        nodes.push(Value::String(format!("{}#{}", uri, name)));
                    }
                }
            }
        }
    }
    if !nodes.is_empty() {
        friendly.insert("nodes".into(), Value::Sequence(nodes));
    }

    // route preset
    let mut route = serde_yaml::Mapping::new();
    route.insert("preset".into(), Value::String("cn_smart".into()));
    friendly.insert("route".into(), Value::Mapping(route));

    serde_yaml::to_string(&Value::Mapping(friendly)).map_err(Into::into)
}

fn mihomo_proxy_to_uri(p: &serde_yaml::Mapping) -> Option<String> {
    let kind = p
        .get(&Value::String("type".into()))
        .and_then(Value::as_str)?;
    // type: dns 不需要 server/port —— 是本机 DNS hijack 出站。
    if kind.eq_ignore_ascii_case("dns") {
        return Some("dns://".to_string());
    }
    let host = p
        .get(&Value::String("server".into()))
        .and_then(Value::as_str)?;
    let port = p.get(&Value::String("port".into())).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })?;
    let pwd = p
        .get(&Value::String("password".into()))
        .and_then(Value::as_str);
    let uuid = p.get(&Value::String("uuid".into())).and_then(Value::as_str);
    Some(match kind {
        "ss" => {
            let cipher = p
                .get(&Value::String("cipher".into()))
                .and_then(Value::as_str)
                .unwrap_or("aes-256-gcm");
            let pwd = pwd.unwrap_or("");
            let userinfo =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{cipher}:{pwd}"));
            format!("ss://{userinfo}@{host}:{port}")
        }
        "trojan" => format!("trojan://{}@{host}:{port}?security=tls", pwd.unwrap_or("")),
        "vless" => format!("vless://{}@{host}:{port}?security=tls", uuid.unwrap_or("")),
        "vmess" => format!("vless://{}@{host}:{port}?security=tls", uuid.unwrap_or("")),
        "hysteria2" | "hy2" => format!("hysteria2://{}@{host}:{port}", pwd.unwrap_or("")),
        _ => return None,
    })
}

use base64::Engine;
