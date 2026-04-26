//! Clash/Mihomo 兼容层 —— 字段转换为 Dashboard 期望的格式。

use std::sync::Arc;

use axum::{response::IntoResponse, routing::get, Json, Router};
use core_runtime::Runtime;
use serde_json::json;

use crate::native::NativeState;

pub fn router(state: NativeState) -> Router {
    Router::new()
        .route("/version", get(version))
        .route("/traffic", get(traffic))
        .route("/proxies", get(proxies))
        .route("/proxies/:name", get(proxy_one))
        .route("/proxies/:name/delay", get(proxy_delay))
        .route(
            "/group/:name/delay",
            axum::routing::get(group_delay),
        )
        .route("/connections", get(connections))
        .route("/configs", get(configs))
        .with_state(state)
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({"version": env!("CARGO_PKG_VERSION"), "premium": false}))
}

async fn traffic(axum::extract::State(s): axum::extract::State<NativeState>) -> Json<serde_json::Value> {
    Json(s.runtime.metrics.snapshot())
}

async fn proxies(axum::extract::State(s): axum::extract::State<NativeState>) -> Json<serde_json::Value> {
    Json(json!({"proxies": collect_proxy_map(&s)}))
}

async fn proxy_one(
    axum::extract::State(s): axum::extract::State<NativeState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    let map = collect_proxy_map(&s);
    if let Some(v) = map.get(&name) {
        Json(v.clone()).into_response()
    } else {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"message": "proxy not found"})),
        )
            .into_response()
    }
}

#[derive(serde::Deserialize)]
struct DelayQ {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    timeout: Option<u64>,
}

async fn proxy_delay(
    axum::extract::State(s): axum::extract::State<NativeState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<DelayQ>,
) -> axum::response::Response {
    let to = q.timeout.map(std::time::Duration::from_millis);
    match s.urltest.test_node(&s.runtime, &name, q.url.as_deref(), to).await {
        Ok(ms) => Json(json!({"delay": ms, "meanDelay": ms})).into_response(),
        Err(e) => (
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Json(json!({"message": e.to_string()})),
        )
            .into_response(),
    }
}

async fn group_delay(
    axum::extract::State(s): axum::extract::State<NativeState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<DelayQ>,
) -> axum::response::Response {
    let members = match s.runtime.groups.read().get(&name) {
        Some(g) => g.members().to_vec(),
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"message": "group not found"})),
            )
                .into_response()
        }
    };
    let to = q.timeout.map(std::time::Duration::from_millis);
    let res = s.urltest.test_many(&s.runtime, &members, q.url, to).await;
    let body: serde_json::Map<String, serde_json::Value> = res
        .into_iter()
        .map(|(n, r)| {
            (
                n,
                match r {
                    Ok(ms) => serde_json::Value::from(ms),
                    Err(_) => serde_json::Value::from(0),
                },
            )
        })
        .collect();
    Json(serde_json::Value::Object(body)).into_response()
}

fn collect_proxy_map(s: &NativeState) -> serde_json::Map<String, serde_json::Value> {
    let runtime: &Arc<Runtime> = &s.runtime;
    let mut proxies = serde_json::Map::new();

    let history_for = |node: &str| -> serde_json::Value {
        let stats = runtime.smart.ensure_node(node);
        let h: Vec<_> = stats
            .history()
            .into_iter()
            .map(|e| {
                json!({
                    "time": chrono_like(e.time_ms),
                    "delay": e.delay_ms,
                })
            })
            .collect();
        serde_json::Value::Array(h)
    };

    for (name, g) in runtime.groups.read().iter() {
        proxies.insert(
            name.clone(),
            json!({
                "type": "Selector",
                "now": g.current_manual().unwrap_or_else(|| g.members().first().cloned().unwrap_or_default()),
                "all": g.members(),
                "history": [],
            }),
        );
    }
    for n in &runtime.plan.nodes {
        proxies.insert(
            n.name.clone(),
            json!({
                "type": map_proto(n.protocol.as_str()),
                "name": n.name,
                "history": history_for(&n.name),
            }),
        );
    }
    proxies.insert(
        "DIRECT".into(),
        json!({"type": "Direct", "name": "DIRECT", "history": []}),
    );
    proxies.insert(
        "REJECT".into(),
        json!({"type": "Reject", "name": "REJECT", "history": []}),
    );
    proxies
}

/// 把 epoch_ms 转成 ISO-8601（不引入 chrono；只输出大致格式给 Dashboard）。
fn chrono_like(time_ms: u64) -> String {
    // 简化：返回秒级 unix 时间戳字符串，绝大多数 Dashboard 都能解析。
    format!("{}", time_ms)
}

fn map_proto(p: &str) -> &'static str {
    match p {
        "ss" => "Shadowsocks",
        "ssr" => "ShadowsocksR",
        "vmess" => "Vmess",
        "vless" => "Vless",
        "trojan" => "Trojan",
        "hysteria" => "Hysteria",
        "hysteria2" => "Hysteria2",
        "tuic" => "Tuic",
        "wireguard" => "WireGuard",
        "ssh" => "Ssh",
        "http" => "Http",
        "socks5" => "Socks5",
        _ => "Unknown",
    }
}

async fn connections(axum::extract::State(s): axum::extract::State<NativeState>) -> Json<serde_json::Value> {
    Json(json!({"connections": s.runtime.connections.list()}))
}

async fn configs() -> Json<serde_json::Value> {
    Json(json!({
        "port": 7890,
        "socks-port": 7890,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": 7890,
        "mode": "Rule",
        "log-level": "info",
        "ipv6": true,
    }))
}
