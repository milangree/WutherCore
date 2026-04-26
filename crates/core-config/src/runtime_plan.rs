//! 把用户友好的 YAML 编译成运行时计划 (`RuntimePlan`)。
//!
//! 流程对应 §3.4：YAML -> profile 默认值 -> feeds/nodes 展开 ->
//! 节点 URI 解析 -> groups 选择器 -> route 规则图 -> resolver 策略 ->
//! capture 接管计划 -> smart 评分器 -> runtime graph。
//!
//! 这里产出的结构是给 `core-runtime` / `core-route` / `core-outbound`
//! 共同消费的 *已展开* 数据，而非 YAML 原貌。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigResult};
use crate::model::*;
use crate::node_uri::{parse_uri, NodeProtocol, ParsedNode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub version: u32,
    pub profile: Profile,
    pub name: String,
    pub listen: ListenPlan,
    pub feeds: BTreeMap<String, FeedDetail>,
    pub nodes: Vec<ParsedNode>,
    pub groups: BTreeMap<String, GroupPlan>,
    pub route: RoutePlan,
    pub resolver: Resolver,
    pub capture: Capture,
    pub smart: Smart,
    pub ui: Ui,
    pub mesh: Mesh,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenPlan {
    pub mixed: Option<MixedListen>,
    pub panel: Option<PanelListen>,
    pub share: Share,
    pub auth: Vec<UserPass>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedListen {
    pub host: String,
    pub port: u16,
    pub udp: bool,
}

impl MixedListen {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|_| ConfigError::invalid(format!("非法监听地址: {}:{}", self.host, self.port)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelListen {
    pub host: String,
    pub port: u16,
}

impl PanelListen {
    pub fn socket_addr(&self) -> ConfigResult<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|_| ConfigError::invalid(format!("非法面板地址: {}:{}", self.host, self.port)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPass {
    pub user: String,
    pub pass: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPlan {
    pub name: String,
    pub choose: ChooseStrategy,
    /// 已展开成的具体 node 名集合。
    pub members: Vec<String>,
    pub prefer: Vec<String>,
    pub avoid: Vec<String>,
    pub check: Option<String>,
    pub sticky: Option<String>,
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutePlan {
    pub preset: String,
    pub r#final: String,
    /// 编译后的规则；preset 已经展开为 steps。
    pub steps: Vec<RouteStep>,
    /// route.sets 原样保留，由 core-ruleset 接管。
    #[serde(default)]
    pub sets: BTreeMap<String, RuleSetSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStep {
    pub matcher: RouteMatcher,
    pub action: RouteAction,
    /// 原始用户行，便于 explain 输出。
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum RouteMatcher {
    /// 兜底
    Any,
    /// 局域网 / 本机 / mDNS / 私有地址。
    Home,
    /// 中国大陆常用域名/IP 集。
    Cn,
    /// 广告/跟踪。
    Ads,
    /// 内置服务别名：telegram/youtube/...
    Service(String),
    Domain(String),
    Suffix(String),
    Cidr(String),
    Port(u16),
    Network(String),
    Process(String),
    /// 外部规则集（route.sets.<name>）。
    Set(String),
    /// L7 协议指纹（stun/dtls/quic/tls/sni/http/webrtc）。
    Proto(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Block,
    Group(String),
}

/* ---------------- compile ---------------- */

/// 用户配置 -> RuntimePlan。要求 [`apply_defaults`] 已执行。
pub fn compile(cfg: UserConfig) -> ConfigResult<RuntimePlan> {
    let listen = compile_listen(&cfg)?;
    let feeds = compile_feeds(&cfg.feeds);
    let nodes = compile_nodes(&cfg.nodes)?;
    let groups = compile_groups(&cfg, &nodes)?;
    let cfg_route = cfg.route.clone().unwrap_or_default();
    let route_sets = cfg_route.sets.clone();
    let route = compile_route(cfg_route, &groups, route_sets)?;
    let resolver = cfg.resolver.unwrap_or_default();
    let capture = cfg.capture.unwrap_or_default();
    validate_capture_platform(&capture)?;
    let smart = cfg.smart.unwrap_or_default();
    let ui = cfg.ui.unwrap_or_default();
    let mesh = cfg.mesh.unwrap_or_default();
    Ok(RuntimePlan {
        version: cfg.version,
        profile: cfg.profile,
        name: cfg.name.unwrap_or_else(|| "rpkernel".into()),
        listen,
        feeds,
        nodes,
        groups,
        route,
        resolver,
        capture,
        smart,
        ui,
        mesh,
    })
}

fn compile_listen(cfg: &UserConfig) -> ConfigResult<ListenPlan> {
    let listen = cfg.listen.clone().unwrap_or(Listen {
        local: None,
        panel: None,
        share: None,
        auth: vec![],
    });

    let share = listen.share.unwrap_or(Share::False);
    let host_for = |share: Share| -> &'static str {
        match share {
            Share::False => "127.0.0.1",
            Share::Home | Share::All => "0.0.0.0",
        }
    };

    let mixed = listen.local.map(|l| match l {
        ListenLocal::Port(p) => MixedListen {
            host: host_for(share).into(),
            port: p,
            udp: true,
        },
        ListenLocal::Detail(d) => MixedListen {
            host: if d.host.is_empty() { host_for(share).into() } else { d.host },
            port: d.port,
            udp: d.udp,
        },
    });

    let panel = listen.panel.and_then(|p| match p {
        PanelBind::Off(false) => None,
        PanelBind::Off(true) => Some(PanelListen {
            host: host_for(share).into(),
            port: 9090,
        }),
        PanelBind::Port(port) => Some(PanelListen {
            host: host_for(share).into(),
            port,
        }),
        PanelBind::Address(addr) => {
            let parts: Vec<&str> = addr.rsplitn(2, ':').collect();
            if parts.len() == 2 {
                let port = parts[0].parse().ok();
                if let Some(port) = port {
                    return Some(PanelListen {
                        host: parts[1].to_string(),
                        port,
                    });
                }
            }
            None
        }
    });

    let auth = listen
        .auth
        .iter()
        .filter_map(|s| s.split_once(':').map(|(u, p)| UserPass { user: u.into(), pass: p.into() }))
        .collect();

    Ok(ListenPlan {
        mixed,
        panel,
        share,
        auth,
    })
}

fn compile_feeds(feeds: &BTreeMap<String, FeedSpec>) -> BTreeMap<String, FeedDetail> {
    feeds
        .iter()
        .map(|(k, v)| {
            let detail = match v {
                FeedSpec::Url(u) => FeedDetail {
                    url: u.clone(),
                    every: Duration::from_secs(12 * 3600),
                    via: "direct".into(),
                    keep: Default::default(),
                    drop: Default::default(),
                    rename: Default::default(),
                },
                FeedSpec::Detail(d) => d.clone(),
            };
            (k.clone(), detail)
        })
        .collect()
}

fn compile_nodes(specs: &[NodeSpec]) -> ConfigResult<Vec<ParsedNode>> {
    let mut out = Vec::with_capacity(specs.len());
    let mut seen = std::collections::HashSet::new();
    for spec in specs {
        let mut node = match spec {
            NodeSpec::Uri(u) => parse_uri(u)?,
            NodeSpec::Detail(d) => detail_to_parsed(d)?,
        };
        if !seen.insert(node.name.clone()) {
            // 同名节点自动追加序号
            let mut i = 2;
            loop {
                let candidate = format!("{}-{}", node.name, i);
                if seen.insert(candidate.clone()) {
                    node.name = candidate;
                    break;
                }
                i += 1;
            }
        }
        out.push(node);
    }
    Ok(out)
}

fn detail_to_parsed(d: &NodeDetail) -> ConfigResult<ParsedNode> {
    if let Some(link) = &d.link {
        let mut n = parse_uri(link)?;
        n.name = d.name.clone();
        return Ok(n);
    }
    let proto = d
        .protocol
        .as_deref()
        .map(NodeProtocol::from_scheme)
        .ok_or_else(|| ConfigError::bad_node(format!("node {} 缺少 protocol", d.name)))?;
    let address = d
        .address
        .as_deref()
        .ok_or_else(|| ConfigError::bad_node(format!("node {} 缺少 address", d.name)))?;
    let (host, port) = address.rsplit_once(':').ok_or_else(|| {
        ConfigError::bad_node(format!("node {} address 缺少端口: {}", d.name, address))
    })?;
    let port: u16 = port
        .parse()
        .map_err(|_| ConfigError::bad_node(format!("node {} 端口非法: {}", d.name, port)))?;
    let mut node = ParsedNode::new(d.name.clone(), proto, host.trim_matches(|c| c == '[' || c == ']'), port);
    if let Some(login) = &d.login {
        node.user = login.user.clone();
        node.password = login.password.clone();
        node.uuid = login.uuid.clone();
    }
    if let Some(secure) = &d.secure {
        node.tls = secure.tls;
        node.sni = secure.sni.clone();
    }
    if let Some(transport) = &d.transport {
        node.transport = transport.kind.clone();
    }
    if let Some(network) = &d.network {
        node.udp = network.udp;
    }
    Ok(node)
}

fn compile_groups(cfg: &UserConfig, nodes: &[ParsedNode]) -> ConfigResult<BTreeMap<String, GroupPlan>> {
    let mut out = BTreeMap::new();
    let valid_feeds: std::collections::HashSet<&str> = cfg.feeds.keys().map(|s| s.as_str()).collect();
    for (name, g) in &cfg.groups {
        let mut members = Vec::new();
        for src in &g.r#use {
            if src == "nodes" {
                for n in nodes {
                    members.push(n.name.clone());
                }
                continue;
            }
            if valid_feeds.contains(src.as_str()) {
                // feeds 节点在运行时按需展开（订阅刷新），这里只做引用记录。
                members.push(format!("feed:{src}"));
                continue;
            }
            // 也允许直接引用具体节点名
            if nodes.iter().any(|n| &n.name == src) {
                members.push(src.clone());
                continue;
            }
            let valid: Vec<String> = valid_feeds
                .iter()
                .map(|s| s.to_string())
                .chain(std::iter::once("nodes".into()))
                .collect();
            return Err(ConfigError::unknown_ref(format!(
                "groups.{name}.use 引用了 \"{src}\""
            ))
            .at(format!("groups.{name}"))
            .hint(format!(
                "可用来源只有 {} 或具体的 node 名",
                valid.join("、")
            )));
        }
        out.insert(
            name.clone(),
            GroupPlan {
                name: name.clone(),
                choose: g.choose,
                members,
                prefer: g.prefer.clone(),
                avoid: g.avoid.clone(),
                check: g.check.clone(),
                sticky: g.sticky.clone(),
                path: g.path.clone(),
            },
        );
    }
    Ok(out)
}

fn compile_route(
    route: Route,
    groups: &BTreeMap<String, GroupPlan>,
    sets: BTreeMap<String, RuleSetSpec>,
) -> ConfigResult<RoutePlan> {
    let preset = if route.preset.is_empty() { "cn_smart".to_string() } else { route.preset };
    let mut steps = Vec::new();

    let final_target = route.r#final.clone();
    if !groups.contains_key(&final_target) && final_target != "direct" && final_target != "block" {
        return Err(ConfigError::bad_route(format!(
            "route.final = \"{final_target}\" 未定义为分组"
        ))
        .hint("把 final 改为已有分组名，或新增 groups.<name>"));
    }

    match preset.as_str() {
        "cn_smart" => {
            steps.push(rs(RouteMatcher::Home, RouteAction::Direct, "preset:cn_smart home"));
            steps.push(rs(RouteMatcher::Cn, RouteAction::Direct, "preset:cn_smart cn"));
            steps.push(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:cn_smart any",
            ));
        }
        "global" => {
            steps.push(rs(RouteMatcher::Home, RouteAction::Direct, "preset:global home"));
            steps.push(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:global any",
            ));
        }
        "direct" => {
            steps.push(rs(RouteMatcher::Any, RouteAction::Direct, "preset:direct any"));
        }
        "privacy" => {
            steps.push(rs(RouteMatcher::Home, RouteAction::Direct, "preset:privacy home"));
            steps.push(rs(
                RouteMatcher::Any,
                RouteAction::Group(final_target.clone()),
                "preset:privacy any",
            ));
        }
        "custom" => {}
        other => {
            return Err(ConfigError::bad_route(format!("未知 preset: {other}"))
                .hint("可选 preset: cn_smart / global / direct / privacy / custom"));
        }
    };

    for line in &route.steps {
        steps.push(parse_step_line(line, groups, &final_target)?);
    }

    if !steps.iter().any(|s| matches!(s.matcher, RouteMatcher::Any)) {
        steps.push(rs(
            RouteMatcher::Any,
            RouteAction::Group(final_target.clone()),
            "auto-fallback",
        ));
    }

    Ok(RoutePlan {
        preset,
        r#final: final_target,
        steps,
        sets,
    })
}

fn rs(matcher: RouteMatcher, action: RouteAction, src: &str) -> RouteStep {
    RouteStep {
        matcher,
        action,
        source: src.into(),
    }
}

fn parse_step_line(
    line: &str,
    groups: &BTreeMap<String, GroupPlan>,
    final_target: &str,
) -> ConfigResult<RouteStep> {
    let (lhs, rhs) = line
        .split_once("->")
        .ok_or_else(|| ConfigError::bad_route(format!("规则缺少 -> : {line}")))?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();

    let matcher = match lhs {
        "home" => RouteMatcher::Home,
        "cn" => RouteMatcher::Cn,
        "ads" => RouteMatcher::Ads,
        "any" | "*" | "final" => RouteMatcher::Any,
        s if s.starts_with("domain:") => RouteMatcher::Domain(s[7..].into()),
        s if s.starts_with("suffix:") => RouteMatcher::Suffix(s[7..].into()),
        s if s.starts_with("ip:") => RouteMatcher::Cidr(s[3..].into()),
        s if s.starts_with("port:") => RouteMatcher::Port(
            s[5..]
                .parse()
                .map_err(|_| ConfigError::bad_route(format!("非法端口: {s}")))?,
        ),
        s if s.starts_with("network:") => RouteMatcher::Network(s[8..].into()),
        s if s.starts_with("process:") => RouteMatcher::Process(s[8..].into()),
        s if s.starts_with("set:") => RouteMatcher::Set(s[4..].into()),
        s if s.starts_with("proto:") => RouteMatcher::Proto(s[6..].into()),
        // sing-box 风格别名：sni:foo.com → 等价 suffix:foo.com 但只在 SNI 命中
        s if s.starts_with("sni:") => RouteMatcher::Suffix(s[4..].into()),
        // 内置服务别名
        "telegram" | "youtube" | "netflix" | "github" | "apple" | "google" => {
            RouteMatcher::Service(lhs.into())
        }
        other => RouteMatcher::Service(other.into()),
    };

    let action = match rhs {
        "direct" => RouteAction::Direct,
        "block" => RouteAction::Block,
        "main" if !groups.contains_key("main") && final_target == "main" => {
            RouteAction::Group("main".into())
        }
        name if groups.contains_key(name) => RouteAction::Group(name.into()),
        other => {
            return Err(ConfigError::bad_route(format!("规则右侧引用未定义 group: {other}"))
                .at(format!("steps: {line}"))
                .hint("把右侧改为已存在的分组、direct 或 block"));
        }
    };

    Ok(RouteStep {
        matcher,
        action,
        source: line.into(),
    })
}

fn validate_capture_platform(c: &Capture) -> ConfigResult<()> {
    if !c.on {
        return Ok(());
    }
    let os = std::env::consts::OS;
    let ok = match c.method {
        CaptureMethod::Auto | CaptureMethod::VirtualNic => true,
        CaptureMethod::Tproxy | CaptureMethod::Redirect => os == "linux" || os == "android",
    };
    if !ok {
        return Err(ConfigError::new(crate::error::ConfigErrorKind::UnsupportedPlatform(format!(
            "capture.method={:?} 在当前平台 ({os}) 不支持",
            c.method
        )))
        .hint("改成 method: auto 或 method: virtual_nic"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::apply_defaults;

    fn compile_cfg(yaml: &str) -> RuntimePlan {
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        compile(cfg).unwrap()
    }

    #[test]
    fn cn_smart_preset_expanded() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
"#,
        );
        let kinds: Vec<_> = plan.route.steps.iter().map(|s| &s.matcher).collect();
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Home)));
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Cn)));
        assert!(kinds.iter().any(|m| matches!(m, RouteMatcher::Any)));
    }

    #[test]
    fn custom_steps_compile() {
        let plan = compile_cfg(
            r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
  ads_block:
    choose: smart
    use: [nodes]
route:
  preset: custom
  steps:
    - "home -> direct"
    - "ads -> block"
    - "domain:example.com -> direct"
    - "any -> main"
"#,
        );
        assert_eq!(plan.route.preset, "custom");
        assert!(plan
            .route
            .steps
            .iter()
            .any(|s| matches!(s.matcher, RouteMatcher::Domain(ref d) if d == "example.com")));
    }

    #[test]
    fn final_must_exist_as_group() {
        let yaml = r#"
version: 1
profile: desktop
nodes: ["ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK"]
groups:
  main:
    choose: smart
    use: [nodes]
route:
  preset: cn_smart
  final: ghost
"#;
        let mut cfg: UserConfig = serde_yaml::from_str(yaml).unwrap();
        apply_defaults(&mut cfg);
        let err = compile(cfg).unwrap_err();
        assert!(err.to_string().contains("ghost"));
    }
}
