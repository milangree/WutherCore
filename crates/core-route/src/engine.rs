//! 路由匹配引擎。
//!
//! 输入：[`FlowContext`] —— 一次连接的目标（域名/IP/端口/网络/进程）。
//! 输出：[`RouteDecision`] —— direct / block / group("xxx")。

use std::net::IpAddr;
use std::sync::Arc;

use core_config::runtime_plan::{RouteAction, RouteMatcher, RoutePlan};
use core_ruleset::RulesetIndex;
use ipnet::IpNet;

use crate::builtin;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

impl NetworkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowContext {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub network: NetworkKind,
    pub process: Option<String>,
    /// L7 协议指纹 —— 由 inbound/capture 嗅探首包后写入；用于 `proto:` 规则。
    pub protocol: Option<crate::sniff::L7Proto>,
}

impl FlowContext {
    pub fn for_domain(host: impl Into<String>, port: u16, network: NetworkKind) -> Self {
        Self {
            host: host.into(),
            ip: None,
            port,
            network,
            process: None,
            protocol: None,
        }
    }

    pub fn for_ip(ip: IpAddr, port: u16, network: NetworkKind) -> Self {
        Self {
            host: ip.to_string(),
            ip: Some(ip),
            port,
            network,
            process: None,
            protocol: None,
        }
    }

    /// 链式：附加嗅探到的协议；SNI 场景自动把 host 同步为 SNI 域名。
    pub fn with_protocol(mut self, p: crate::sniff::L7Proto) -> Self {
        if let crate::sniff::L7Proto::Sni(sni) = &p {
            if !sni.is_empty() && self.host.parse::<std::net::IpAddr>().is_ok() {
                self.host = sni.clone();
            }
        }
        self.protocol = Some(p);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Block,
    Group(String),
}

impl RouteDecision {
    pub fn from_action(a: &RouteAction) -> Self {
        match a {
            RouteAction::Direct => RouteDecision::Direct,
            RouteAction::Block => RouteDecision::Block,
            RouteAction::Group(g) => RouteDecision::Group(g.clone()),
        }
    }
}

/// 路由引擎；按 [`RoutePlan::steps`] 顺序匹配。
#[derive(Debug, Clone)]
pub struct RouteEngine {
    plan: Arc<RoutePlan>,
    extra_cidrs: Vec<IpNet>,
    rulesets: Option<Arc<RulesetIndex>>,
}

impl RouteEngine {
    pub fn new(plan: RoutePlan) -> Self {
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: None,
        }
    }

    pub fn with_rulesets(plan: RoutePlan, rulesets: Arc<RulesetIndex>) -> Self {
        Self {
            plan: Arc::new(plan),
            extra_cidrs: Vec::new(),
            rulesets: Some(rulesets),
        }
    }

    pub fn plan(&self) -> &RoutePlan {
        &self.plan
    }

    pub fn rulesets(&self) -> Option<Arc<RulesetIndex>> {
        self.rulesets.clone()
    }

    pub fn decide(&self, ctx: &FlowContext) -> (RouteDecision, &'static str, String) {
        for step in &self.plan.steps {
            if step_matches(&step.matcher, ctx, &self.extra_cidrs, self.rulesets.as_ref()) {
                return (RouteDecision::from_action(&step.action), matcher_kind(&step.matcher), step.source.clone());
            }
        }
        (RouteDecision::Direct, "fallback", "implicit-direct".into())
    }
}

fn matcher_kind(m: &RouteMatcher) -> &'static str {
    match m {
        RouteMatcher::Any => "any",
        RouteMatcher::Home => "home",
        RouteMatcher::Cn => "cn",
        RouteMatcher::Ads => "ads",
        RouteMatcher::Service(_) => "service",
        RouteMatcher::Domain(_) => "domain",
        RouteMatcher::Suffix(_) => "suffix",
        RouteMatcher::Cidr(_) => "ip",
        RouteMatcher::Port(_) => "port",
        RouteMatcher::Network(_) => "network",
        RouteMatcher::Process(_) => "process",
        RouteMatcher::Set(_) => "set",
        RouteMatcher::Proto(_) => "proto",
    }
}

fn step_matches(
    m: &RouteMatcher,
    ctx: &FlowContext,
    extra_cidrs: &[IpNet],
    rulesets: Option<&Arc<RulesetIndex>>,
) -> bool {
    match m {
        RouteMatcher::Any => true,
        RouteMatcher::Home => match_home(ctx),
        RouteMatcher::Cn => match_cn(ctx),
        RouteMatcher::Ads => match_suffix_list(&ctx.host, builtin::ADS_SUFFIXES),
        RouteMatcher::Service(name) => match_suffix_list(&ctx.host, builtin::service_suffixes(name)),
        RouteMatcher::Domain(d) => host_eq(&ctx.host, d),
        RouteMatcher::Suffix(s) => host_suffix(&ctx.host, s),
        RouteMatcher::Cidr(s) => match_cidr(ctx, s, extra_cidrs),
        RouteMatcher::Port(p) => ctx.port == *p,
        RouteMatcher::Network(n) => n.eq_ignore_ascii_case(ctx.network.as_str()),
        RouteMatcher::Process(name) => ctx
            .process
            .as_ref()
            .map(|p| p.eq_ignore_ascii_case(name))
            .unwrap_or(false),
        RouteMatcher::Set(name) => match rulesets {
            Some(idx) => idx
                .get(name)
                .map(|m| m.matches(&ctx.host, ctx.ip, Some(ctx.port), ctx.process.as_deref()))
                .unwrap_or(false),
            None => false,
        },
        RouteMatcher::Proto(name) => ctx
            .protocol
            .as_ref()
            .map(|p| crate::sniff::proto_name_matches(name, p))
            .unwrap_or(false),
    }
}

fn host_eq(host: &str, target: &str) -> bool {
    host.eq_ignore_ascii_case(target)
}

fn host_suffix(host: &str, suffix: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let s = suffix.trim_start_matches('.').to_ascii_lowercase();
    h == s || h.ends_with(&format!(".{s}"))
}

fn match_suffix_list(host: &str, list: &[&str]) -> bool {
    list.iter().any(|s| host_suffix(host, s))
}

fn match_home(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::HOME_SUFFIXES) {
        return true;
    }
    if let Some(ip) = ctx.ip {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    if let Ok(ip) = ctx.host.parse::<IpAddr>() {
        return builtin::HOME_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cn(ctx: &FlowContext) -> bool {
    if match_suffix_list(&ctx.host, builtin::CN_SUFFIXES) {
        return true;
    }
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        return builtin::CN_CIDRS.iter().any(|n| n.contains(&ip));
    }
    false
}

fn match_cidr(ctx: &FlowContext, cidr: &str, extra: &[IpNet]) -> bool {
    let net: IpNet = match cidr.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    let ip = ctx.ip.or_else(|| ctx.host.parse::<IpAddr>().ok());
    if let Some(ip) = ip {
        if net.contains(&ip) {
            return true;
        }
        return extra.iter().any(|n| n.contains(&ip));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use core_config::runtime_plan::{RouteStep, RoutePlan};

    fn plan_cn_smart() -> RoutePlan {
        let mut p = RoutePlan {
            preset: "cn_smart".into(),
            r#final: "main".into(),
            steps: vec![],
            sets: Default::default(),
        };
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Home,
            action: RouteAction::Direct,
            source: "preset:home".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Cn,
            action: RouteAction::Direct,
            source: "preset:cn".into(),
        });
        p.steps.push(RouteStep {
            matcher: RouteMatcher::Any,
            action: RouteAction::Group("main".into()),
            source: "preset:any".into(),
        });
        p
    }

    #[test]
    fn cn_domain_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.qq.com", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn lan_ip_goes_direct() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_ip("192.168.1.10".parse().unwrap(), 22, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Direct);
    }

    #[test]
    fn unknown_goes_main() {
        let eng = RouteEngine::new(plan_cn_smart());
        let ctx = FlowContext::for_domain("www.example.org", 443, NetworkKind::Tcp);
        let (d, _, _) = eng.decide(&ctx);
        assert_eq!(d, RouteDecision::Group("main".into()));
    }

    #[test]
    fn host_suffix_case_insensitive() {
        assert!(super::host_suffix("Mail.QQ.com", "qq.com"));
        assert!(!super::host_suffix("noqq.com", "qq.com"));
    }
}
