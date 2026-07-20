//! 语义保持的规则集 IR。
//!
//! sing-box source JSON 与后续 SRS 解码器都应产出这一结构，避免把一条复合规则
//! 展平为多个彼此独立的 classical 条目而丢失 AND / OR / invert 语义。

use std::net::IpAddr;

use ipnet::IpNet;
use regex::RegexSet;

/// 一次规则集匹配所需的结构化上下文。
///
/// source 与 destination 字段刻意分槽。调用方没有相应元数据时传 `None`，
/// 对应 predicate 的结果就是 `false`，绝不能退化成匹配另一侧。
#[derive(Debug, Clone, Copy, Default)]
pub struct RulesetMatchContext<'a> {
    pub dst_host: &'a str,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub network: Option<&'a str>,
    pub process_name: Option<&'a str>,
}

/// 已校验的闭区间端口。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Option<Self> {
        (start <= end).then_some(Self { start, end })
    }

    #[inline]
    pub fn contains(self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

/// 已完成规范化或编译的叶子 predicate。
#[derive(Debug)]
pub enum RulesetPredicate {
    Domain(Vec<String>),
    DomainSuffix(Vec<String>),
    DomainKeyword(Vec<String>),
    DomainRegex(RegexSet),
    DstIpCidr(Vec<IpNet>),
    SrcIpCidr(Vec<IpNet>),
    DstPort(Vec<PortRange>),
    SrcPort(Vec<PortRange>),
    ProcessName(Vec<String>),
    Network(Vec<String>),
}

impl RulesetPredicate {
    fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        match self {
            Self::Domain(domains) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && domains.iter().any(|domain| host == *domain)
            }
            Self::DomainSuffix(suffixes) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty()
                    && suffixes
                        .iter()
                        .any(|suffix| domain_has_suffix(&host, suffix))
            }
            Self::DomainKeyword(keywords) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && keywords.iter().any(|keyword| host.contains(keyword))
            }
            Self::DomainRegex(regex) => {
                let host = normalize_domain(ctx.dst_host);
                !host.is_empty() && regex.is_match(&host)
            }
            Self::DstIpCidr(networks) => destination_ip(ctx)
                .map(|ip| networks.iter().any(|network| network.contains(&ip)))
                .unwrap_or(false),
            Self::SrcIpCidr(networks) => ctx
                .src_ip
                .map(|ip| networks.iter().any(|network| network.contains(&ip)))
                .unwrap_or(false),
            Self::DstPort(ranges) => ctx
                .dst_port
                .map(|port| ranges.iter().any(|range| range.contains(port)))
                .unwrap_or(false),
            Self::SrcPort(ranges) => ctx
                .src_port
                .map(|port| ranges.iter().any(|range| range.contains(port)))
                .unwrap_or(false),
            Self::ProcessName(names) => ctx
                .process_name
                .map(|name| names.iter().any(|candidate| candidate == name))
                .unwrap_or(false),
            Self::Network(networks) => ctx
                .network
                .map(|network| {
                    networks
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(network))
                })
                .unwrap_or(false),
        }
    }

    fn item_count(&self) -> usize {
        match self {
            Self::Domain(items)
            | Self::DomainSuffix(items)
            | Self::DomainKeyword(items)
            | Self::ProcessName(items)
            | Self::Network(items) => items.len(),
            Self::DomainRegex(items) => items.len(),
            Self::DstIpCidr(items) | Self::SrcIpCidr(items) => items.len(),
            Self::DstPort(items) | Self::SrcPort(items) => items.len(),
        }
    }
}

/// 可由 JSON、SRS 等前端共享的布尔表达式树。
#[derive(Debug)]
pub enum RulesetExpr {
    Any(Vec<RulesetExpr>),
    All(Vec<RulesetExpr>),
    Not(Box<RulesetExpr>),
    Predicate(RulesetPredicate),
}

impl RulesetExpr {
    pub fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        match self {
            Self::Any(children) => children.iter().any(|child| child.matches(ctx)),
            Self::All(children) => children.iter().all(|child| child.matches(ctx)),
            Self::Not(child) => !child.matches(ctx),
            Self::Predicate(predicate) => predicate.matches(ctx),
        }
    }

    /// 统计叶子值数量，用于 provider 状态展示。
    pub fn item_count(&self) -> usize {
        match self {
            Self::Any(children) | Self::All(children) => {
                children.iter().map(Self::item_count).sum()
            }
            Self::Not(child) => child.item_count(),
            Self::Predicate(predicate) => predicate.item_count(),
        }
    }
}

/// 一份完整、已校验且可直接求值的语义规则集。
#[derive(Debug)]
pub struct RulesetProgram {
    version: u8,
    rule_count: usize,
    root: RulesetExpr,
}

impl RulesetProgram {
    pub fn new(version: u8, rule_count: usize, root: RulesetExpr) -> Self {
        Self {
            version,
            rule_count,
            root,
        }
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    pub fn item_count(&self) -> usize {
        self.root.item_count()
    }

    pub fn matches(&self, ctx: &RulesetMatchContext<'_>) -> bool {
        self.root.matches(ctx)
    }
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn domain_has_suffix(host: &str, suffix: &str) -> bool {
    // sing-box 以 leading dot 区分两种语义：
    // * example.com  => root + subdomain
    // * .example.com => 仅 subdomain
    if suffix.starts_with('.') {
        return suffix.len() > 1 && host.len() > suffix.len() && host.ends_with(suffix);
    }
    host == suffix
        || (host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

fn destination_ip(ctx: &RulesetMatchContext<'_>) -> Option<IpAddr> {
    ctx.dst_ip.or_else(|| ctx.dst_host.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_source_metadata_does_not_fall_back_to_destination() {
        let expression = RulesetExpr::Predicate(RulesetPredicate::SrcIpCidr(vec![
            "10.0.0.0/8".parse().unwrap(),
        ]));
        let ctx = RulesetMatchContext {
            dst_ip: Some("10.1.2.3".parse().unwrap()),
            ..Default::default()
        };
        assert!(!expression.matches(&ctx));
    }
}
