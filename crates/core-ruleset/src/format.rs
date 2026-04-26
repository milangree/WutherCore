//! 规则集格式枚举 + 自动嗅探。

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesetFormat {
    /// mihomo / Clash payload yaml
    Yaml,
    /// 每行一条规则的 txt / list
    Text,
    /// sing-box ruleset JSON `{"version":N,"rules":[...]}`
    SingboxJson,
    /// mihomo binary（MRS）—— 嗅探后回退错误
    Mrs,
    /// sing-box binary（SRS）—— 嗅探后回退错误
    Srs,
    /// **RPKernel 自研二进制**：magic "RRS\0" + CRC32
    Rrs,
    Unknown,
}

/// 综合：1) 用户显式指定 → 2) 文件扩展名 → 3) 内容魔数。
pub fn detect_format(hint: Option<&str>, path: Option<&str>, body: &[u8]) -> RulesetFormat {
    if let Some(h) = hint {
        if let Some(f) = parse_hint(h) {
            return f;
        }
    }
    if let Some(p) = path {
        if let Some(f) = from_extension(p) {
            return f;
        }
    }
    sniff(body)
}

fn parse_hint(s: &str) -> Option<RulesetFormat> {
    Some(match s.to_ascii_lowercase().as_str() {
        "yaml" | "yml" => RulesetFormat::Yaml,
        "txt" | "list" | "text" => RulesetFormat::Text,
        "json" | "singbox" | "sing-box" => RulesetFormat::SingboxJson,
        "mrs" | "mihomo-binary" => RulesetFormat::Mrs,
        "srs" | "singbox-binary" => RulesetFormat::Srs,
        "rrs" | "rpkernel" | "rpkernel-binary" => RulesetFormat::Rrs,
        _ => return None,
    })
}

fn from_extension(path: &str) -> Option<RulesetFormat> {
    let ext = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "yaml" | "yml" => RulesetFormat::Yaml,
        "txt" | "list" => RulesetFormat::Text,
        "json" => RulesetFormat::SingboxJson,
        "mrs" => RulesetFormat::Mrs,
        "srs" => RulesetFormat::Srs,
        "rrs" => RulesetFormat::Rrs,
        _ => return None,
    })
}

fn sniff(body: &[u8]) -> RulesetFormat {
    if body.is_empty() {
        return RulesetFormat::Unknown;
    }
    // RPKernel RRS：magic = "RRS\0"
    if body.starts_with(&crate::rrs::MAGIC) {
        return RulesetFormat::Rrs;
    }
    // mihomo MRS：magic = "MRS\0" 之类（无公开规范，按截至 2026 mihomo 主分支约定）
    if body.starts_with(b"MRS") || body.starts_with(b"\x4D\x52\x53") {
        return RulesetFormat::Mrs;
    }
    // sing-box SRS：magic = "SRS\0" 0x53 0x52 0x53
    if body.starts_with(b"SRS") || body.starts_with(b"\x53\x52\x53") {
        return RulesetFormat::Srs;
    }
    // 文本：从前 256 字节判断
    let head = &body[..body.len().min(2048)];
    let text = String::from_utf8_lossy(head);
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') {
        if trimmed.contains("\"rules\"") {
            return RulesetFormat::SingboxJson;
        }
    }
    if trimmed.starts_with("payload:") || trimmed.contains("\npayload:") {
        return RulesetFormat::Yaml;
    }
    // 含 "DOMAIN," 或 "IP-CIDR," 关键字 → 文本
    if trimmed.contains("DOMAIN") || trimmed.contains("IP-CIDR") || trimmed.contains("PROCESS-NAME") {
        return RulesetFormat::Text;
    }
    // 默认按 text 试一次
    RulesetFormat::Text
}
