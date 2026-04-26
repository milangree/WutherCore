//! 多格式 → 统一 [`ClassicalEntry`] 列表。

use thiserror::Error;

use crate::format::RulesetFormat;
use crate::matcher::ClassicalEntry;

pub mod yaml;
pub mod txt;
pub mod sb_json;
pub mod binary;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("YAML 解析失败: {0}")]
    Yaml(String),
    #[error("JSON 解析失败: {0}")]
    Json(String),
    #[error("非法行 \"{0}\"")]
    BadLine(String),
    #[error("尚未实现该二进制格式: {0}")]
    UnsupportedBinary(&'static str),
    #[error("未知格式")]
    Unknown,
}

pub fn parse_ruleset(format: RulesetFormat, body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    match format {
        RulesetFormat::Yaml => yaml::parse(body),
        RulesetFormat::Text => txt::parse(body),
        RulesetFormat::SingboxJson => sb_json::parse(body),
        RulesetFormat::Mrs => binary::parse_mrs(body),
        RulesetFormat::Srs => binary::parse_srs(body),
        RulesetFormat::Rrs => crate::rrs::decode(body),
        RulesetFormat::Unknown => Err(ParseError::Unknown),
    }
}
