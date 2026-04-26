//! 二进制规则集 —— mihomo MRS / sing-box SRS。
//!
//! **现状**：
//! * mihomo MRS 由 mihomo 仓库内私有 `binary.go` 编码（zstd 压缩域名 trie），
//!   无对外公开规范；版本号经常变。
//! * sing-box SRS 由 `sing-box rule-set compile` 生成，使用 `gob`-like 二进制；
//!   依赖 sing-box 自身代码。
//!
//! 我们 **明确不假装支持**：检测到 magic 时给出三段式错误，引导用户改用
//! 文本规则集（mihomo `mihomo convert-ruleset` / sing-box `sing-box rule-set decompile`）。
//! 等到上游 spec 稳定再补完整解码。

use crate::matcher::ClassicalEntry;
use crate::parser::ParseError;

pub fn parse_mrs(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let _ = body;
    Err(ParseError::UnsupportedBinary(
        "mihomo MRS 二进制规则集尚未完整解码。请用 \
         `mihomo convert-ruleset --in xxx.mrs --out xxx.yaml` 转换为 yaml/txt。",
    ))
}

pub fn parse_srs(body: &[u8]) -> Result<Vec<ClassicalEntry>, ParseError> {
    let _ = body;
    Err(ParseError::UnsupportedBinary(
        "sing-box SRS 二进制规则集尚未完整解码。请用 \
         `sing-box rule-set decompile xxx.srs` 转换为 json，或在配置中改 format: json 指向源 JSON。",
    ))
}
