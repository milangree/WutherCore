//! 出站协议适配器集合。
//!
//! **真实现**（与 mihomo 互通的常用协议）：
//! * [`shadowsocks`] —— SS AEAD（aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305），
//!   含目标地址 SOCKS5 编码、salt + HKDF-SHA1 子密钥、payload 分块封装。
//! * [`trojan`] —— TLS + 56 字节 SHA-224(password) hex + CRLF + SOCKS5 cmd。
//! * [`vless`] —— VLESS（无加密）over TLS/TCP/WS：版本 + UUID + addons + cmd + 端口 + 目标。
//!
//! **占位**（dial 返回明确的"协议尚未实现"）：
//! * vmess（AEAD 头部链路较复杂，独立 PR 实现）
//! * shadowsocksr / snell / anytls / mieru / sudoku / trusttunnel
//! * hysteria / hysteria2 / tuic（基于 QUIC，需 quinn 依赖）
//! * wireguard / ssh（独立栈，单独实现）
//!
//! 上述占位由 [`crate::stub::StubOutbound`] 提供，dial 时给出
//! `ErrorKind::Unsupported` 与协议名，避免静默失败。

pub mod addr;
pub mod shadowsocks;
pub mod trojan;
pub mod vless;
