//! core-api —— /v1 原生 API + Clash 兼容轻量层。
//!
//! §10：原生 API 字段与 Friendly YAML 一致；Clash/Mihomo 兼容层做字段转换。

#![forbid(unsafe_code)]

pub mod native;
pub mod compat;
pub mod server;

pub use server::ApiServer;
