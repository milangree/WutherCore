//! core-outbound —— 出站协议适配器。
//!
//! §11.2 关键 trait [`OutboundAdapter`]：所有出站使用统一接口。
//! MVP 阶段实现 direct / block / http / socks5 / shadowsocks（基础 AEAD）。
//! 其它协议（vmess / vless / trojan / hysteria2 / tuic / wireguard / ssh）
//! 提供 stub 适配器，并在 dial 时返回"协议尚未实现"。

#![forbid(unsafe_code)]

pub mod adapter;
pub mod registry;

pub mod direct;
pub mod block;
pub mod http;
pub mod socks5;
pub mod stub;

pub mod transport;
pub mod proto;

pub use adapter::{Capabilities, DialContext, OutboundAdapter, ProxyStream};
pub use registry::{OutboundRegistry, ResolveFn};
