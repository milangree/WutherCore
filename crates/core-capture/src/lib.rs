//! core-capture —— 透明代理（TUN / TProxy / redirect）平台适配。
//!
//! §8 设计要点：
//! * Linux/Android：tproxy + redirect + native TUN（/dev/net/tun）。
//! * Windows：Wintun + 系统路由表（CreateUnicastIpv4Route）。
//! * macOS：utun + pf 防火墙。
//! * OpenWrt：检查 kmod-nft-tproxy / iptables-mod-tproxy。
//! * Tailscale：默认排除 100.64.0.0/10、fd7a:115c:a1e0::/48 与 tailscale0。
//!
//! 这个模块负责 *接管*（drag traffic into the kernel），抓到的连接交给
//! [`Runtime::dial`]。本实现遵循 §11.7：所有平台具体细节封装在
//! [`Engine`] trait 后面，跨平台代码用 [`CaptureSupervisor`] 协调。

#![forbid(unsafe_code)]

pub mod android_caps;
pub mod doctor;
pub mod engine;
pub mod fakeip_dns;
pub mod nat;
pub mod platform;
pub mod route_table;
pub mod supervisor;
pub mod tun;

pub use android_caps::{AndroidCapability, AndroidTier};

pub use doctor::{diagnose, DoctorReport};
pub use engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};
pub use nat::NatTable;
pub use route_table::{ManagedRoute, RouteTable};
pub use supervisor::CaptureSupervisor;
pub use tun::{TunConfig, TunDevice};
