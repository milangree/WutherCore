//! Capture 引擎抽象 —— 平台无关协议契约。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use core_config::model::{Capture, CaptureMethod, CaptureStack, CaptureTraffic};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("当前平台不支持: {0}")]
    Unsupported(String),
    #[error("doctor 检查失败: {0}")]
    Doctor(String),
    #[error("内核拒绝创建 TUN/TProxy: {0}")]
    DeviceFailed(String),
    #[error("路由表写入失败: {0}")]
    Route(String),
    #[error("NAT 表满 / 失败: {0}")]
    Nat(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("已停止")]
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EngineKind {
    /// virtual_nic —— 创建一张 TUN 网卡，转发其上 IP 包。
    Tun,
    /// Linux 透明代理：TPROXY socket + nftables / iptables。
    Tproxy,
    /// 仅 TCP 重定向（兼容模式，无法处理 UDP）。
    Redirect,
    /// 不接管，仅诊断。
    None,
}

#[derive(Debug, Clone)]
pub struct CapturePlan {
    pub on: bool,
    pub kind: EngineKind,
    pub stack: CaptureStack,
    pub traffic: CaptureTraffic,
    pub mtu: u32,
    pub offload: bool,
    pub hijack_dns: bool,
    pub exclude_cidrs: Vec<ipnet::IpNet>,
    pub exclude_processes: Vec<String>,
    pub interface_name: String,
    pub tun_v4_cidr: ipnet::Ipv4Net,
    pub tun_v6_cidr: ipnet::Ipv6Net,
}

impl CapturePlan {
    /// 由 [`Capture`] 配置 + 平台决议得到的执行计划。
    pub fn from_config(c: &Capture) -> Result<Self, CaptureError> {
        let kind = decide_kind(c)?;
        let mut excludes: Vec<ipnet::IpNet> = c
            .exclude
            .cidr
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        // §9.1：默认排除 Tailnet。
        for s in ["100.64.0.0/10", "fd7a:115c:a1e0::/48"] {
            if let Ok(n) = s.parse() {
                if !excludes.contains(&n) {
                    excludes.push(n);
                }
            }
        }
        Ok(Self {
            on: c.on,
            kind,
            stack: c.stack,
            traffic: c.traffic,
            mtu: c.mtu.unwrap_or(default_mtu(kind)),
            offload: c.offload,
            hijack_dns: matches!(c.resolver, core_config::model::CaptureResolver::Hijack),
            exclude_cidrs: excludes,
            exclude_processes: c.exclude.process.clone(),
            interface_name: default_iface_name(),
            tun_v4_cidr: "198.18.0.0/15".parse().unwrap(),
            tun_v6_cidr: "fc00:1::/64".parse().unwrap(),
        })
    }
}

fn default_mtu(kind: EngineKind) -> u32 {
    match kind {
        EngineKind::Tun => 1500,
        _ => 1500,
    }
}

fn default_iface_name() -> String {
    if cfg!(target_os = "windows") {
        "RPKernelTun".into()
    } else if cfg!(target_os = "macos") {
        "utun7".into()
    } else {
        "rpktun0".into()
    }
}

fn decide_kind(c: &Capture) -> Result<EngineKind, CaptureError> {
    if !c.on {
        return Ok(EngineKind::None);
    }
    let os = std::env::consts::OS;
    let kind = match c.method {
        CaptureMethod::Auto => match os {
            "linux" | "android" => EngineKind::Tproxy,
            "windows" | "macos" | "ios" => EngineKind::Tun,
            other => return Err(CaptureError::Unsupported(other.into())),
        },
        CaptureMethod::VirtualNic => EngineKind::Tun,
        CaptureMethod::Tproxy => {
            if !matches!(os, "linux" | "android") {
                return Err(CaptureError::Unsupported(format!(
                    "tproxy 仅 Linux/Android；当前 {os}"
                )));
            }
            EngineKind::Tproxy
        }
        CaptureMethod::Redirect => {
            if !matches!(os, "linux" | "android") {
                return Err(CaptureError::Unsupported(format!(
                    "redirect 仅 Linux/Android；当前 {os}"
                )));
            }
            EngineKind::Redirect
        }
    };
    Ok(kind)
}

/// 一次"被接管"的连接事件。Engine 通过 mpsc 把它发给 supervisor。
#[derive(Debug, Clone)]
pub struct CaptureEvent {
    pub original_dst: SocketAddr,
    pub source: SocketAddr,
    pub network: &'static str, // "tcp" / "udp"
    pub fake_host: Option<String>,
}

/// 平台 Engine trait —— 由 platform/* 子模块各自实现。
#[async_trait]
pub trait CaptureEngine: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn plan(&self) -> &CapturePlan;
    /// 启动；事件通过 channel 推出。
    async fn start(self: Arc<Self>, events: mpsc::Sender<CaptureEvent>) -> Result<(), CaptureError>;
    /// 优雅停止：撤销路由 / 清除防火墙规则 / 关 TUN。
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError>;
    fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": format!("{:?}", self.kind()).to_lowercase(),
            "stack": format!("{:?}", self.plan().stack).to_lowercase(),
            "traffic": format!("{:?}", self.plan().traffic).to_lowercase(),
            "mtu": self.plan().mtu,
            "interface": self.plan().interface_name,
        })
    }
}

/// 工具：判断目标 IP 是否被 exclude。
pub fn is_excluded(plan: &CapturePlan, ip: IpAddr) -> bool {
    plan.exclude_cidrs.iter().any(|n| n.contains(&ip))
}
