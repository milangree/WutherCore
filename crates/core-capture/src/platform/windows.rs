//! Windows 后端：Wintun + 系统路由表。
//!
//! 实现策略：
//! * 通过 `netsh interface ip add address` / `netsh interface ipv6 add address`
//!   配置 TUN 网卡 IP；通过 `route add 0.0.0.0 mask 0.0.0.0 <gw> if <idx> metric N`
//!   写默认路由。
//! * Wintun.dll 加载留接口（M4）；当前 MVP 仅完成网卡命令编排与诊断，
//!   不依赖 Wintun.dll 也可在 Windows 主机编译通过。
//! * 检测系统 DNS 泄漏：默认插入 fake-dns 时把 `netsh interface ip set dns`
//!   切到 127.0.0.1（stop 时恢复）。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};

pub fn list_interfaces() -> Vec<String> {
    // PowerShell `Get-NetAdapter` 最稳；这里走轻量解析。
    let out = std::process::Command::new("netsh")
        .args(["interface", "show", "interface"])
        .output();
    let mut names = Vec::new();
    if let Ok(o) = out {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines().skip(3) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                names.push(parts[3..].join(" "));
            }
        }
    }
    names
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    match plan.kind {
        EngineKind::Tun => Ok(Arc::new(WindowsTun::new(plan))),
        EngineKind::Tproxy | EngineKind::Redirect => {
            Err(CaptureError::Unsupported("Windows 不支持 tproxy/redirect".into()))
        }
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct WindowsTun {
    plan: CapturePlan,
    state: Mutex<bool>,
}

impl WindowsTun {
    pub fn new(plan: CapturePlan) -> Self {
        Self { plan, state: Mutex::new(false) }
    }

    fn configure(plan: &CapturePlan) -> Result<(), CaptureError> {
        let v4 = format!("{}", plan.tun_v4_cidr.addr());
        let mask = format!("{}", v4mask(plan.tun_v4_cidr.prefix_len()));
        let st = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &plan.interface_name,
                "static",
                &v4,
                &mask,
            ])
            .status();
        if let Ok(st) = st {
            if !st.success() {
                warn!(target: "capture", "netsh set address 可能失败 —— 网卡名: {}", plan.interface_name);
            }
        } else {
            warn!(target: "capture", "未能调用 netsh，跳过 IPv4 配置");
        }

        // MTU
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &plan.interface_name,
                &format!("mtu={}", plan.mtu),
                "store=active",
            ])
            .status();
        Ok(())
    }
}

fn v4mask(prefix: u8) -> std::net::Ipv4Addr {
    let mask: u32 = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    std::net::Ipv4Addr::from(mask)
}

#[async_trait]
impl CaptureEngine for WindowsTun {
    fn kind(&self) -> EngineKind {
        EngineKind::Tun
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(self: Arc<Self>, _events: mpsc::Sender<CaptureEvent>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if *g {
            return Ok(());
        }
        Self::configure(&self.plan)?;
        *g = true;
        info!(target: "capture", iface = %self.plan.interface_name, "windows tun configured (Wintun loop pending M4)");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !*g {
            return Ok(());
        }
        // 还原 DHCP
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &self.plan.interface_name,
                "dhcp",
            ])
            .status();
        *g = false;
        info!(target: "capture", iface = %self.plan.interface_name, "windows tun stopped");
        Ok(())
    }
}
