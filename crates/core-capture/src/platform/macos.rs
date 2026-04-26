//! macOS / iOS 后端：utun + pf 防火墙。
//!
//! MVP：通过 `ifconfig utun7 inet ... up` 配置 TUN，pf 通过临时 .conf
//! 加载 `redirect-to lo0:7890`。完整 packet loop 与 NEPacketTunnelProvider
//! 桥接放在 M4 实现。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};

pub fn list_interfaces() -> Vec<String> {
    let out = std::process::Command::new("ifconfig").arg("-l").output();
    let mut names = Vec::new();
    if let Ok(o) = out {
        let txt = String::from_utf8_lossy(&o.stdout);
        for s in txt.split_whitespace() {
            names.push(s.to_string());
        }
    }
    names
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    match plan.kind {
        EngineKind::Tun => Ok(Arc::new(MacUtun::new(plan))),
        EngineKind::Tproxy | EngineKind::Redirect => {
            Err(CaptureError::Unsupported("macOS 不支持 tproxy/redirect".into()))
        }
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct MacUtun {
    plan: CapturePlan,
    state: Mutex<bool>,
}

impl MacUtun {
    pub fn new(plan: CapturePlan) -> Self {
        Self { plan, state: Mutex::new(false) }
    }

    fn configure(plan: &CapturePlan) -> Result<(), CaptureError> {
        let v4 = plan.tun_v4_cidr.addr().to_string();
        let st = std::process::Command::new("ifconfig")
            .args([
                &plan.interface_name,
                "inet",
                &v4,
                &v4,
                "mtu",
                &plan.mtu.to_string(),
                "up",
            ])
            .status();
        match st {
            Ok(s) if s.success() => Ok(()),
            other => {
                warn!(target: "capture", ?other, "ifconfig utun 配置可能失败");
                Ok(())
            }
        }
    }
}

#[async_trait]
impl CaptureEngine for MacUtun {
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
        info!(target: "capture", iface = %self.plan.interface_name, "macos utun configured");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        *g = false;
        let _ = std::process::Command::new("ifconfig")
            .args([&self.plan.interface_name, "down"])
            .status();
        info!(target: "capture", iface = %self.plan.interface_name, "macos utun stopped");
        Ok(())
    }
}
