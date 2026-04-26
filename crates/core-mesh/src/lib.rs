//! core-mesh —— Tailscale / WireGuard / 局域网协同。
//!
//! §9：默认排除 100.64.0.0/10、fd7a:115c:a1e0::/48；
//! Tailnet 目标默认 direct，不进入 Smart。
//! MVP：检测本机是否存在 tailscaled / userspace proxy，并产出诊断。

#![forbid(unsafe_code)]

use core_config::model::{Mesh, TailscaleMode};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use tracing::info;

pub static TAILNET_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    ["100.64.0.0/10", "fd7a:115c:a1e0::/48"]
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
});

/// 启动时诊断 Tailscale 集成。
pub fn diagnose(mesh: &Mesh) -> String {
    let Some(ts) = mesh.tailscale.as_ref() else {
        return "tailscale: 未配置".into();
    };
    if !ts.on {
        return "tailscale: 关闭".into();
    }
    let mode = match ts.mode {
        TailscaleMode::Auto => "auto",
        TailscaleMode::Localapi => "localapi",
        TailscaleMode::Userspace => "userspace",
        TailscaleMode::Tsnet => "tsnet",
        TailscaleMode::Off => "off",
    };
    let report = format!(
        "tailscale: on (mode={mode}, keep_tailnet_direct={}, expose_as_node={})",
        ts.keep_tailnet_direct, ts.expose_as_node
    );
    info!(target: "mesh", report = %report, "tailscale diagnose");
    report
}

pub mod tailscale {
    pub use super::TAILNET_CIDRS;
}

mod once_cell_uses {
    #[allow(dead_code)]
    fn _ensure_use() {
        let _ = &*super::TAILNET_CIDRS;
    }
}
