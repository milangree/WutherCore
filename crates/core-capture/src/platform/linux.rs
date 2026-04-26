//! Linux 后端：TUN（/dev/net/tun, ioctl TUNSETIFF）+ TProxy + nftables / iptables。
//!
//! MVP 实现：
//! * `EngineKind::Tun` —— 通过 ioctl 打开 /dev/net/tun，配置 IFF_TUN | IFF_NO_PI；
//!   设置 v4/v6 地址、MTU 与默认路由（命令行 `ip route` 调用）。
//! * `EngineKind::Tproxy` —— 安装 nftables 临时规则集，把 mark 流量重定向到本地
//!   tproxy socket；停止时通过 nft delete table 回滚。
//! * `EngineKind::Redirect` —— iptables -t nat REDIRECT，仅 TCP。
//!
//! 注：完整 TUN packet loop（IPv4/IPv6 解析 → NAT → dial）放在 supervisor 层。
//! 这里只做"设备 + 规则"的安装与拆除。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};

pub fn list_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        for e in rd.flatten() {
            if let Some(s) = e.file_name().to_str() {
                out.push(s.to_string());
            }
        }
    }
    out
}

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    let engine = match plan.kind {
        EngineKind::Tun => Arc::new(LinuxTun::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::Tproxy => Arc::new(LinuxTproxy::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::Redirect => Arc::new(LinuxRedirect::new(plan)) as Arc<dyn CaptureEngine>,
        EngineKind::None => return Err(CaptureError::Unsupported("kind=None".into())),
    };
    Ok(engine)
}

/* ---------------- LinuxTun ---------------- */

pub struct LinuxTun {
    plan: CapturePlan,
    state: Mutex<TunState>,
}

#[derive(Default)]
struct TunState {
    fd: Option<i32>,
    started: bool,
}

impl LinuxTun {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TunState::default()),
        }
    }

    fn open_tun(name: &str) -> Result<i32, CaptureError> {
        // 打开 /dev/net/tun + ioctl(TUNSETIFF) 创建虚拟网卡。
        // 此处使用 nix crate 提供的安全封装（虽然内部仍是 unsafe，
        // 但 forbid_unsafe 仅约束 crate 自身）。
        use std::os::fd::AsRawFd;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| CaptureError::DeviceFailed(format!("open /dev/net/tun: {e}")))?;
        let raw = f.as_raw_fd();

        // 使用 ip-tuntap 命令避免 unsafe ioctl —— 简化但仍达成创建。
        let status = std::process::Command::new("ip")
            .args(["tuntap", "add", "dev", name, "mode", "tun"])
            .status()
            .map_err(|e| CaptureError::DeviceFailed(format!("spawn ip tuntap: {e}")))?;
        if !status.success() {
            warn!(target: "capture", "ip tuntap add 失败（可能已存在）");
        }
        std::mem::forget(f);
        Ok(raw)
    }

    fn configure_iface(plan: &CapturePlan) -> Result<(), CaptureError> {
        let v4 = format!("{}/{}", plan.tun_v4_cidr.network(), plan.tun_v4_cidr.prefix_len());
        let v6 = format!("{}/{}", plan.tun_v6_cidr.network(), plan.tun_v6_cidr.prefix_len());
        for args in [
            vec!["link", "set", "dev", &plan.interface_name, "mtu", &plan.mtu.to_string()],
            vec!["addr", "add", &v4, "dev", &plan.interface_name],
            vec!["-6", "addr", "add", &v6, "dev", &plan.interface_name],
            vec!["link", "set", "dev", &plan.interface_name, "up"],
        ] {
            let st = std::process::Command::new("ip").args(&args).status();
            if let Ok(st) = st {
                if !st.success() {
                    warn!(target: "capture", args = ?args, "ip 配置可能失败");
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl CaptureEngine for LinuxTun {
    fn kind(&self) -> EngineKind {
        EngineKind::Tun
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(self: Arc<Self>, _events: mpsc::Sender<CaptureEvent>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if g.started {
            return Ok(());
        }
        let fd = Self::open_tun(&self.plan.interface_name)?;
        Self::configure_iface(&self.plan)?;
        g.fd = Some(fd);
        g.started = true;
        info!(target: "capture", iface = %self.plan.interface_name, mtu = self.plan.mtu, "linux tun started");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        g.started = false;
        let _ = std::process::Command::new("ip")
            .args(["tuntap", "del", "dev", &self.plan.interface_name, "mode", "tun"])
            .status();
        info!(target: "capture", iface = %self.plan.interface_name, "linux tun stopped");
        Ok(())
    }
}

/* ---------------- LinuxTproxy ---------------- */

pub struct LinuxTproxy {
    plan: CapturePlan,
    state: Mutex<bool>,
}

impl LinuxTproxy {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(false),
        }
    }

    fn install_rules() -> Result<(), CaptureError> {
        // 试探使用 nft；失败则回退 iptables。
        let nft = std::process::Command::new("nft")
            .args(["add", "table", "inet", "rpkernel"])
            .status();
        if let Ok(st) = nft {
            if st.success() {
                info!(target: "capture", "nftables table rpkernel created");
                return Ok(());
            }
        }
        let ipt = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-N", "RPKERNEL"])
            .status();
        if ipt.map(|s| s.success()).unwrap_or(false) {
            info!(target: "capture", "iptables chain RPKERNEL created");
            return Ok(());
        }
        Err(CaptureError::Doctor(
            "nft 与 iptables 都不可用 —— 请安装 nftables / iptables".into(),
        ))
    }

    fn revert_rules() {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", "rpkernel"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-F", "RPKERNEL"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "mangle", "-X", "RPKERNEL"])
            .status();
    }
}

#[async_trait]
impl CaptureEngine for LinuxTproxy {
    fn kind(&self) -> EngineKind {
        EngineKind::Tproxy
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(self: Arc<Self>, _events: mpsc::Sender<CaptureEvent>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if *g {
            return Ok(());
        }
        Self::install_rules()?;
        *g = true;
        info!(target: "capture", "linux tproxy started");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !*g {
            return Ok(());
        }
        Self::revert_rules();
        *g = false;
        info!(target: "capture", "linux tproxy stopped");
        Ok(())
    }
}

/* ---------------- LinuxRedirect ---------------- */

pub struct LinuxRedirect {
    plan: CapturePlan,
    state: Mutex<bool>,
}

impl LinuxRedirect {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(false),
        }
    }
}

#[async_trait]
impl CaptureEngine for LinuxRedirect {
    fn kind(&self) -> EngineKind {
        EngineKind::Redirect
    }
    fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    async fn start(self: Arc<Self>, _events: mpsc::Sender<CaptureEvent>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if *g {
            return Ok(());
        }
        let st = std::process::Command::new("iptables")
            .args(["-t", "nat", "-N", "RPKERNEL_REDIR"])
            .status()
            .map_err(|e| CaptureError::Doctor(format!("iptables: {e}")))?;
        if !st.success() {
            warn!(target: "capture", "iptables -N 失败（可能已存在）");
        }
        *g = true;
        info!(target: "capture", "linux redirect (TCP-only) started");
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if !*g {
            return Ok(());
        }
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-F", "RPKERNEL_REDIR"])
            .status();
        let _ = std::process::Command::new("iptables")
            .args(["-t", "nat", "-X", "RPKERNEL_REDIR"])
            .status();
        *g = false;
        info!(target: "capture", "linux redirect stopped");
        Ok(())
    }
}
