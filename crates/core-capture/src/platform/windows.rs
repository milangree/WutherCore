//! Windows 后端：Wintun + 系统路由表。
//!
//! M4 完整化：
//! * 通过 [`windows_tun_io::open`] 探测 Wintun.dll；
//!   - 存在则返回占位设备并发出 warning；完整 ABI 接入留 M4-Phase2；
//!   - 不存在则仅做 netsh 配置（IP/MTU 设置），不跑 packet loop。
//! * `route ADD 0.0.0.0 MASK 0.0.0.0 ... IF <idx>` 写默认路由。
//! * `netsh interface ip set dns 127.0.0.1` 切系统 DNS（仅 hijack_dns 时；
//!   stop 时还原 DHCP）。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};
use crate::packet::{parse_tun_frame, L4};
use crate::platform::windows_tun_io;
use crate::route_table::{ManagedRoute, RouteTable};
use crate::tun_io::TunIo;

pub fn list_interfaces() -> Vec<String> {
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
        EngineKind::Tproxy | EngineKind::Redirect => Err(CaptureError::Unsupported(
            "Windows 不支持 tproxy/redirect".into(),
        )),
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct WindowsTun {
    plan: CapturePlan,
    state: Mutex<TunState>,
    routes: Arc<RouteTable>,
}

#[derive(Default)]
struct TunState {
    started: bool,
    device: Option<Arc<dyn TunIo>>,
    loop_handle: Option<JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
    /// 启动 hijack_dns 时记录的"原始系统 DNS"接口列表，stop 时还原。
    saved_dns: Vec<(String, Vec<String>)>,
}

impl WindowsTun {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(TunState::default()),
            routes: RouteTable::new(),
        }
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
    let mask: u32 = if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
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
    fn tun_io(&self) -> Option<Arc<dyn crate::tun_io::TunIo>> {
        let g = self.state.try_lock().ok()?;
        g.device.clone()
    }
    async fn start(
        self: Arc<Self>,
        events: mpsc::Sender<CaptureEvent>,
        _runtime: Arc<core_runtime::Runtime>,
    ) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if g.started {
            return Ok(());
        }
        // **关键**：在 TUN 创建之前先探物理默认网卡 ifindex —— 一旦 TUN 起来，
        // 系统默认路由会切到 TUN（metric 最低），再探就拿到 TUN 自己 → 出站 socket
        // 反而绑回 TUN 形成死循环。
        //
        // 探到的 ifindex 写到 core-outbound 全局态，TCP/UDP 出站 socket 通过
        // `bind_outbound_socket` 走 IP_UNICAST_IF / IPV6_UNICAST_IF 强绑物理接口，
        // 内核选路时跳过 TUN，让代理出站包真正走物理网卡。
        let (v4_idx, v6_idx) = probe_default_interface_indices();
        if v4_idx.is_some() || v6_idx.is_some() {
            core_outbound::set_outbound_interface_index(v4_idx, v6_idx);
            info!(
                target: "capture::windows",
                v4 = ?v4_idx,
                v6 = ?v6_idx,
                "physical outbound interface index probed for IP_UNICAST_IF bind"
            );
        } else {
            warn!(
                target: "capture::windows",
                "default interface ifindex probe returned nothing — outbound dials may loop through TUN"
            );
        }
        Self::configure(&self.plan)?;
        // hijack_dns：保存当前所有接口的 DNS，统一切到 127.0.0.1（fake-dns 监听）。
        if self.plan.hijack_dns {
            g.saved_dns = snapshot_system_dns();
            apply_dns_to_all_interfaces("127.0.0.1");
            info!(target: "capture::windows", count = g.saved_dns.len(), "DNS hijacked → 127.0.0.1");
        }
        // 默认路由（非 v6）
        if let Ok(default4) = "0.0.0.0/0".parse() {
            let _ = self.routes.add(ManagedRoute {
                dest: default4,
                gateway: None,
                interface: self.plan.interface_name.clone(),
                metric: 0,
                table: None,
            });
        }
        // Wintun 的事件级 packet_loop 只发现流，不能转发 payload。
        // virtual_nic 始终由 CaptureSupervisor 的 TunDispatcher 独占读写。
        let dispatcher_owns_tun = true;
        match crate::platform::tunrs_io::open(&self.plan)
            .map(|d| d as std::sync::Arc<dyn crate::tun_io::TunIo>)
        {
            Ok(device) => {
                let (stop_tx, stop_rx) = oneshot::channel();
                if !dispatcher_owns_tun {
                    let dev_for_loop = device.clone();
                    let mtu = self.plan.mtu as usize;
                    let handle = tokio::spawn(async move {
                        packet_loop(dev_for_loop, mtu, events, stop_rx).await;
                    });
                    g.loop_handle = Some(handle);
                } else {
                    let _ = stop_rx;
                    let _ = events;
                }
                g.device = Some(device);
                g.stop_tx = Some(stop_tx);
            }
            Err(e) => {
                warn!(
                    target: "capture::windows",
                    error = %e,
                    "Wintun 不可用 —— packet loop 未启动；仅 netsh 配置生效"
                );
            }
        }
        g.started = true;
        info!(
            target: "capture",
            iface = %self.plan.interface_name,
            "windows tun started"
        );
        Ok(())
    }
    async fn stop(self: Arc<Self>) -> Result<(), CaptureError> {
        let mut g = self.state.lock().await;
        if let Some(tx) = g.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = g.loop_handle.take() {
            h.abort();
        }
        if let Some(d) = g.device.take() {
            let _ = d.close().await;
        }
        self.routes.revert_all();
        // 还原系统 DNS
        if !g.saved_dns.is_empty() {
            for (iface, servers) in g.saved_dns.drain(..) {
                restore_dns_for_interface(&iface, &servers);
            }
            info!(target: "capture::windows", "DNS restored");
        }
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
        g.started = false;
        info!(target: "capture", iface = %self.plan.interface_name, "windows tun stopped");
        Ok(())
    }
}

/* ---------------- 默认物理接口 ifindex 探测 ---------------- */

/// 通过 `Get-NetRoute` 找出 metric 最低的 0.0.0.0/0 / ::/0 路由，再用
/// `Get-NetIPInterface` 把 InterfaceAlias 转成 InterfaceIndex。
///
/// PowerShell 解析比 `route print` 解析稳健（后者有本地化、列宽可变等问题），
/// 同时沿用 Windows 已经为我们做好的"按 metric 排序"逻辑。
fn probe_default_interface_indices() -> (Option<u32>, Option<u32>) {
    let v4 = probe_default_interface_index_for("IPv4");
    let v6 = probe_default_interface_index_for("IPv6");
    (v4, v6)
}

fn probe_default_interface_index_for(family: &str) -> Option<u32> {
    let prefix = if family == "IPv6" { "::/0" } else { "0.0.0.0/0" };
    // 单行脚本 —— 拿 metric 最低的默认路由的 InterfaceIndex；缺省时输出空。
    let script = format!(
        "$r = Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue \
         | Where-Object {{ $_.NextHop -ne '::' -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch '^(WutherCore|Meta|tun|wintun)' }} \
         | Sort-Object -Property RouteMetric \
         | Select-Object -First 1; \
         if ($r) {{ $r.InterfaceIndex }}"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u32>().ok().filter(|&v| v != 0)
}

/* ---------------- DNS hijack helpers ---------------- */

/// 用 PowerShell `Get-DnsClientServerAddress` 拿当前每个接口的 DNS。
fn snapshot_system_dns() -> Vec<(String, Vec<String>)> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | \
             Where-Object { $_.ServerAddresses } | \
             ForEach-Object { \"$($_.InterfaceAlias)|$($_.ServerAddresses -join ',')\" }",
        ])
        .output();
    let mut result = Vec::new();
    if let Ok(o) = out {
        let txt = String::from_utf8_lossy(&o.stdout);
        for line in txt.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((iface, list)) = line.split_once('|') {
                let servers: Vec<String> = list
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if !servers.is_empty() {
                    result.push((iface.to_string(), servers));
                }
            }
        }
    }
    result
}

fn apply_dns_to_all_interfaces(server: &str) {
    let snap = snapshot_system_dns();
    for (iface, _) in snap {
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "dnsservers",
                &iface,
                "static",
                server,
                "primary",
            ])
            .status();
    }
}

fn restore_dns_for_interface(iface: &str, servers: &[String]) {
    // 先重置成 dhcp，再依次添加（保留原优先级）。
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ip", "set", "dnsservers", iface, "dhcp"])
        .status();
    for (i, s) in servers.iter().enumerate() {
        let idx = (i + 1).to_string();
        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "add",
                "dnsservers",
                iface,
                s,
                &format!("index={idx}"),
            ])
            .status();
    }
}

async fn packet_loop(
    device: Arc<dyn TunIo>,
    mtu: usize,
    events: mpsc::Sender<CaptureEvent>,
    mut stop_rx: oneshot::Receiver<()>,
) {
    let mut buf = vec![0u8; mtu + 64];
    use std::collections::HashSet;
    let mut seen: HashSet<(std::net::SocketAddr, std::net::SocketAddr, &'static str)> =
        HashSet::new();
    loop {
        tokio::select! {
            _ = &mut stop_rx => break,
            r = device.read_packet(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(target: "capture::windows::tun", error = %e, "read failed; loop exit");
                        break;
                    }
                };
                let parsed = match parse_tun_frame(&buf[..n]) {
                    Ok(p) => p.packet,
                    Err(_) => continue,
                };
                let net = match parsed.l4 {
                    L4::Tcp(_) => "tcp",
                    L4::Udp(_) => "udp",
                    L4::Other(_) => continue,
                };
                let src = match parsed.src_socket() { Some(s) => s, None => continue };
                let dst = match parsed.dst_socket() { Some(s) => s, None => continue };
                if !seen.insert((src, dst, net)) {
                    continue;
                }
                let evt = CaptureEvent {
                    original_dst: dst,
                    source: src,
                    network: net,
                    fake_host: None,
                };
                if events.send(evt).await.is_err() {
                    debug!(target: "capture::windows::tun", "events channel closed");
                    break;
                }
            }
        }
    }
}
