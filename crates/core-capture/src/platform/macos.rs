//! macOS / iOS 后端：utun + pf 防火墙。
//!
//! M4 完整化：
//! * 通过 [`macos_tun_io::open`] 打开 utun 控制 socket（PF_SYSTEM）；
//! * spawn packet read loop 解析 IP 包并 emit [`CaptureEvent`]；
//! * 写默认路由：`route -n add -net 0.0.0.0/0 -interface utunN`；
//! * 完整 NEPacketTunnelProvider 桥接（iOS 应用商店打包）放在 M4-Phase2。

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};
use crate::packet::{parse_tun_frame, L4};
use crate::platform::macos_tun_io;
use crate::route_table::{ManagedRoute, RouteTable};
use crate::tun_io::TunIo;

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
        EngineKind::Tproxy | EngineKind::Redirect => Err(CaptureError::Unsupported(
            "macOS 不支持 tproxy/redirect".into(),
        )),
        EngineKind::None => Err(CaptureError::Unsupported("kind=None".into())),
    }
}

pub struct MacUtun {
    plan: CapturePlan,
    state: Mutex<UtunState>,
    routes: Arc<RouteTable>,
}

#[derive(Default)]
struct UtunState {
    started: bool,
    device: Option<Arc<dyn TunIo>>,
    loop_handle: Option<JoinHandle<()>>,
    stop_tx: Option<oneshot::Sender<()>>,
}

impl MacUtun {
    pub fn new(plan: CapturePlan) -> Self {
        Self {
            plan,
            state: Mutex::new(UtunState::default()),
            routes: RouteTable::new(),
        }
    }

    fn configure(plan: &CapturePlan, real_name: &str) -> Result<(), CaptureError> {
        let v4 = plan.tun_v4_cidr.addr().to_string();
        let st = std::process::Command::new("ifconfig")
            .args([
                real_name,
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
        // 探物理默认网卡 ifindex —— 必须在 utun 创建之前。一旦 utun 起来并接管
        // 默认路由，再探就拿到 utun 自己 → 出站 socket 反而绑回 TUN，形成死循环。
        // 探到的 ifindex 写到 core-outbound 全局态，TCP/UDP 出站 socket 通过
        // `bind_outbound_socket` 走 IP_BOUND_IF / IPV6_BOUND_IF 绑定到物理接口，
        // darwin 内核选路时跳过 utun，让代理出站包真正走以太网/Wi-Fi。
        let (v4_idx, v6_idx) = probe_default_interface_indices(&self.plan);
        if v4_idx.is_some() || v6_idx.is_some() {
            core_outbound::set_outbound_interface_index(v4_idx, v6_idx);
            info!(
                target: "capture::macos",
                v4 = ?v4_idx,
                v6 = ?v6_idx,
                "physical outbound interface index probed for IP_BOUND_IF bind"
            );
        } else {
            warn!(
                target: "capture::macos",
                "default interface ifindex probe returned nothing — outbound dials may loop through utun"
            );
        }
        let device: std::sync::Arc<dyn crate::tun_io::TunIo> = {
            #[cfg(target_os = "ios")]
            if let Some(fd) = crate::platform::ios_bridge::take_injected_fd() {
                crate::platform::tunrs_io::from_fd(
                    fd,
                    self.plan.interface_name.clone(),
                    self.plan.mtu,
                )
                .map(|d| d as std::sync::Arc<dyn crate::tun_io::TunIo>)
                .map_err(|e| CaptureError::DeviceFailed(format!("tun-rs from fd: {e}")))?
            } else {
                crate::platform::tunrs_io::open(&self.plan)
                    .map(|d| d as std::sync::Arc<dyn crate::tun_io::TunIo>)
                    .map_err(|e| CaptureError::DeviceFailed(format!("tun-rs open: {e}")))?
            }
            #[cfg(not(target_os = "ios"))]
            crate::platform::tunrs_io::open(&self.plan)
                .map(|d| d as std::sync::Arc<dyn crate::tun_io::TunIo>)
                .map_err(|e| CaptureError::DeviceFailed(format!("tun-rs open: {e}")))?
        };
        let real_name = device.name().to_string();
        Self::configure(&self.plan, &real_name)?;

        // 默认路由 → utunN
        if let Ok(default4) = "0.0.0.0/0".parse() {
            let _ = self.routes.add(ManagedRoute {
                dest: default4,
                gateway: None,
                interface: real_name.clone(),
                metric: 0,
                table: None,
            });
        }

        // utun 的事件级 packet_loop 只发现流，不能转发 payload。
        // virtual_nic 始终由 CaptureSupervisor 的 TunDispatcher 独占读写。
        let dispatcher_owns_tun = true;
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
        g.started = true;
        info!(
            target: "capture",
            iface = %real_name,
            mtu = self.plan.mtu,
            dispatcher_owns_tun,
            "macos utun started"
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
        let real_name = g
            .device
            .as_ref()
            .map(|d| d.name().to_string())
            .unwrap_or_else(|| self.plan.interface_name.clone());
        if let Some(d) = g.device.take() {
            let _ = d.close().await;
        }
        self.routes.revert_all();
        let _ = std::process::Command::new("ifconfig")
            .args([&real_name, "down"])
            .status();
        g.started = false;
        info!(target: "capture", iface = %real_name, "macos utun stopped");
        Ok(())
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
                        warn!(target: "capture::macos::utun", error = %e, "read failed; loop exit");
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
                    debug!(target: "capture::macos::utun", "events channel closed");
                    break;
                }
            }
        }
    }
}

/* ---------------- 默认物理接口 ifindex 探测 ---------------- */

/// `route -n get [-inet6] default` 解析 + `if_nametoindex` —— BSD route 工具是
/// macOS / iOS 上唯一稳健的查询入口（getifaddrs 没有"默认路由"概念）。
///
/// 必须在 utun 创建前调用，否则系统默认路由会切到 utun，结果就拿到自己。
fn probe_default_interface_indices(plan: &CapturePlan) -> (Option<u32>, Option<u32>) {
    let v4 = probe_default_interface_index_for("inet", &plan.interface_name);
    let v6 = probe_default_interface_index_for("inet6", &plan.interface_name);
    (v4, v6)
}

fn probe_default_interface_index_for(family: &str, our_iface: &str) -> Option<u32> {
    let args: &[&str] = match family {
        "inet6" => &["-n", "get", "-inet6", "default"],
        _ => &["-n", "get", "default"],
    };
    let out = std::process::Command::new("route").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let iface = parse_route_default_interface(&stdout)?;
    // 已经创建过的旧 utun / lo0 不算物理出口，跳过。
    if iface.is_empty()
        || iface == our_iface
        || iface == "lo0"
        || iface.starts_with("utun")
    {
        return None;
    }
    nametoindex(iface)
}

/// 从 `route -n get default` 的输出里抓 `interface: <name>` 行的值。
/// 抽出来便于在非 macOS 主机做单元测试。
fn parse_route_default_interface(stdout: &str) -> Option<&str> {
    stdout.lines().find_map(|line| {
        let trimmed = line.trim_start();
        trimmed
            .strip_prefix("interface:")
            .map(|rest| rest.trim())
            .filter(|s| !s.is_empty())
    })
}

fn nametoindex(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name)
        .ok()
        .filter(|&v| v != 0)
        .map(|v| v as u32)
}

#[cfg(test)]
mod ifindex_probe_tests {
    use super::parse_route_default_interface;

    #[test]
    fn parses_typical_macos_route_output() {
        let stdout = "   route to: default\n\
                      destination: default\n\
                             mask: default\n\
                          gateway: 192.168.1.1\n\
                        interface: en0\n\
                            flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_route_default_interface(stdout), Some("en0"));
    }

    #[test]
    fn parses_with_extra_whitespace_and_tabs() {
        let stdout = "interface:\t  en7  \n";
        assert_eq!(parse_route_default_interface(stdout), Some("en7"));
    }

    #[test]
    fn returns_none_when_interface_line_missing() {
        let stdout = "route to: default\nstatus: error\n";
        assert_eq!(parse_route_default_interface(stdout), None);
    }

    #[test]
    fn returns_none_for_empty_value() {
        let stdout = "interface:   \n";
        assert_eq!(parse_route_default_interface(stdout), None);
    }

    #[test]
    fn picks_first_interface_line_when_multiple() {
        // 异常情况：route 输出多段（不应发生但要兜底）。取第一段。
        let stdout = "interface: en0\ninterface: en1\n";
        assert_eq!(parse_route_default_interface(stdout), Some("en0"));
    }
}
