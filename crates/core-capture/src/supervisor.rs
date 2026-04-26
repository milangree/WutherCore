//! CaptureSupervisor —— 把 [`CaptureEngine`] 与 [`Runtime`] 串起来。
//!
//! 流程：
//! 1. 由配置生成 [`CapturePlan`]；
//! 2. 平台 `build_engine` 创建 engine；
//! 3. spawn 一条事件协程：每一个 [`CaptureEvent`] 调用 `runtime.dial`；
//! 4. （可选）启动 fake-dns server 监听 53/udp，与 [`FakeIpPool`] 交互。
//!
//! supervisor 持有 stop_tx，便于 graceful shutdown。

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use core_config::model::{Capture, Mesh};
use core_resolver::fake_ip::{FakeIpConfig, FakeIpPool};
use core_runtime::Runtime;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::engine::{CaptureEngine, CaptureError, CaptureEvent, CapturePlan, EngineKind};

pub struct CaptureSupervisor {
    pub plan: CapturePlan,
    pub engine: Arc<dyn CaptureEngine>,
    pub fake_pool: Arc<FakeIpPool>,
    handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
    stopper: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    dns_handle: parking_lot::Mutex<Option<JoinHandle<()>>>,
}

impl CaptureSupervisor {
    /// 由 capture+mesh 配置 + Runtime 生成 supervisor。off 时返回 None。
    pub fn build(capture: &Capture, _mesh: &Mesh) -> Result<Option<Arc<Self>>, CaptureError> {
        let plan = CapturePlan::from_config(capture)?;
        if plan.kind == EngineKind::None {
            return Ok(None);
        }
        let engine = crate::platform::build_engine(plan.clone())?;
        let pool = Arc::new(FakeIpPool::new(FakeIpConfig {
            v4_cidr: plan.tun_v4_cidr,
            v6_cidr: plan.tun_v6_cidr,
            ..FakeIpConfig::default()
        }));
        Ok(Some(Arc::new(Self {
            plan,
            engine,
            fake_pool: pool,
            handle: parking_lot::Mutex::new(None),
            stopper: parking_lot::Mutex::new(None),
            dns_handle: parking_lot::Mutex::new(None),
        })))
    }

    /// 启动 capture：让 engine 就绪，并把事件转发给 runtime.dial。
    pub async fn start(self: &Arc<Self>, runtime: Arc<Runtime>) -> Result<(), CaptureError> {
        let (tx, mut rx) = mpsc::channel::<CaptureEvent>(1024);
        let (stop_tx, mut stop_rx) = oneshot::channel();
        self.engine.clone().start(tx).await?;

        let runtime_for_loop = runtime.clone();
        let pool = self.fake_pool.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    event = rx.recv() => {
                        let Some(evt) = event else { break };
                        let host = evt.fake_host
                            .clone()
                            .or_else(|| pool.lookup(evt.original_dst.ip()))
                            .unwrap_or_else(|| evt.original_dst.ip().to_string());
                        debug!(target: "capture::dispatch", host = %host, port = evt.original_dst.port(), net = evt.network, "dial");
                        let net = if evt.network == "udp" {
                            core_route::NetworkKind::Udp
                        } else {
                            core_route::NetworkKind::Tcp
                        };
                        if let Err(e) = runtime_for_loop
                            .dial(&host, evt.original_dst.port(), net)
                            .await
                        {
                            warn!(target: "capture::dispatch", error = %e, host = %host, "dial failed");
                        }
                    }
                }
            }
        });
        *self.handle.lock() = Some(handle);
        *self.stopper.lock() = Some(stop_tx);

        // 可选 fake-dns
        if self.plan.hijack_dns {
            let pool = self.fake_pool.clone();
            let dns_handle = tokio::spawn(async move {
                let bind: SocketAddr = "127.0.0.1:5454".parse().unwrap();
                if let Err(e) = crate::fakeip_dns::run_fake_dns(bind, pool).await {
                    warn!(target: "capture::dns", error = %e, "fake-dns exited");
                }
            });
            *self.dns_handle.lock() = Some(dns_handle);
        }

        info!(target: "capture", kind = ?self.plan.kind, "capture supervisor running");
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) -> Result<(), CaptureError> {
        if let Some(tx) = self.stopper.lock().take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.lock().take() {
            h.abort();
        }
        if let Some(h) = self.dns_handle.lock().take() {
            h.abort();
        }
        self.engine.clone().stop().await?;
        Ok(())
    }

    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "engine": self.engine.report(),
            "fake_pool_size": self.fake_pool.len(),
            "exclude_cidrs": self.plan.exclude_cidrs.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
            "hijack_dns": self.plan.hijack_dns,
        })
    }
}

/// 工具：把字符串地址解析。
pub fn first_addr(s: &str) -> Option<SocketAddr> {
    s.to_socket_addrs().ok().and_then(|mut it| it.next())
}
