//! 路由表管理 —— 跨平台抽象。
//!
//! 添加与撤销路由必须配对，否则会污染系统路由表。所有由 capture 写入的路由
//! 由 [`RouteTable`] 集中持有，进程退出/Stop 时统一回滚。

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use parking_lot::Mutex;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ManagedRoute {
    pub dest: IpNet,
    pub gateway: Option<IpAddr>,
    pub interface: String,
    pub metric: u32,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    inner: Mutex<Vec<ManagedRoute>>,
}

impl RouteTable {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn add(&self, r: ManagedRoute) -> Result<(), String> {
        // 平台后端会调用 sys_route_add，这里只做记录。
        info!(target: "capture::route", dest = %r.dest, iface = %r.interface, "add route (recorded)");
        self.inner.lock().push(r);
        Ok(())
    }

    pub fn list(&self) -> Vec<ManagedRoute> {
        self.inner.lock().clone()
    }

    /// 退出时回滚所有由本管理器创建的路由。
    pub fn revert_all(&self) {
        let mut g = self.inner.lock();
        for r in g.drain(..) {
            warn!(target: "capture::route", dest = %r.dest, iface = %r.interface, "revert route (recorded)");
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_revert() {
        let t = RouteTable::new();
        t.add(ManagedRoute {
            dest: "0.0.0.0/0".parse().unwrap(),
            gateway: None,
            interface: "rpktun0".into(),
            metric: 1,
        })
        .unwrap();
        assert_eq!(t.len(), 1);
        t.revert_all();
        assert_eq!(t.len(), 0);
    }
}
