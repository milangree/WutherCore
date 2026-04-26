//! Runtime —— 启动 + 持有所有运行时组件 + 提供 dispatch 接口。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use core_config::runtime_plan::RuntimePlan;
use core_observe::{ConnectionTable, Metrics};
use core_outbound::{
    adapter::{DialContext, SharedOutbound},
    registry::{register_nodes, OutboundRegistry},
};
use core_resolver::Resolver;
use core_route::{FlowContext, NetworkKind, RouteDecision, RouteEngine};
use core_smart::SmartSelector;
use core_store::{schema::GROUP_MANUAL, Store};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::group_selector::GroupSelector;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("配置错误: {0}")]
    Config(#[from] core_config::ConfigError),
    #[error("出站不存在: {0}")]
    UnknownOutbound(String),
    #[error("IO 错误: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Runtime {
    pub plan: RuntimePlan,
    pub outbounds: parking_lot::RwLock<OutboundRegistry>,
    pub groups: parking_lot::RwLock<BTreeMap<String, Arc<GroupSelector>>>,
    pub route: RouteEngine,
    pub resolver: Arc<Resolver>,
    pub smart: Arc<SmartSelector>,
    pub metrics: Arc<Metrics>,
    pub connections: Arc<ConnectionTable>,
    pub store: Option<Arc<Store>>,
}

impl Runtime {
    /// 从 [`RuntimePlan`] 构造 Runtime，但不启动任何监听。
    pub fn build(plan: RuntimePlan) -> Self {
        Self::build_with_store(plan, None)
    }

    /// 同 [`Runtime::build`]，但带持久化 store —— Smart 评分、group 手选、
    /// pin/avoid 等数据会从 store 加载并由后台 writer 异步落盘。
    pub fn build_with_store(plan: RuntimePlan, store: Option<Arc<Store>>) -> Self {
        let mut reg = OutboundRegistry::new();
        register_nodes(&mut reg, &plan.nodes);

        let mut groups = BTreeMap::new();
        for (name, g) in &plan.groups {
            groups.insert(name.clone(), Arc::new(GroupSelector::new(g.clone())));
        }

        let route = RouteEngine::new(plan.route.clone());
        let resolver = Arc::new(Resolver::new(plan.resolver.clone()));
        let smart = if let Some(store) = store.clone() {
            Arc::new(SmartSelector::with_store(
                plan.smart.goal,
                plan.smart.sticky,
                store,
            ))
        } else {
            Arc::new(SmartSelector::new(plan.smart.goal, plan.smart.sticky))
        };

        // Smart 节点初始化
        for n in &plan.nodes {
            smart.ensure_node(&n.name);
        }

        // 恢复 group manual 选择
        if let Some(store) = &store {
            if let Ok(rows) = store.iter_string(GROUP_MANUAL) {
                for (group_name, picked) in rows {
                    if let Some(g) = groups.get(&group_name) {
                        if g.members().iter().any(|m| m == &picked) {
                            g.set_manual(picked);
                        }
                    }
                }
            }
        }

        Self {
            plan,
            outbounds: parking_lot::RwLock::new(reg),
            groups: parking_lot::RwLock::new(groups),
            route,
            resolver,
            smart,
            metrics: Metrics::new(),
            connections: ConnectionTable::new(),
            store,
        }
    }

    /// 把 group manual 选择写入 store（持久化跨重启）。
    pub fn set_group_manual(&self, group: &str, node: &str) {
        let groups = self.groups.read();
        if let Some(g) = groups.get(group) {
            g.set_manual(node);
        }
        if let Some(store) = &self.store {
            let _ = store.put_json::<String>(
                core_store::schema::GROUP_MANUAL,
                group,
                &node.to_string(),
            );
            // 不用 JSON：直接存裸字符串。这里复用 put_json 会写入 "node" 带引号的 JSON。
            // 改为直接 batch put：
            let _ = store.write_batch(&[core_store::store::BatchOp::PutGroupManual(
                group.to_string(),
                node.to_string(),
            )]);
        }
    }

    /// 优雅停止：把 Smart writer 的内存数据 flush 到磁盘。
    pub async fn shutdown(&self) {
        self.smart.shutdown().await;
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.read().keys().cloned().collect()
    }

    pub fn outbound_names(&self) -> Vec<String> {
        self.outbounds.read().names().map(|s| s.to_string()).collect()
    }

    /// 把订阅刷新得到的最新节点列表注入到 outbound registry，
    /// 同时把 group.members 中的 `feed:<name>` 占位符替换为真实节点名集合。
    pub fn apply_feed_nodes(&self, feed_name: &str, nodes: Vec<core_config::node_uri::ParsedNode>) {
        let placeholder = format!("feed:{feed_name}");
        let mut new_names: Vec<String> = Vec::with_capacity(nodes.len());
        {
            let mut reg = self.outbounds.write();
            for n in &nodes {
                let ob = core_outbound::registry::build_outbound(n);
                reg.insert(n.name.clone(), ob);
                new_names.push(n.name.clone());
                self.smart.ensure_node(&n.name);
            }
        }
        // 重建受影响的 GroupSelector：对每个含 feed:<name> 占位符的分组，
        // 用 (原 members - 占位符 + 实际节点名) 重建一个新的 selector。
        let plan_map = self.plan.groups.clone();
        let mut groups = self.groups.write();
        for (name, base_plan) in plan_map {
            if base_plan.members.iter().any(|m| m == &placeholder) {
                let mut new_members = Vec::with_capacity(base_plan.members.len() + new_names.len());
                for m in &base_plan.members {
                    if m == &placeholder {
                        for nn in &new_names {
                            if !new_members.contains(nn) {
                                new_members.push(nn.clone());
                            }
                        }
                    } else if !new_members.contains(m) {
                        new_members.push(m.clone());
                    }
                }
                let mut updated = base_plan.clone();
                updated.members = new_members;
                groups.insert(
                    name.clone(),
                    Arc::new(crate::group_selector::GroupSelector::new(updated)),
                );
            }
        }
        tracing::info!(
            target: "feeds",
            feed = feed_name,
            registered = new_names.len(),
            "feed nodes applied to runtime"
        );
    }

    pub fn pick_outbound(&self, host: &str, port: u16, network: NetworkKind) -> (RouteDecision, String, SharedOutbound) {
        self.metrics.inc_route();
        let ip = host.parse().ok();
        let ctx = FlowContext {
            host: host.to_string(),
            ip,
            port,
            network,
            process: None,
            protocol: None,
        };
        let (decision, kind, source) = self.route.decide(&ctx);
        debug!(target: "route", host = %host, port, ?decision, kind, source = %source, "rule hit");

        let (label, ob) = match &decision {
            RouteDecision::Direct => ("DIRECT".into(), self.must_get("DIRECT")),
            RouteDecision::Block => ("BLOCK".into(), self.must_get("BLOCK")),
            RouteDecision::Group(name) => self.pick_in_group(name, host),
        };
        let _ = kind;
        let _ = source;
        (decision, label, ob)
    }

    fn pick_in_group(&self, group: &str, host: &str) -> (String, SharedOutbound) {
        let groups = self.groups.read();
        let Some(g) = groups.get(group) else {
            warn!(target: "route", group, "未知分组，回退 DIRECT");
            return ("DIRECT".into(), self.must_get("DIRECT"));
        };
        let pick = g.pick(host, &self.smart);
        if let Some(name) = pick {
            if let Some(ob) = self.outbounds.read().get(&name) {
                return (name, ob);
            }
            warn!(target: "route", node = %name, "节点未注册，回退 DIRECT");
        }
        ("DIRECT".into(), self.must_get("DIRECT"))
    }

    fn must_get(&self, name: &str) -> SharedOutbound {
        self.outbounds
            .read()
            .get(name)
            .expect("DIRECT/BLOCK 必须存在")
    }

    /// 给 inbound 调用：根据 host:port 找出口并 dial。
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        network: NetworkKind,
    ) -> std::io::Result<DialResult> {
        let started = Instant::now();
        let (decision, label, ob) = self.pick_outbound(host, port, network);
        if matches!(decision, RouteDecision::Block) {
            info!(target: "dispatch", %host, port, "blocked");
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "blocked",
            ));
        }
        let ctx = DialContext {
            host: host.to_string(),
            port,
            network: match network {
                NetworkKind::Tcp => "tcp",
                NetworkKind::Udp => "udp",
            },
        };
        let res = ob.dial_tcp(ctx).await;
        let elapsed = started.elapsed();
        match &res {
            Ok(_) => {
                if label != "DIRECT" && label != "BLOCK" {
                    self.smart.record_success(&label, elapsed);
                }
            }
            Err(e) => {
                if label != "DIRECT" && label != "BLOCK" {
                    self.smart.record_failure(&label, e.to_string());
                }
            }
        }
        let stream = res?;
        Ok(DialResult {
            stream,
            outbound: label,
            decision,
            elapsed,
        })
    }
}

pub struct DialResult {
    pub stream: core_outbound::adapter::BoxedStream,
    pub outbound: String,
    pub decision: RouteDecision,
    pub elapsed: std::time::Duration,
}
