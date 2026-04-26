//! GroupSelector —— 对应 §5.6 的 manual/smart/fast/stable/spread/chain。
//!
//! MVP 实现：
//! * manual：当前选择由用户/API 设置，回退到 members[0]。
//! * smart：转发给 [`SmartSelector`]。
//! * fast/stable/spread/chain：按 round-robin / 第一个可用 / 取首位 简化处理。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use core_config::model::ChooseStrategy;
use core_config::runtime_plan::GroupPlan;
use core_smart::{SmartContext, SmartSelector};
use parking_lot::RwLock;

#[derive(Debug)]
pub struct GroupSelector {
    plan: GroupPlan,
    manual_pick: RwLock<Option<String>>,
    rr_idx: AtomicUsize,
}

impl GroupSelector {
    pub fn new(plan: GroupPlan) -> Self {
        Self {
            plan,
            manual_pick: RwLock::new(None),
            rr_idx: AtomicUsize::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.plan.name
    }

    pub fn members(&self) -> &[String] {
        &self.plan.members
    }

    pub fn set_manual(&self, node: impl Into<String>) {
        *self.manual_pick.write() = Some(node.into());
    }

    pub fn current_manual(&self) -> Option<String> {
        self.manual_pick.read().clone()
    }

    /// 选出本次连接应该使用的节点名。返回 None 时调用方应该回退到 DIRECT。
    pub fn pick(&self, host: &str, smart: &Arc<SmartSelector>) -> Option<String> {
        if self.plan.members.is_empty() {
            return None;
        }
        match self.plan.choose {
            ChooseStrategy::Manual => self
                .manual_pick
                .read()
                .clone()
                .or_else(|| self.plan.members.first().cloned()),
            ChooseStrategy::Smart => {
                let ctx = SmartContext {
                    group: self.plan.name.clone(),
                    host: host.to_string(),
                    prefer: self.plan.prefer.clone(),
                    avoid: self.plan.avoid.clone(),
                };
                Some(smart.choose(&ctx, &self.plan.members).node)
            }
            ChooseStrategy::Fast => Some(self.plan.members[0].clone()),
            ChooseStrategy::Stable => Some(self.plan.members[0].clone()),
            ChooseStrategy::Spread => {
                let i = self.rr_idx.fetch_add(1, Ordering::Relaxed) % self.plan.members.len();
                Some(self.plan.members[i].clone())
            }
            ChooseStrategy::Chain => self.plan.path.first().cloned().or_else(|| self.plan.members.first().cloned()),
        }
    }
}
