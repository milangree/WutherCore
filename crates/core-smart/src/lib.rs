//! core-smart —— Smart 选择引擎。
//!
//! §6 设计：
//! * 评分公式见 §6.4，每次决策可解释（§6.9 `/v1/smart/why`）。
//! * MVP：启发式评分 + EWMA 成功率 + domain/ASN 记忆（domain）。
//! * 后续 M5 加入 LightGBM/异常检测；接口已预留。

#![forbid(unsafe_code)]

pub mod cache;
pub mod explain;
pub mod metrics;
pub mod selector;

pub use explain::{ChoiceExplain, NodeScore};
pub use metrics::NodeStats;
pub use selector::{SmartChoice, SmartContext, SmartSelector};
