//! core-runtime —— 把 [`RuntimePlan`] 接成一张实际可工作的 graph。
//!
//! §11 模块划分：runtime 持有 selector + dispatcher + 资源生命周期。
//! 它不负责具体的 inbound/outbound 协议实现，只负责把它们粘起来。

#![forbid(unsafe_code)]

pub mod engine;
pub mod group_selector;
pub mod health;

pub use engine::{Runtime, RuntimeError};
pub use group_selector::GroupSelector;
pub use health::{spawn_periodic, DelayError, UrlTestConfig, UrlTester};
