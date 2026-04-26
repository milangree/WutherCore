//! 平台后端 —— 由 cfg(target_os) 选择具体实现。
//!
//! 每个平台模块需要导出：
//! * `pub fn build_engine(plan, deps) -> Result<Arc<dyn CaptureEngine>, CaptureError>`
//! * `pub fn list_interfaces() -> Vec<String>`

use std::sync::Arc;

use crate::engine::{CaptureEngine, CaptureError, CapturePlan};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod macos;
#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios",
    target_os = "android"
)))]
pub mod stub;

// Android 模块：所有平台都参与编译（提供类型 + cfg 守护命令调用），
// 让 select_tier 等纯逻辑可在任何主机做单元测试；实际 build_engine 仍受
// `target_os` 限制。
pub mod android;

pub fn build_engine(plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    #[cfg(target_os = "linux")]
    {
        return linux::build_engine(plan);
    }
    #[cfg(target_os = "windows")]
    {
        return windows::build_engine(plan);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::build_engine(plan);
    }
    #[cfg(target_os = "android")]
    {
        return android::build_engine(plan);
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        return stub::build_engine(plan);
    }
}

pub fn list_interfaces() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        return linux::list_interfaces();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::list_interfaces();
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::list_interfaces();
    }
    #[cfg(target_os = "android")]
    {
        return crate::platform::android::list_interfaces();
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios",
        target_os = "android"
    )))]
    {
        return stub::list_interfaces();
    }
}
