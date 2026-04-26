//! 不支持的平台：仅返回 doctor 风格错误。

use std::sync::Arc;

use crate::engine::{CaptureEngine, CaptureError, CapturePlan};

pub fn list_interfaces() -> Vec<String> {
    vec![]
}

pub fn build_engine(_plan: CapturePlan) -> Result<Arc<dyn CaptureEngine>, CaptureError> {
    Err(CaptureError::Unsupported(format!(
        "capture 在当前平台 {} 暂不支持，请使用普通代理模式",
        std::env::consts::OS
    )))
}
