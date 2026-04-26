use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// 简单初始化：环境变量 `RP_LOG`、默认 info；`RP_LOG_FORMAT=json` 启用 JSON。
pub fn init_tracing() {
    let env = std::env::var("RP_LOG").unwrap_or_else(|_| "info".into());
    let filter = EnvFilter::try_new(&env).unwrap_or_else(|_| EnvFilter::new("info"));
    let json = std::env::var("RP_LOG_FORMAT").map(|s| s == "json").unwrap_or(false);

    let registry = tracing_subscriber::registry().with(filter);
    if json {
        let layer = fmt::layer().json();
        let _ = registry.with(layer).try_init();
    } else {
        let layer = fmt::layer().with_target(true).with_level(true);
        let _ = registry.with(layer).try_init();
    }
}
