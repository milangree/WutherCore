//! 加载 + 校验 + 默认值合并 + 编译为 [`RuntimePlan`]。

use std::path::Path;

use crate::error::{ConfigError, ConfigErrorKind, ConfigResult};
use crate::model::*;
use crate::profile::apply_defaults;
use crate::runtime_plan::RuntimePlan;

/// 从字符串加载并完整编译。
pub fn load_from_str(text: &str) -> ConfigResult<RuntimePlan> {
    let mut cfg: UserConfig = serde_yaml::from_str(text)?;
    if cfg.version != 1 {
        return Err(ConfigError::new(ConfigErrorKind::UnsupportedVersion(cfg.version))
            .hint("当前版本为 1；请保持 version: 1"));
    }
    apply_defaults(&mut cfg);
    crate::runtime_plan::compile(cfg)
}

/// 读取文件后转交 [`load_from_str`]。
pub fn load_from_path<P: AsRef<Path>>(path: P) -> ConfigResult<RuntimePlan> {
    let text = std::fs::read_to_string(&path).map_err(|e| {
        ConfigError::new(ConfigErrorKind::Io(e))
            .at(path.as_ref().display().to_string())
            .hint("请确认文件存在且具有读取权限")
    })?;
    load_from_str(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_yaml_loads() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/sub"
nodes:
  - "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#HK-01"
  - "trojan://pwd@example.com:443?sni=example.com#US-01"
"#;
        let plan = load_from_str(yaml).unwrap();
        assert!(plan.groups.contains_key("main"));
        assert_eq!(plan.nodes.len(), 2);
        assert_eq!(plan.route.preset, "cn_smart");
    }

    #[test]
    fn unknown_group_use_yields_friendly_error() {
        let yaml = r#"
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/sub"
groups:
  main:
    choose: smart
    use: ["airport2"]
"#;
        let err = load_from_str(yaml).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("引用未定义"));
        assert!(s.contains("airport2"));
    }
}
