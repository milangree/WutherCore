//! 订阅磁盘缓存 —— 抓取失败时回退到上一次成功内容。

use std::path::{Path, PathBuf};

use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct FeedDiskCache {
    root: PathBuf,
}

impl FeedDiskCache {
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path_for(&self, name: &str) -> PathBuf {
        let safe = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect::<String>();
        self.root.join(format!("{safe}.cache"))
    }

    pub fn save(&self, name: &str, data: &[u8]) {
        let path = self.path_for(name);
        if let Err(e) = std::fs::write(&path, data) {
            warn!(target: "feeds::cache", error = %e, path = %path.display(), "save failed");
        } else {
            debug!(target: "feeds::cache", path = %path.display(), bytes = data.len(), "saved");
        }
    }

    pub fn load(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.path_for(name);
        std::fs::read(&path).ok()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
