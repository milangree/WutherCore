//! core-store —— 持久化层。
//!
//! 选型：[`redb`] 嵌入式 B+tree 存储。理由：
//! * **纯 Rust**，无 C 依赖（vs SQLite/rusqlite），跨平台构建与体积更友好；
//! * **ACID + MVCC**，崩溃安全；
//! * **写性能**：多次小写入合并到一次提交（内置 write batch）；
//! * **读性能**：读取走 mmap，零拷贝 borrowed access；
//! * **单文件**：`data/state/rpkernel.redb`，便于备份/迁移。
//!
//! 支持的 schema（见 [`schema`]）：
//!
//! | 表 | 键 | 值（JSON） | 用途 |
//! |---|---|---|---|
//! | `smart_node_stats` | `node_name` | `NodeStatsBlob` | Smart 节点评分历史 |
//! | `smart_domain_best` | `group\|etld` | `DomainBestBlob` | 域名→最佳节点缓存 |
//! | `smart_negative` | `node_name` | `NegativeBlob` | 失败节点冷却 |
//! | `smart_pin` | `group\|host` | `node_name`（字符串） | 用户固定 |
//! | `group_manual` | `group` | `node_name` | manual 分组当前选择 |
//! | `feed_meta` | `feed_name` | `FeedMetaBlob` | 订阅最近抓取元数据 |
//! | `kv_meta` | 任意 key | bytes | 通用元数据/版本号 |
//!
//! 写入策略：[`Store::write_batch`] 用单事务合并多个 put；
//! [`AsyncWriter`] 提供后台 mpsc + 周期 flush（默认 200ms 或 256 项触发）。

#![forbid(unsafe_code)]

pub mod async_writer;
pub mod blobs;
pub mod schema;
pub mod store;

pub use async_writer::{AsyncWriter, WriteOp};
pub use blobs::{DnsCacheBlob, DomainBestBlob, FeedMetaBlob, HistoryEntry, NegativeBlob, NodeStatsBlob};
pub use store::{Store, StoreError};
