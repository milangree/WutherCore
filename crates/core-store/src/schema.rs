//! redb 表定义 —— 全部 `&str → &[u8]`，值为 JSON 序列化结果。

use redb::TableDefinition;

pub const SMART_NODE_STATS: TableDefinition<&str, &[u8]> = TableDefinition::new("smart_node_stats");
pub const SMART_DOMAIN_BEST: TableDefinition<&str, &[u8]> =
    TableDefinition::new("smart_domain_best");
pub const SMART_NEGATIVE: TableDefinition<&str, &[u8]> = TableDefinition::new("smart_negative");
pub const SMART_PIN: TableDefinition<&str, &[u8]> = TableDefinition::new("smart_pin");
pub const GROUP_MANUAL: TableDefinition<&str, &[u8]> = TableDefinition::new("group_manual");
pub const FEED_META: TableDefinition<&str, &[u8]> = TableDefinition::new("feed_meta");
pub const DNS_CACHE: TableDefinition<&str, &[u8]> = TableDefinition::new("dns_cache");
pub const KV_META: TableDefinition<&str, &[u8]> = TableDefinition::new("kv_meta");

pub const ALL_TABLES: &[&str] = &[
    "smart_node_stats",
    "smart_domain_best",
    "smart_negative",
    "smart_pin",
    "group_manual",
    "feed_meta",
    "dns_cache",
    "kv_meta",
];

pub const SCHEMA_VERSION: u32 = 1;
pub const SCHEMA_KEY: &str = "schema_version";
