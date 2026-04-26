//! 配置数据模型 —— 直接对应 §5 字段完整说明。
//!
//! 所有 field 默认值通过 [`profile::Profile::apply_defaults`] 注入，
//! 模型本身只负责"原样反序列化 + 短写法/长写法兼容"。

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// 顶层配置 —— 用户实际写的 YAML。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// 必填，目前固定为 `1`。
    pub version: u32,
    #[serde(default)]
    pub profile: Profile,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub listen: Option<Listen>,
    #[serde(default)]
    pub feeds: BTreeMap<String, FeedSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub groups: BTreeMap<String, GroupSpec>,
    #[serde(default)]
    pub route: Option<Route>,
    #[serde(default)]
    pub resolver: Option<Resolver>,
    #[serde(default)]
    pub capture: Option<Capture>,
    #[serde(default)]
    pub smart: Option<Smart>,
    #[serde(default)]
    pub ui: Option<Ui>,
    #[serde(default)]
    pub mesh: Option<Mesh>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Desktop,
    Router,
    Server,
    Mobile,
}

impl Default for Profile {
    fn default() -> Self {
        Profile::Desktop
    }
}

/* ---------------- listen ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    #[serde(default)]
    pub local: Option<ListenLocal>,
    #[serde(default)]
    pub panel: Option<PanelBind>,
    #[serde(default)]
    pub share: Option<Share>,
    #[serde(default)]
    pub auth: Vec<String>,
}

/// listen.local 支持端口写法 / 完整对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ListenLocal {
    Port(u16),
    Detail(ListenLocalDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListenLocalDetail {
    #[serde(default = "default_localhost")]
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub auth: Vec<String>,
    #[serde(default = "default_true")]
    pub udp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PanelBind {
    Off(bool),
    Port(u16),
    Address(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Share {
    False,
    Home,
    All,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ShareValue {
    Bool(bool),
    Tag(Share),
}

/* ---------------- feeds ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeedSpec {
    Url(String),
    Detail(FeedDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedDetail {
    pub url: String,
    #[serde(default = "default_feed_every", with = "humantime_serde")]
    pub every: Duration,
    #[serde(default = "default_feed_via")]
    pub via: String,
    #[serde(default)]
    pub keep: FeedFilter,
    #[serde(default)]
    pub drop: FeedFilter,
    #[serde(default)]
    pub rename: FeedRename,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedFilter {
    #[serde(default)]
    pub name_has: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FeedRename {
    #[serde(default)]
    pub add_prefix: Option<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

/* ---------------- nodes ---------------- */

/// 手动节点；支持纯 URI 字符串或结构化对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NodeSpec {
    Uri(String),
    Detail(NodeDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeDetail {
    pub name: String,
    #[serde(default)]
    pub link: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub login: Option<NodeLogin>,
    #[serde(default)]
    pub secure: Option<NodeSecure>,
    #[serde(default)]
    pub transport: Option<NodeTransport>,
    #[serde(default)]
    pub network: Option<NodeNetwork>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeLogin {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeSecure {
    #[serde(default)]
    pub tls: bool,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub utls: Option<String>,
    #[serde(default)]
    pub reality: Option<bool>,
    #[serde(default)]
    pub ech: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeTransport {
    #[serde(default = "default_transport")]
    pub kind: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeNetwork {
    #[serde(default = "default_true")]
    pub udp: bool,
    #[serde(default)]
    pub tfo: bool,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default)]
    pub mark: Option<u32>,
    #[serde(default)]
    pub ip_family: Option<String>,
}

/* ---------------- groups ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupSpec {
    #[serde(default = "default_choose")]
    pub choose: ChooseStrategy,
    #[serde(default)]
    pub r#use: Vec<String>,
    #[serde(default)]
    pub prefer: Vec<String>,
    #[serde(default)]
    pub avoid: Vec<String>,
    #[serde(default)]
    pub check: Option<String>,
    #[serde(default)]
    pub sticky: Option<String>,
    #[serde(default)]
    pub path: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChooseStrategy {
    Manual,
    Smart,
    Fast,
    Stable,
    Spread,
    Chain,
}

/* ---------------- route ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Route {
    #[serde(default = "default_route_preset")]
    pub preset: String,
    #[serde(default = "default_route_final")]
    pub r#final: String,
    #[serde(default)]
    pub steps: Vec<String>,
    /// 外部规则集 —— mihomo / sing-box / 自定义 payload。
    /// 在 [`steps`] 中通过 `set:<name> -> <action>` 引用。
    #[serde(default)]
    pub sets: BTreeMap<String, RuleSetSpec>,
}

/// route.sets.<name> 配置 —— 与 [`core-ruleset::RulesetSpec`] 一一对应，
/// 这里只做 YAML 反序列化所需的最小字段；运行时由 core-ruleset 编译。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RuleSetSpec {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub payload: Vec<String>,
    #[serde(default = "default_ruleset_type")]
    pub r#type: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "default_ruleset_every", with = "humantime_serde")]
    pub every: Duration,
    #[serde(default = "default_feed_via")]
    pub via: String,
}

fn default_ruleset_type() -> String { "domain".into() }
fn default_ruleset_every() -> Duration { Duration::from_secs(24 * 3600) }

/* ---------------- resolver ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolver {
    #[serde(default = "default_resolver_mode")]
    pub mode: ResolverMode,
    #[serde(default = "default_fake")]
    pub fake: FakeMode,
    #[serde(default = "default_cache", with = "humantime_serde")]
    pub cache: Duration,
    #[serde(default)]
    pub mainland: Option<String>,
    #[serde(default)]
    pub overseas: Option<String>,
    #[serde(default)]
    pub servers: BTreeMap<String, String>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            mode: ResolverMode::Smart,
            fake: FakeMode::Auto,
            cache: default_cache(),
            mainland: Some("ali".into()),
            overseas: Some("cloudflare".into()),
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverMode {
    System,
    Secure,
    Fake,
    Smart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FakeMode {
    Off,
    Auto,
    Force,
}

/* ---------------- capture ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    #[serde(default)]
    pub on: bool,
    #[serde(default = "default_capture_method")]
    pub method: CaptureMethod,
    #[serde(default = "default_capture_traffic")]
    pub traffic: CaptureTraffic,
    #[serde(default = "default_capture_resolver")]
    pub resolver: CaptureResolver,
    #[serde(default = "default_capture_stack")]
    pub stack: CaptureStack,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default = "default_true")]
    pub offload: bool,
    #[serde(default)]
    pub exclude: CaptureExclude,
}

impl Default for Capture {
    fn default() -> Self {
        Self {
            on: false,
            method: CaptureMethod::Auto,
            traffic: CaptureTraffic::System,
            resolver: CaptureResolver::Hijack,
            stack: CaptureStack::Native,
            mtu: None,
            offload: true,
            exclude: CaptureExclude::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMethod {
    Auto,
    #[serde(rename = "virtual_nic")]
    VirtualNic,
    Tproxy,
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureTraffic {
    System,
    Lan,
    Apps,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureResolver {
    Off,
    Hijack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureStack {
    Native,
    Gvisor,
    Smoltcp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureExclude {
    #[serde(default)]
    pub cidr: Vec<String>,
    #[serde(default)]
    pub process: Vec<String>,
}

/* ---------------- smart ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smart {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default = "default_smart_goal")]
    pub goal: SmartGoal,
    #[serde(default = "default_smart_learn", with = "humantime_serde")]
    pub learn: Duration,
    #[serde(default = "default_smart_sticky")]
    pub sticky: SmartSticky,
    #[serde(default = "default_true")]
    pub explain: bool,
}

impl Default for Smart {
    fn default() -> Self {
        Self {
            on: true,
            goal: SmartGoal::Balanced,
            learn: default_smart_learn(),
            sticky: SmartSticky::Site,
            explain: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmartGoal {
    Balanced,
    Speed,
    Stability,
    LowCost,
    Privacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmartSticky {
    Off,
    Site,
    Session,
}

/* ---------------- ui ---------------- */

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ui {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default = "default_dashboard")]
    pub dashboard: String,
    #[serde(default)]
    pub api: UiApi,
    #[serde(default)]
    pub cors: Vec<String>,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            on: true,
            secret: None,
            dashboard: default_dashboard(),
            api: UiApi::default(),
            cors: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiApi {
    #[serde(default = "default_true")]
    pub native: bool,
    #[serde(default = "default_true")]
    pub clash_compat: bool,
}

impl Default for UiApi {
    fn default() -> Self {
        Self {
            native: true,
            clash_compat: true,
        }
    }
}

/* ---------------- mesh ---------------- */

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mesh {
    #[serde(default)]
    pub tailscale: Option<MeshTailscale>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshTailscale {
    #[serde(default = "default_true")]
    pub on: bool,
    #[serde(default = "default_tailscale_mode")]
    pub mode: TailscaleMode,
    #[serde(default = "default_true")]
    pub keep_tailnet_direct: bool,
    #[serde(default)]
    pub expose_as_node: bool,
    #[serde(default)]
    pub userspace_proxy: Option<TailscaleUserspaceProxy>,
}

impl Default for MeshTailscale {
    fn default() -> Self {
        Self {
            on: true,
            mode: TailscaleMode::Auto,
            keep_tailnet_direct: true,
            expose_as_node: false,
            userspace_proxy: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TailscaleMode {
    Auto,
    Localapi,
    Userspace,
    Tsnet,
    Off,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TailscaleUserspaceProxy {
    #[serde(default)]
    pub socks: Option<String>,
    #[serde(default)]
    pub http: Option<String>,
}

/* ---------------- defaults ---------------- */

fn default_localhost() -> String {
    "127.0.0.1".into()
}
fn default_true() -> bool {
    true
}
fn default_feed_every() -> Duration {
    Duration::from_secs(12 * 3600)
}
fn default_feed_via() -> String {
    "direct".into()
}
fn default_choose() -> ChooseStrategy {
    ChooseStrategy::Smart
}
fn default_route_preset() -> String {
    "cn_smart".into()
}
fn default_route_final() -> String {
    "main".into()
}
fn default_resolver_mode() -> ResolverMode {
    ResolverMode::Smart
}
fn default_fake() -> FakeMode {
    FakeMode::Auto
}
fn default_cache() -> Duration {
    Duration::from_secs(24 * 3600)
}
fn default_transport() -> String {
    "tcp".into()
}
fn default_capture_method() -> CaptureMethod {
    CaptureMethod::Auto
}
fn default_capture_traffic() -> CaptureTraffic {
    CaptureTraffic::System
}
fn default_capture_resolver() -> CaptureResolver {
    CaptureResolver::Hijack
}
fn default_capture_stack() -> CaptureStack {
    CaptureStack::Native
}
fn default_smart_goal() -> SmartGoal {
    SmartGoal::Balanced
}
fn default_smart_learn() -> Duration {
    Duration::from_secs(14 * 24 * 3600)
}
fn default_smart_sticky() -> SmartSticky {
    SmartSticky::Site
}
fn default_dashboard() -> String {
    "auto".into()
}
fn default_tailscale_mode() -> TailscaleMode {
    TailscaleMode::Auto
}
