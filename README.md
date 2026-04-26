# WutherCore

> **Rust 代理内核** —— Friendly YAML 配置 + Smart 自动选节点 + mihomo / sing-box 双向兼容 + Android root 完整 IPv4/IPv6 透明代理。
>
> 设计目标：小白能看懂、专家能扩展；配置字段独立但能力面对齐 mihomo / sing-box。

[![rust](https://img.shields.io/badge/rust-1.75%2B-orange)]() [![tests](https://img.shields.io/badge/tests-119%2F0-brightgreen)]() [![crates](https://img.shields.io/badge/workspace-15%20crates-blue)]() [![license](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blueviolet)]()

参见 [RP内核设计文档.md](RP内核设计文档.md) 获取完整设计。

---

## 目录

- [核心特性](#核心特性)
- [10 个词的配置](#10-个词的配置)
- [最小有效配置](#最小有效配置)
- [快速开始](#快速开始)
- [工作空间布局](#工作空间布局)
- [功能矩阵](#功能矩阵)
- [协议支持](#协议支持)
- [DNS 系统](#dns-系统-sing-box-1.14-兼容)
- [规则集系统](#规则集系统)
- [Android Root 模式](#android-root-模式-5-层自动降级)
- [性能与构建](#性能与构建)
- [API](#api)
- [测试](#测试)
- [路线图](#路线图)

---

## 核心特性

| 维度 | 内容 |
|---|---|
| **配置** | Friendly YAML —— 用户只需理解 10 个词；profile 自动补默认；mihomo/sing-box 字段双向迁移 |
| **协议** | direct / block / http / socks5 / **Shadowsocks AEAD** / **Trojan** / **VLESS（TLS+WS）**；vmess/hysteria2/tuic 等保留 stub 不假装 |
| **DNS** | 乐观缓存 (stale-while-revalidate) + 多 group 并发（fastest/fallback/all）+ sing-box 1.14 完整动作（evaluate/respond/predefined/reject）+ 三层 ECS fallback + redb 持久化 |
| **路由** | 规则引擎 + 内置 preset + **L7 协议嗅探**（STUN/DTLS/QUIC/TLS-SNI/HTTP）+ WebRTC 防 IP 泄漏 |
| **规则集** | mihomo yaml/txt/list + sing-box JSON + **自研 RRS 二进制**（CRC32 校验，~45% 体积，双向无损转换） |
| **Smart** | 启发式评分 + EWMA 成功率 + domain_best 缓存 + URLTest 周期测速 + 全部持久化 |
| **入站** | Mixed (HTTP+SOCKS5 同端口) + 跨平台权限检测 + 智能端口降级 + Android root 优先/降级 VpnService |
| **透明代理** | TUN / TProxy / redirect 平台后端 + Fake-IP 池 + Tailscale 防回环 + Android **5 Tier 自动降级** |
| **持久化** | redb 嵌入式 KV + AsyncWriter 批量异步落盘（Smart/DNS缓存/group手选/feed元数据全持久化） |
| **API** | /v1 原生 + Clash/Mihomo Dashboard 兼容 + URLTest delay endpoints |
| **构建** | Windows 一键多平台（zigbuild / cross / cargo-ndk）+ rust-lld/mold 链接 + dev 增量 22s → 2s |

---

## 10 个词的配置

| 词       | 小白理解               | 内核含义                                      |
|----------|------------------------|-----------------------------------------------|
| listen   | 软件在哪个端口等你连接 | HTTP/SOCKS/Mixed/控制面板/API 入站监听        |
| feeds    | 机场订阅链接           | 远程/本地 Provider，支持过滤、重命名、健康检查 |
| nodes    | 自己手动添加的节点     | URI 字符串或结构化对象                        |
| groups   | 一堆节点怎么选         | manual / smart / fast / stable / spread / chain |
| route    | 哪些直连，哪些走代理   | 规则引擎 + preset + sets + L7 嗅探            |
| resolver | 域名怎么查             | 多 group 并发 / DoH/DoT/UDP / 乐观缓存 / 防泄漏 |
| capture  | 是否接管全设备流量     | TUN / TProxy / redirect / DNS 劫持            |
| smart    | 自动选最合适节点       | EWMA + URLTest + 解释 API                     |
| ui       | 面板和 API             | /v1 原生 + Clash/Mihomo 兼容                   |
| mesh     | 和内网/VPN 协同        | Tailscale / WireGuard / 局域网保护            |

---

## 最小有效配置

```yaml
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/your-subscription"
```

内核自动补全：本地代理端口 7890、面板 9090、main 分组 Smart 选节点、国内直连、国外走 main、DoH/DoT smart 解析。

---

## 快速开始

### 一键构建（Windows 主机）

```cmd
:: 默认矩阵：Windows MSVC x64/ARM64 + Linux musl/gnu x64/ARM64 + Android arm64 (NDK 自动发现)
build.cmd

:: 单目标
build.cmd windows
build.cmd linux        :: x86_64-unknown-linux-musl，zigbuild 后端
build.cmd android      :: aarch64-linux-android，cargo-ndk 后端

:: 强制后端
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
```

详见 [scripts/README.md](scripts/README.md)。

### 直接 cargo

```bash
cargo build --release -p proxy-core

# 校验配置
./target/release/proxy-core check    examples/desktop.yaml

# 输出展开后的 RuntimePlan（JSON）
./target/release/proxy-core explain  examples/desktop.yaml

# 运行内核
./target/release/proxy-core run -c   examples/desktop.yaml
```

### CLI 子命令

```text
proxy-core run        -c <yaml>             启动内核
proxy-core check         <yaml>             校验配置
proxy-core explain       <yaml>             输出 RuntimePlan JSON
proxy-core migrate mihomo <old.yaml> -o <friendly.yaml>
proxy-core feeds   list/refresh             订阅源管理
proxy-core ruleset list/refresh/convert     规则集管理（含 yaml↔txt↔json↔rrs 转换）
proxy-core store   info/reset               持久化数据（节点学习数据等）
```

---

## 工作空间布局

```
crates/
├─ core-config        Friendly YAML / profile 默认值 / 节点 URI 解析 / 迁移
├─ core-runtime       Runtime + GroupSelector + URLTest + 连接池
├─ core-inbound       Mixed (HTTP+SOCKS5) + 权限检测 + 智能端口降级
├─ core-outbound      direct/block/http/socks5/SS-AEAD/Trojan/VLESS + TLS/WS 传输层
├─ core-route         规则引擎 + 内置 preset + L7 协议嗅探 (STUN/DTLS/QUIC/TLS-SNI/HTTP)
├─ core-resolver      多 group DNS + 乐观缓存 + sing-box 兼容 evaluate/respond/predefined/reject + ECS 三层 fallback
├─ core-ruleset       mihomo yaml/txt/list + sing-box JSON + 自研 RRS 二进制 + 双向转换
├─ core-feeds         订阅拉取 (Base64/Clash YAML/SIP008/纯文本) + 缓存 + 周期刷新
├─ core-smart         EWMA + domain_best + negative cooldown + URLTest history
├─ core-store         redb 嵌入式 KV + AsyncWriter 批量异步落盘
├─ core-capture       TUN/TProxy/redirect 平台后端 + Android 5-Tier 降级
├─ core-mesh          Tailscale 协同 + 路由保护
├─ core-observe       tracing / metrics / connections
├─ core-api           /v1 原生 + Clash/Mihomo 兼容 + URLTest delay
└─ proxy-core         CLI 入口

tests-e2e/           端到端：mixed inbound + URLTest
examples/            desktop / daily / router / manual_only / with_feed
scripts/             build-all.ps1 + Cross.toml
docs/                BUILD-PERF.md（编译性能优化指南）
```

---

## 功能矩阵

| 模块 | 关键能力 | 测试 |
|---|---|---|
| Config | profile 默认值、节点 URI 解析（ss/vless/vmess/trojan 等）、route preset/sets/steps、payload 内联 | 12 |
| Runtime | Runtime + GroupSelector(manual/smart/fast/stable/spread/chain) + URLTest 周期测速 | 3 |
| Inbound | Mixed HTTP+SOCKS5 同端口 + 跨平台权限检测 + 端口降级 + Android su 提权 | 5 |
| Outbound | direct/block/http/socks5/SS-AEAD/Trojan/VLESS + TLS+WS 传输层 | 4 |
| Route | preset 编译 + 规则引擎 + L7 嗅探（STUN/DTLS/QUIC/SNI/HTTP）+ proto:webrtc 别名 | 11 |
| Resolver | 乐观缓存 + LRU + Group 三策略 + sing-box 完整动作 + ECS 三层 + redb 持久化 | 37 |
| Ruleset | yaml/txt/list/json 解析 + RRS encode/decode + double-pass 一致性 + matcher 6 种 | 20 |
| Feeds | Base64/Clash/SIP008/Plain 解析 + 过滤重命名 + 缓存回退 | 5 |
| Smart | EWMA + cooldown + 跨重启持久化 | 3 |
| Store | redb 单值/批量/iter/reset + AsyncWriter | 4 |
| Capture | NAT 表 + 路由登记 + Fake-DNS + Android 5-Tier 选择 | 13 |
| API | 原生 + Clash 兼容 + URLTest delay (单/组/全部) | (e2e) |
| **总计** | | **119 / 0 失败** |

---

## 协议支持

### 真实现（与 mihomo / sing-box 互通）

| 协议 | 实现深度 |
|---|---|
| direct / block / http / socks5 | 完整含 TCP/UDP/认证 |
| **Shadowsocks AEAD** | aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 + EVP_BytesToKey + HKDF-SHA1 |
| **Trojan** | TLS（rustls + ALPN + insecure 选项） + 56B SHA-224 + SOCKS5 cmd |
| **VLESS** | UUID + addons + cmd over **TLS / TCP / WebSocket** 三种传输层 |
| TLS 传输层 | rustls + ring + webpki-roots + 可选 insecure + ALPN |
| WebSocket 传输层 | tokio-tungstenite 包装为 AsyncRead/AsyncWrite |

### 占位（明确返回 `Unsupported`，不假装）

vmess / shadowsocksr / shadowsocks 2022 / snell / hysteria2 / tuic / wireguard / ssh / anytls / mieru / sudoku / trusttunnel —— 接口已就位，由 OutboundAdapter trait 统一抽象，后续 PR 逐个填补，绝不静默成功。

---

## DNS 系统 (sing-box 1.14 兼容)

### 5 大动作（与 sing-box 字段一一对应）

| sing-box action | RPKernel | 说明 |
|---|---|---|
| `route` | `Route { server, opts }` | 终止评估 |
| `evaluate` (1.14+) | `Evaluate { server, opts }` | **不终止**，结果保存为 saved_response |
| `respond` (1.14+) | `Respond` | 返回 saved_response |
| `reject` | `Reject(RejectOptions)` | method=default(REFUSED) / drop；30s 50 次自动切 drop |
| `predefined` (1.12+) | `Predefined(PredefinedResponse)` | rcode + answer/ns/extra 文本记录 |

### per-query 选项

`disable_cache` · `disable_optimistic_cache` · `rewrite_ttl` · `client_subnet`

### 三层 ECS fallback

`rule.opts.client_subnet > server.default_client_subnet > resolver.global_client_subnet`

### 友好 DSL（两种风格任选）

```yaml
# 字符串行内（短到一眼看懂）
- "ads.com    -> drop"                        # reject method=drop
- "tracker    -> refuse"                      # REFUSED
- "*.cn       -> direct:mainland"             # 后缀短写
- "=foo.local -> hosts:127.0.0.1"             # 精确 + hosts
- "geosite:cn -> direct:mainland"             # sing-box 别名

# 结构化 YAML（推荐）
- { suffix: ads.com, drop: true }
- { suffix: foo.local, hosts: [127.0.0.1, "::1"] }
- { set: cn, direct: mainland, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }
- { match: any, evaluate: overseas, no_cache: true }
- { match_response: 1.1.1.0/24, respond: true }
- { suffix: nx.local, nxdomain: true }
```

详见 [crates/core-resolver/src/lib.rs](crates/core-resolver/src/lib.rs) 顶部 `_DSL_DOC`。

---

## 规则集系统

### 输入格式

| 格式 | 来源 | 状态 |
|---|---|---|
| YAML payload | mihomo / Clash | ✅ 完整 |
| TXT / LIST | mihomo / Clash | ✅ 完整（含 `+.suffix`、`.suffix`、CIDR、policy 短写法） |
| JSON | sing-box rule-set | ✅ 完整（含 v1/v2 + logical 嵌套） |
| **RRS**（自研二进制） | RPKernel | ✅ CRC32 校验，~45% YAML 体积 |
| MRS / SRS（二进制） | mihomo / sing-box | ⚠️ 嗅探 + 友好提示用工具转文本 |

### RRS 自研格式

```
24B header (magic="RRS\0" + version + flags + created_at + body_len + body_crc32)
+ body 8 段 (DomainExact / Suffix / Keyword / Regex / V4 / V6 / Port / Process)
  紧凑编码：var-len 字符串 + 5B v4 CIDR + 17B v6 CIDR
```

### 双向转换

```bash
proxy-core ruleset convert in.yaml  out.rrs       # YAML → RRS
proxy-core ruleset convert in.rrs   out.yaml      # RRS → YAML
proxy-core ruleset convert in.json  out.rrs       # sing-box JSON → RRS
proxy-core ruleset convert in.rrs   out.json      # RRS → sing-box JSON
proxy-core ruleset convert in.txt   out.rrs --output-format rrs
```

实测 1000 条规则 yaml=27075 → **rrs=12044 (45%)** → json=15524 → rrs=12044（MD5 byte-exact 一致）。

### 高速 matcher

后缀 trie + AHashSet 精确 + Vec 关键字 + RegexSet + 按掩码长度倒序 CIDR + 端口区间 + 进程名集合，10w 条规模 ~100µs 命中。

---

## Android Root 模式（5 层自动降级）

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Tier 1  NftablesFull         nft + ip6 nat + IPv4/v6 TPROXY            │ ← 推荐：完整透明代理
├────────────────────────────────────────────────────────────────────────┤
│ Tier 2  IptablesV4V6Tproxy   iptables + ip6tables + 双栈 TPROXY        │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 3  IptablesV4V6Redirect iptables + ip6tables NAT REDIRECT         │ ← 双栈 TCP；UDP 受限
├────────────────────────────────────────────────────────────────────────┤
│ Tier 4  IptablesV4Only       仅 iptables v4 NAT REDIRECT               │
├────────────────────────────────────────────────────────────────────────┤
│ Tier 5  VpnService           用户态 TUN（无 root / 上述全部失败）       │
└────────────────────────────────────────────────────────────────────────┘
```

`AndroidCapability::detect_capability()` 通过 `su -c` 探测 11 项关键能力（has_root / has_ip6tables / has_nftables / kernel_ipv6_nat / kernel_tproxy_v6 / uid_owner_match / ...），自动选最高可用层；启动钩子 `try_request_root_android()` 失败时透明降级到 VpnService。

---

## 性能与构建

### 编译加速（已写入仓库默认）

| 优化 | 位置 | 效果 |
|---|---|---|
| `incremental + codegen-units=256` (dev) | [Cargo.toml](Cargo.toml) | 单 crate 内并行 |
| `[profile.dev.package."*"] opt-level=1` | 同上 | 依赖也快，运行/编译都受益 |
| `debug="line-tables-only"` + `split-debuginfo` | 同上 | debuginfo -80%，链接 -40% |
| `lto="thin" + codegen-units=16` (release) | 同上 | 替代 fat LTO；性能差 ~1%，构建 -60% |
| `release-fast` profile | 同上 | CI 冒烟用：`lto=off + cgu=256`，比 release 快 4× |
| `rust-lld` (Windows MSVC) | [.cargo/config.toml](.cargo/config.toml) | 链接 -50%~-70% |
| `mold` (Linux x64) | 同上 | 链接 -80% |

实测增量构建：改一行 main.rs 全量 22s → **2s**。详见 [docs/BUILD-PERF.md](docs/BUILD-PERF.md)。

### 多平台构建矩阵

| 目标 | 后端 | Windows 主机能跑 | 备注 |
|---|---|---|---|
| `x86_64-pc-windows-msvc` | cargo | ✅ | MSVC build tools |
| `aarch64-pc-windows-msvc` | cargo | ✅ | MSVC ARM64 |
| `x86_64-unknown-linux-{musl,gnu}` | **cargo-zigbuild** | ✅（无需 Docker） | 推荐 |
| `aarch64-unknown-linux-{musl,gnu}` | cargo-zigbuild | ✅ | |
| `aarch64-linux-android` | **cargo-ndk** + 自动发现 NDK | ✅ | 自动从 `%LOCALAPPDATA%\Android\Sdk\ndk` 找 |
| `*-apple-darwin` | — | ❌ 需 macOS 主机 | 自动 skip |

---

## API

### 原生 `/v1`

```
GET  /v1/status                    版本/运行时间/profile/平台
GET  /v1/traffic                   实时流量
GET  /v1/nodes                     节点列表 + 能力
GET  /v1/groups                    分组 + 当前选择
PATCH /v1/groups/:name             手动切节点（持久化到 redb）
GET  /v1/connections               连接列表
DELETE /v1/connections/:id         关闭连接
GET  /v1/route/check?host=&port=&network=    路由命中调试
GET  /v1/proxies/:name/delay       URLTest 单节点
POST /v1/groups/:name/healthcheck  整组测速
POST /v1/healthcheck               全局测速
GET  /v1/smart/why?host=&group=    解释 Smart 选择
POST /v1/smart/{pin,avoid,reset}   Smart 控制
```

### Clash 兼容

`/proxies` `/proxies/:name` `/proxies/:name/delay` `/group/:name/delay` `/connections` `/configs` `/version` `/traffic` —— 现成 Dashboard 直接可用。

---

## 测试

```bash
cargo test --workspace
# → TOTAL PASS=119 FAIL=0
```

涵盖：单元 + e2e（mixed listener / URLTest / 缓存持久化 / 多协议路由 / 规则集双向 round-trip）。

---

## 路线图

| 阶段 | 状态 | 内容 |
|---|---|---|
| M1 配置 + 普通代理 | ✅ | Friendly YAML / Mixed / direct/block/http/socks5 / route preset |
| M2 协议完整化 | 🟡 部分 | SS AEAD / Trojan / VLESS（TLS+WS） 已 ✅；vmess / hysteria2 / tuic / wireguard / ssh 待 |
| M3 Resolver | ✅ | DoH/DoT/UDP + 乐观缓存 + 多 group + sing-box 完整动作 + ECS 三层 + 持久化 |
| M4 Capture | 🟡 框架 | TUN/TProxy/redirect 后端 + Fake-DNS + Android 5-Tier；packet-loop 待 |
| M5 Smart | ✅ | EWMA + URLTest + cooldown + 持久化 |
| M6 API + 生态 | ✅ | /v1 + Clash 兼容 + RRS 自研二进制 + 规则集双向转换 |
| M7 Tailscale | 🟡 诊断 | mesh.diagnose + Tailnet 自动排除；userspace_proxy 接入待 |
| M8 性能冲刺 | 🟡 部分 | 编译性能完成；运行时 io_uring/GSO 待 |

---

## 许可证

MIT OR Apache-2.0（双协议）。

## 设计文档

完整设计参见 [RP内核设计文档.md](RP内核设计文档.md) 与各 crate 顶部 doc 注释。
