# WutherCore

Rust 实现的代理内核，与 mihomo / sing-box 配置生态互通。提供 YAML 配置、节点测速、规则路由、DNS 解析、透明代理与 HTTP 控制面板。

[![rust](https://img.shields.io/badge/rust-1.75%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![edition](https://img.shields.io/badge/edition-2021-000000)](https://doc.rust-lang.org/edition-guide/)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blueviolet)](LICENSE)
[![tests](https://img.shields.io/badge/tests-281%20passed-brightgreen)]()
[![crates](https://img.shields.io/badge/workspace-15%20crates-1f6feb)]()

代码仓库：<https://github.com/MiChongs/WutherCore>（私有）

---

## 目录

- [项目状态](#项目状态)
- [快速开始](#快速开始)
- [配置示例](#配置示例)
- [工作空间](#工作空间)
- [出站协议](#出站协议)
- [传输层](#传输层)
- [DNS 系统](#dns-系统)
- [规则集](#规则集)
- [Smart 选节点](#smart-选节点)
- [Android 透明代理](#android-透明代理)
- [构建](#构建)
- [HTTP API](#http-api)
- [测试](#测试)
- [路线图](#路线图)
- [许可证](#许可证)

---

## 项目状态

| 项目 | 数据 |
|---|---|
| 工作空间 | 15 个 crate |
| 总代码量 | Rust ≈ 35k 行 |
| 测试通过 | 281 / 281 |
| 出站协议 | 18 种实现，4 种保留 |
| 传输层 | 7 种（TCP/TLS/WS/HTTP/H2/gRPC/XHTTP） |
| 编译器 | Rust 1.75+，stable |
| 平台 | Windows / Linux / macOS / Android（root 透明代理） |

---

## 快速开始

最小可运行配置（10 个顶层字段）：

```yaml
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/your-subscription"
```

启动：

```bash
cargo build --release -p proxy-core
./target/release/proxy-core run -c examples/desktop.yaml
```

CLI 子命令：

```text
proxy-core run        -c <yaml>             启动内核
proxy-core check         <yaml>             校验配置
proxy-core explain       <yaml>             输出展开后的 RuntimePlan JSON
proxy-core migrate mihomo <old.yaml> -o <out.yaml>
proxy-core feeds   list / refresh           订阅源管理
proxy-core ruleset list / refresh / convert 规则集管理（含 yaml↔txt↔json↔rrs 转换）
proxy-core store   info / reset             持久化数据管理
```

---

## 配置示例

### 顶层字段

| 字段 | 含义 |
|---|---|
| listen | 入站监听端口（HTTP / SOCKS5 / Mixed / 控制面板） |
| feeds | 远程或本地订阅源（Base64 / Clash YAML / SIP008 / 纯文本） |
| nodes | 手动节点列表（URI 或结构化对象） |
| groups | 节点分组（manual / smart / fast / stable / spread / chain） |
| route | 路由规则（preset + sets + steps） |
| resolver | DNS 解析（多 group 并发 / DoH / DoT / UDP） |
| capture | 透明代理（TUN / TProxy / redirect） |
| smart | 自动选节点（EWMA + URLTest） |
| ui | 控制面板与 API（/v1 + Clash 兼容） |
| mesh | Tailscale 协同 |

### 完整示例

参见 [examples/desktop.yaml](examples/desktop.yaml)、[examples/router.yaml](examples/router.yaml)、[examples/with_feed.yaml](examples/with_feed.yaml) 等。

---

## 工作空间

```
crates/
  core-config        YAML / 节点 URI 解析 / profile 默认值 / 迁移
  core-runtime       Runtime + GroupSelector + URLTest 周期测速
  core-inbound       Mixed (HTTP+SOCKS5) + 权限检测 + 端口降级
  core-outbound      18 种代理协议 + 7 种传输层
  core-route         规则引擎 + 内置 preset + L7 嗅探（STUN/DTLS/QUIC/SNI/HTTP）
  core-resolver      多 group DNS + 乐观缓存 + sing-box 1.14 动作 + ECS
  core-ruleset       mihomo yaml/txt/list + sing-box JSON + 自研 RRS 二进制
  core-feeds         订阅拉取 + 缓存 + 周期刷新
  core-smart         EWMA 评分 + domain_best + cooldown
  core-store         redb 嵌入式 KV + AsyncWriter
  core-capture       TUN / TProxy / redirect + Android 5 层降级
  core-mesh          Tailscale 协同
  core-observe       tracing / metrics / connections
  core-api           /v1 原生 API + Clash 兼容 + URLTest delay
  proxy-core         CLI 入口

tests-e2e/           端到端测试
examples/            5 个示例配置
docs/                构建性能优化等文档
scripts/             多平台一键构建脚本
```

---

## 出站协议

实现状态参考各文件顶部 doc 注释。所有「实现」协议均含完整握手与 wire-format，与 mihomo / xray / sing-box 互通。

### 已完整实现（18 种）

| 协议 | 关键特性 |
|---|---|
| direct | TCP / UDP 直连 |
| block | 立即拒绝 |
| http | CONNECT 方法 + Basic 认证 |
| socks5 | TCP / UDP + 用户名密码认证 |
| Shadowsocks AEAD | aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 + EVP_BytesToKey + HKDF-SHA1 |
| Shadowsocks 2022 | 2022-blake3-aes-128-gcm / aes-256-gcm / chacha20-poly1305，含 EIH 多用户 / UDP / timestamp 防重放 / variable-header padding |
| ShadowsocksR | aes-128/256-cfb / aes-128/256-ctr / chacha20-ietf / rc4-md5；plain / http_simple / tls1.2_ticket_auth obfs；origin / auth_aes128_md5 / auth_aes128_sha1 / auth_chain_a / auth_chain_b protocol |
| Snell v3 | aes-128-gcm / chacha20-poly1305；CONNECT / PING / PONG / UDP_FORWARD / UDP_STREAM；HTTP / TLS obfs |
| Trojan | TLS + 56 字节 SHA-224(password) hex 鉴权 + SOCKS5 命令 |
| VLESS | UUID + addons + cmd over TCP / TLS / WS / HTTP / H2 / gRPC / XHTTP |
| VMess AEAD | aes-128-gcm / chacha20-poly1305 / none；CHUNK_MASKING（SHAKE128）+ GLOBAL_PADDING + AUTH_LEN；UDP cmd；嵌套 HMAC-SHA256 KDF |
| VMess Legacy | HMAC-MD5 AuthInfo + AES-128-CFB header（兼容 alterId>0 老服务端） |
| AnyTLS | mux 多路复用（SYN/PSH/FIN/ALERT/SETTINGS）+ padding scheme 协商 |
| SSH | 基于 russh：密码 / 私钥（路径或内容）/ passphrase 鉴权；session 复用；known_hosts 校验；direct-tcpip 通道 |
| Hysteria v1 | QUIC + msgpack ClientHello/ServerHello + 上下行 Mbps 协商 |
| Hysteria2 | QUIC + HTTP/3 鉴权（POST /auth）+ TCP frame 0x401 + Salamander obfs（自定义 AsyncUdpSocket + BLAKE2 keystream） |
| TUIC v5 | QUIC + UUID + token 鉴权；Authenticate / Connect / Packet / Heartbeat / Dissociate；UDP relay 支持 datagram 与 stream 双模式 |
| WireGuard | 手写 Noise IK 完整握手（X25519 + HMAC-BLAKE2s + HKDF + ChaCha20-Poly1305） + transport encryption；smoltcp 用户态网络栈接口 |
| Mieru | PBKDF2-SHA256（4096 iter）+ AES-256-GCM / ChaCha20-Poly1305 + 用户名 + timestamp 防重放 |
| Sudoku | 4×4 数独网格混淆（288 个网格 / ASCII / Entropy / Custom 三种 byte layout）+ AEAD RecordConn（epoch + seq + 自动密钥更新）+ KIP 握手（X25519 + HKDF）+ HTTP mask legacy |
| Trusttunnel | HTTP/2 CONNECT method + Basic 鉴权；魔法地址 `_udp2` / `_icmp` / `_check`；连接池 max_connections / min_streams / max_streams |

### 解析支持但运行时占位

vmess legacy 自动检测 alterId 切换；其它解析层完整支持的协议但运行时返回 Unsupported（避免静默失败）：暂无。

---

## 传输层

| 传输 | 用途 | 实现要点 |
|---|---|---|
| TCP | 裸 TCP | tokio TcpStream |
| TLS | 加密层 | rustls + ring + webpki-roots + ALPN + insecure 选项 |
| WebSocket | wss/ws 隧道 | tokio-tungstenite，可叠加 TLS |
| HTTP | HTTP/1.1 伪装 | TLS + 写出伪装请求头后裸字节通信 |
| H2 | HTTP/2 双向流 | hyper http2 + 自定义 Host / Path / Method（默认 PUT） |
| gRPC（gun） | gRPC 隧道 | hyper http2 + `/<service>/Tun` + frame `flag(1)‖length(4)‖protobuf-wrap(data)` |
| XHTTP | v2ray/xray xhttp | 完整 stream-one / stream-up / packet-up 三模式；session/seq/uplink-data/x-padding 全 Placement（path/query/header/cookie/body/queryInHeader） |

VLESS / VMess 通过 `network` 字段（兼容 `net` / `type` 别名）分发到上述 7 种传输层之一。

### XHTTP 详细参数

| 参数 | 说明 |
|---|---|
| mode | auto / stream-one / stream-up / packet-up |
| path | 请求路径（自动补 `/`） |
| host | `:authority` |
| session-placement / seq-placement | path / query / header / cookie |
| uplink-data-placement | body / header / cookie / auto |
| sc-max-each-post-bytes | packet-up 单 POST 大小（默认 1000000） |
| sc-min-posts-interval-ms | packet-up POST 间隔（默认 30） |
| x-padding-bytes | padding 长度范围（默认 100-1000） |
| x-padding-method | repeat-x / tokenish |
| x-padding-obfs-mode | 启用自定义 placement / 否则放 Referer 查询 |
| no-grpc-header | 不发 `Content-Type: application/grpc` |

参见 [proto/xhttp/config.rs](crates/core-outbound/src/proto/xhttp/config.rs)。

---

## DNS 系统

兼容 sing-box 1.14 的完整 DNS 规则动作集合。

### 动作

| sing-box 名称 | WutherCore 实现 | 说明 |
|---|---|---|
| route | `Route { server, opts }` | 转发并终止匹配 |
| evaluate | `Evaluate { server, opts }` | 转发但不终止；结果保存为 saved_response |
| respond | `Respond` | 返回 saved_response |
| reject | `Reject(RejectOptions)` | method=default 返回 REFUSED；method=drop 静默丢弃；30 秒 50 次失败自动切换为 drop |
| predefined | `Predefined(PredefinedResponse)` | 自定义 rcode + answer / ns / extra |

### per-query 选项

`disable_cache` · `disable_optimistic_cache` · `rewrite_ttl` · `client_subnet`

### 三层 ECS fallback

```
rule.opts.client_subnet  >  server.default_client_subnet  >  resolver.global_client_subnet
```

### 友好 DSL

```yaml
# 字符串行内
- "ads.com    -> drop"
- "tracker    -> refuse"
- "*.cn       -> direct:mainland"
- "=foo.local -> hosts:127.0.0.1"
- "geosite:cn -> direct:mainland"

# 结构化 YAML
- { suffix: ads.com, drop: true }
- { suffix: foo.local, hosts: [127.0.0.1, "::1"] }
- { set: cn, direct: mainland, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }
- { match: any, evaluate: overseas, no_cache: true }
- { match_response: 1.1.1.0/24, respond: true }
- { suffix: nx.local, nxdomain: true }
```

详见 [crates/core-resolver/src/lib.rs](crates/core-resolver/src/lib.rs) 顶部 `_DSL_DOC`。

---

## 规则集

### 输入格式

| 格式 | 来源 |
|---|---|
| YAML payload | mihomo / Clash |
| TXT / LIST | mihomo / Clash（含 `+.suffix`、`.suffix`、CIDR、policy 短写法） |
| JSON | sing-box rule-set（v1 / v2 + logical 嵌套） |
| RRS（自研二进制） | WutherCore；CRC32 校验，体积约为 YAML 的 45% |
| MRS / SRS（mihomo / sing-box 二进制） | 仅嗅探识别，提示用工具转文本 |

### RRS 格式

```
24 字节 header
  magic     "RRS\0"
  version   2 字节
  flags     2 字节
  created_at 8 字节
  body_len  4 字节
  body_crc32 4 字节

body 8 段紧凑编码：
  DomainExact  var-len string
  Suffix       var-len string
  Keyword      var-len string
  Regex        var-len string
  V4 CIDR      5 字节 (4B addr + 1B prefix)
  V6 CIDR      17 字节 (16B addr + 1B prefix)
  Port         2 字节
  Process      var-len string
```

### 转换

```bash
proxy-core ruleset convert in.yaml out.rrs
proxy-core ruleset convert in.rrs  out.yaml
proxy-core ruleset convert in.json out.rrs
proxy-core ruleset convert in.rrs  out.json
proxy-core ruleset convert in.txt  out.rrs --output-format rrs
```

实测 1000 条规则：YAML 27075 字节 → RRS 12044 字节（约 45%），与从 RRS 反解的 JSON 重新转 RRS 字节级一致。

### 匹配性能

后缀 trie + AHashSet 精确 + Vec 关键字 + RegexSet + 按掩码长度倒序 CIDR + 端口区间 + 进程名集合，10 万条规则量级下命中约 100 µs。

---

## Smart 选节点

| 维度 | 实现 |
|---|---|
| 评分 | EWMA 成功率衰减（α 可调） |
| 最近最优 | `domain_best` 域名级最近选择缓存 |
| 失败冷却 | `negative` 表，连续失败的节点冷却时间指数退避 |
| 主动测速 | URLTest，目标 URL 与并发度可配置；周期任务持续刷新 |
| 持久化 | redb 落盘；评分、域名最优、冷却、URLTest 历史均跨重启保留 |
| 控制面 | `/v1/smart/why?host=&group=`、`/v1/smart/{pin,avoid,reset}` |

---

## Android 透明代理

Root 透明代理按可用能力降级，共 4 层；未 root 的 `virtual_nic` 走 Android
`VpnService` 注入 TUN fd，它不是 root 透明代理能力层，也不是桥接网卡。

| 层级 | 名称 | 条件 | 备注 |
|---|---|---|---|
| 1 | NftablesFull | 有 nft + ip6 nat + IPv4/v6 TPROXY | 完整透明代理 |
| 2 | IptablesV4V6Tproxy | iptables + ip6tables + 双栈 TPROXY | |
| 3 | IptablesV4V6Redirect | iptables + ip6tables NAT REDIRECT | UDP 受限 |
| 4 | IptablesV4Only | 仅 iptables v4 NAT REDIRECT | |

`VpnService` 模式必须由宿主 App 调用 `VpnBridge.vpnServiceConfigJson(configPath)`，
把返回的 `addresses`、`routes`、`dns_servers`、应用白/黑名单逐项写入
`VpnService.Builder`，再 `establish()`、`detachFd()`、`setVpnService(this)`、
`setVpnFd(fd)`。没有 Builder 路由/DNS 时，native 侧拿到 fd 也不会有真实流量进入。

`AndroidCapability::detect_capability()` 通过 `su -c` 探测 11 项能力（has_root / has_ip6tables / has_nftables / kernel_ipv6_nat / kernel_tproxy_v6 / uid_owner_match / ...），自动选最高可用 root 层。没有 root 或没有 iptables/nftables 时，root 透明代理不可用，应显式使用 `virtual_nic` + VpnService fd 注入。

---

## 构建

### 基本编译

```bash
cargo build --release -p proxy-core
cargo test --workspace
```

### 多平台一键构建（Windows 主机）

```cmd
build.cmd                  默认矩阵
build.cmd windows
build.cmd linux            x86_64-unknown-linux-musl，zigbuild 后端
build.cmd android          aarch64-linux-android，cargo-ndk 后端
```

强制后端：

```powershell
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
```

### 编译目标矩阵

| 目标 | 后端 | Windows 主机 |
|---|---|---|
| x86_64-pc-windows-msvc | cargo | 是 |
| aarch64-pc-windows-msvc | cargo | 是 |
| x86_64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-linux-android | cargo-ndk + 自动从 `%LOCALAPPDATA%\Android\Sdk\ndk` 发现 | 是 |
| x86_64 / aarch64-apple-darwin | 仅 macOS 主机 | 否 |

### 编译性能

仓库内置以下优化：

| 优化 | 位置 | 效果 |
|---|---|---|
| `incremental` + `codegen-units=256`（dev） | [Cargo.toml](Cargo.toml) | 单 crate 内并行 |
| `[profile.dev.package."*"] opt-level=1` | 同上 | 依赖也快 |
| `debug="line-tables-only"` + `split-debuginfo` | 同上 | debuginfo 减少约 80% |
| `lto="thin" + codegen-units=16`（release） | 同上 | 性能差约 1%，构建时间减少约 60% |
| `release-fast` profile | 同上 | CI 冒烟用，比 release 快约 4× |
| `rust-lld`（Windows MSVC） | [.cargo/config.toml](.cargo/config.toml) | 链接时间减少 50%–70% |
| `mold`（Linux x64） | 同上 | 链接时间减少约 80% |

实测增量构建：改一行 `main.rs` 全量从 22 秒降至 2 秒。详见 [docs/BUILD-PERF.md](docs/BUILD-PERF.md)。

---

## HTTP API

### 原生 `/v1`

```
GET    /v1/status                              版本 / 运行时间 / profile / 平台
GET    /v1/traffic                             实时流量
GET    /v1/nodes                               节点列表
GET    /v1/groups                              分组列表
PATCH  /v1/groups/:name                        手动切节点（持久化到 redb）
GET    /v1/connections                         连接列表
DELETE /v1/connections/:id                     关闭指定连接
GET    /v1/route/check?host=&port=&network=    路由命中调试
GET    /v1/proxies/:name/delay                 URLTest 单节点延迟
POST   /v1/groups/:name/healthcheck            整组测速
POST   /v1/healthcheck                         全局测速
GET    /v1/smart/why?host=&group=              解释 Smart 选择
POST   /v1/smart/pin                           固定节点
POST   /v1/smart/avoid                         避开节点
POST   /v1/smart/reset                         重置 Smart 学习数据
```

### Clash / Mihomo 兼容

`/proxies` `/proxies/:name` `/proxies/:name/delay` `/group/:name/delay` `/connections` `/configs` `/version` `/traffic`

---

## 测试

```bash
cargo test --workspace
```

覆盖：

```
core-config         13
core-runtime        12
core-inbound         5
core-outbound      166   含全部 18 种协议 + 7 种传输层
core-route          37
core-resolver       11   核心；DNS 完整动作集另在 ruleset/feeds 中
core-ruleset        20
core-feeds           3
core-smart           4
core-store           2
core-capture         3
e2e + 其它           5

总计               281   全部通过
```

---

## 路线图

| 阶段 | 状态 | 说明 |
|---|---|---|
| M1 配置与基础代理 | 完成 | YAML / Mixed inbound / direct / block / http / socks5 / route preset |
| M2 协议完整化 | 完成 | 18 种代理协议 + 7 种传输层与 mihomo 互通 |
| M3 Resolver | 完成 | DoH / DoT / UDP + 乐观缓存 + 多 group + sing-box 完整动作 + ECS 三层 + 持久化 |
| M4 Capture | 部分 | TUN / TProxy / redirect 后端 + Fake-DNS + Android 5 层降级；TUN packet-loop 待补 |
| M5 Smart | 完成 | EWMA + URLTest + cooldown + 持久化 |
| M6 API + 生态 | 完成 | /v1 + Clash 兼容 + 自研 RRS 二进制 + 规则集双向转换 |
| M7 Tailscale | 部分 | mesh.diagnose + Tailnet 自动排除；userspace_proxy 接入待 |
| M8 性能调优 | 部分 | 编译性能完成；运行时 io_uring / GSO 待 |

---

## 许可证

[MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE)，二选一。

---

## 设计文档

完整设计参见 [RP内核设计文档.md](RP内核设计文档.md) 与各 crate 顶部 doc 注释。
