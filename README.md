# WutherCore

Rust 实现的代理内核 —— Friendly YAML 配置、节点学习与 URLTest 测速、L4/L7 路由、完整 DNS 系统、透明代理（TUN / TProxy / Redirect / Android VpnService）、HTTP 控制面板。

[![rust](https://img.shields.io/badge/rust-1.85%2B-CE422B?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![edition](https://img.shields.io/badge/edition-2024-000000)](https://doc.rust-lang.org/edition-guide/)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blueviolet)](LICENSE)
[![crates](https://img.shields.io/badge/workspace-17%20crates-1f6feb)]()

---

## 目录

- [特性概览](#特性概览)
- [快速开始](#快速开始)
- [CLI 子命令](#cli-子命令)
- [配置概览](#配置概览)
- [出站协议](#出站协议)
- [传输层](#传输层)
- [路由（route）](#路由route)
  - [DSL 字符串行](#dsl-字符串行)
  - [结构化对象行](#结构化对象行)
  - [matcher 类型](#matcher-类型)
  - [And / Or 复合](#and--or-复合)
  - [route preset](#route-preset)
  - [外部规则集（route.sets）](#外部规则集routesets)
- [DNS（resolver）](#dnsresolver)
  - [字段总览](#字段总览)
  - [DNS DSL](#dns-dsl)
  - [Group 调度与三层 fallback](#group-调度与三层-fallback)
  - [Fake-IP](#fake-ip)
  - [Hosts 与 IPv6 开关](#hosts-与-ipv6-开关)
- [节点分组（groups）](#节点分组groups)
- [Smart 选节点](#smart-选节点)
- [透明代理（capture）](#透明代理capture)
  - [method × stack](#method--stack)
  - [Linux TProxy / Redirect](#linux-tproxy--redirect)
  - [Android VpnService](#android-vpnservice)
- [入站与控制面板](#入站与控制面板)
- [工作空间](#工作空间)
- [构建](#构建)
- [HTTP API](#http-api)
- [测试](#测试)
- [许可证](#许可证)

---

## 特性概览

| 项目 | 说明 |
|---|---|
| 工作空间 | 17 个 crate（16 个 core 库 + 1 个 CLI） |
| 出站协议 | 22 种实现，全部含完整握手与线格式（无占位） |
| 传输层 | 7 种：TCP / TLS / WebSocket / HTTP / H2 / gRPC / XHTTP |
| 路由 | L4（IP/端口/网络）+ L7（域名/进程/协议嗅探）+ 5 个 preset + 外部规则集 |
| DNS | 多 group 并发、乐观缓存、DoH/DoT/UDP/TCP/DoQ-就绪、ECS 三层、完整动作集 |
| 透明代理 | TUN / TPROXY / REDIRECT / Android VpnService；4 种方法 × 5 种栈 |
| 选节点 | EWMA + URLTest + domain_best 域名级最近最优 + 5 种策略 |
| 控制面 | `/v1/*` 原生 API + Clash 兼容路径；redb 持久化 |
| 平台 | Windows · Linux · macOS · Android（root 与 VpnService 双路径） |

---

## 快速开始

最小可运行配置（10 行）：

```yaml
version: 1
profile: desktop
listen:
  local: "127.0.0.1:7890"
feeds:
  airport: "https://example.com/your-subscription"
route:
  preset: cn_smart
```

启动：

```bash
cargo build --release -p proxy-core
./target/release/proxy-core run -c config.yaml
```

---

## CLI 子命令

```text
proxy-core run        -c <yaml>             启动内核（前台）
proxy-core check         <yaml>             仅校验配置，不启动
proxy-core explain       <yaml>             输出展开后的 RuntimePlan（JSON，便于排错）
proxy-core migrate clash  <old.yaml> -o <out.yaml>   旧 Clash 风格配置迁移到 Friendly YAML
proxy-core feeds   list / refresh           订阅源管理
proxy-core ruleset list / refresh / convert 规则集管理与格式互转
proxy-core store   info / reset             redb 持久化数据查看与清空
```

`ruleset convert` 支持 `yaml ↔ txt ↔ json ↔ rrs` 互转，输入/输出格式按扩展名自动识别，可被 `--input-format` / `--output-format` 覆盖。

---

## 配置概览

顶层字段：

| 字段 | 必填 | 含义 |
|---|---|---|
| `version` | 是 | 配置版本号（当前 `1`） |
| `profile` | 是 | `desktop` / `router` / `mobile` 三种内置 profile，决定默认值 |
| `listen` | 否 | Mixed 入站 / 控制面板监听地址 + 鉴权 |
| `feeds` | 否 | 远程或本地订阅源（Base64 / Clash YAML / SIP008 / 纯文本） |
| `nodes` | 否 | 手动节点列表（URI 或结构化对象） |
| `groups` | 否 | 节点分组定义；缺省时由 profile 给出兜底 |
| `route` | 否 | 路由规则（preset + sets + steps） |
| `resolver` | 否 | DNS 解析器配置 |
| `capture` | 否 | 透明代理（TUN / TProxy / Redirect） |
| `smart` | 否 | 自动选节点参数（goal / sticky / EWMA） |
| `ui` | 否 | 控制面板 + API 开关 |
| `mesh` | 否 | Tailscale 协同（Tailnet 自动排除等） |
| `log` | 否 | 日志级别 / 输出 / 连接表周期摘要 |

完整示例：

- [examples/desktop.yaml](examples/desktop.yaml) —— 桌面最简（订阅 + cn_smart 路由）
- [examples/router.yaml](examples/router.yaml) —— 路由器（virtual_nic + cn_smart + Tailscale 排除）
- [examples/with_feed.yaml](examples/with_feed.yaml) —— 订阅 + 节点 keep/drop/rename
- [examples/daily.yaml](examples/daily.yaml) —— 自定义 route.steps 全量演示
- [examples/manual_only.yaml](examples/manual_only.yaml) —— 仅手动节点
- [examples/android.yaml](examples/android.yaml) —— Android VpnService 完整模板

---

## 出站协议

22 种实现，全部含完整握手与线格式，与主流客户端互通。

### 核心 4 种

| 协议 | 关键特性 |
|---|---|
| direct | TCP / UDP 直连；按出站接口 / fwmark 绑定 |
| block | 立即拒绝；可选择 close / reset 行为 |
| http | CONNECT 方法 + Basic 鉴权 |
| socks5 | TCP / UDP + 用户名密码鉴权 |

### Shadowsocks 系

| 协议 | 关键特性 |
|---|---|
| Shadowsocks AEAD | aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305 + EVP_BytesToKey + HKDF-SHA1 |
| Shadowsocks 2022 | `2022-blake3-{aes-128-gcm, aes-256-gcm, chacha20-poly1305}`；EIH 多用户 / UDP / timestamp 防重放 / variable-header padding |
| ShadowsocksR | aes-128/256-cfb / aes-128/256-ctr / chacha20-ietf / rc4-md5；plain / http_simple / tls1.2_ticket_auth obfs；origin / auth_aes128_md5 / auth_aes128_sha1 / auth_chain_a / auth_chain_b protocol |
| Snell v3 | aes-128-gcm / chacha20-poly1305；CONNECT / PING / PONG / UDP_FORWARD / UDP_STREAM；HTTP / TLS obfs |

### V 系

| 协议 | 关键特性 |
|---|---|
| Trojan | TLS + 56 字节 SHA-224(password) hex 鉴权 + SOCKS5 命令 |
| VLESS | UUID + addons + cmd over TCP / TLS / WS / HTTP / H2 / gRPC / XHTTP |
| VMess AEAD | aes-128-gcm / chacha20-poly1305 / none；CHUNK_MASKING（SHAKE128）+ GLOBAL_PADDING + AUTH_LEN；UDP cmd；嵌套 HMAC-SHA256 KDF |
| VMess Legacy | HMAC-MD5 AuthInfo + AES-128-CFB header（兼容 alterId>0 老服务端） |
| AnyTLS | mux 多路复用（SYN/PSH/FIN/ALERT/SETTINGS）+ padding scheme 协商 |

### QUIC 系

| 协议 | 关键特性 |
|---|---|
| Hysteria v1 | QUIC + msgpack ClientHello/ServerHello + 上下行 Mbps 协商 |
| Hysteria2 | QUIC + HTTP/3 鉴权（POST /auth）+ TCP frame 0x401 + Salamander obfs（自定义 `AsyncUdpSocket` + BLAKE2 keystream） |
| TUIC v5 | QUIC + UUID + token 鉴权；Authenticate / Connect / Packet / Heartbeat / Dissociate；UDP relay 支持 datagram 与 stream 双模式 |

### 其它

| 协议 | 关键特性 |
|---|---|
| WireGuard | 手写 Noise IK 完整握手（X25519 + HMAC-BLAKE2s + HKDF + ChaCha20-Poly1305）+ transport encryption；smoltcp 用户态网络栈 |
| SSH | 基于 russh：密码 / 私钥（路径或内容）/ passphrase 鉴权；session 复用；known_hosts 校验；direct-tcpip 通道 |
| Mieru | PBKDF2-SHA256（4096 iter）+ AES-256-GCM / ChaCha20-Poly1305 + 用户名 + timestamp 防重放 |
| Sudoku | 4×4 数独网格混淆（288 个网格 / ASCII / Entropy / Custom 三种 byte layout）+ AEAD RecordConn（epoch + seq + 自动密钥更新）+ KIP 握手（X25519 + HKDF）+ HTTP mask legacy |
| Trusttunnel | HTTP/2 CONNECT method + Basic 鉴权；魔法地址 `_udp2` / `_icmp` / `_check`；连接池 max_connections / min_streams / max_streams |

---

## 传输层

VLESS / VMess 通过 `network` 字段（兼容别名 `net` / `type`）分发到下列任意传输：

| 传输 | 用途 | 实现要点 |
|---|---|---|
| TCP | 裸 TCP | tokio TcpStream |
| TLS | 加密层 | rustls + ring + webpki-roots + ALPN + skip-cert-verify |
| WebSocket | wss / ws 隧道 | tokio-tungstenite，可叠加 TLS |
| HTTP | HTTP/1.1 伪装 | TLS + 写出伪装请求头后裸字节通信 |
| H2 | HTTP/2 双向流 | hyper http2 + 自定义 Host / Path / Method（默认 PUT） |
| gRPC（gun） | gRPC 隧道 | hyper http2 + `/<service>/Tun` + frame `flag(1)‖length(4)‖protobuf-wrap(data)` |
| XHTTP | xhttp 三模式 | stream-one / stream-up / packet-up；session/seq/uplink-data/x-padding 全 placement |

### XHTTP 详细参数

| 参数 | 说明 |
|---|---|
| `mode` | `auto` / `stream-one` / `stream-up` / `packet-up` |
| `path` | 请求路径（自动补 `/`） |
| `host` | `:authority` |
| `session-placement` / `seq-placement` | `path` / `query` / `header` / `cookie` |
| `uplink-data-placement` | `body` / `header` / `cookie` / `auto` |
| `sc-max-each-post-bytes` | packet-up 单 POST 大小（默认 1000000） |
| `sc-min-posts-interval-ms` | packet-up POST 间隔（默认 30） |
| `x-padding-bytes` | padding 长度范围（默认 100–1000） |
| `x-padding-method` | `repeat-x` / `tokenish` |
| `x-padding-obfs-mode` | 启用自定义 placement / 否则放 Referer 查询 |
| `no-grpc-header` | 不发 `Content-Type: application/grpc` |

参见 [proto/xhttp/config.rs](crates/core-outbound/src/proto/xhttp/config.rs)。

---

## 路由（route）

```yaml
route:
  preset: custom            # cn_smart | global | direct | privacy | custom
  final: proxy              # preset=custom 时必填，未命中所有 step 时使用
  steps:
    - "..."                 # 字符串行（兼容 Clash 简写）
    - { ... }               # 结构化对象行（强类型 key）
  sets:
    geoip-cn:
      type: ipcidr
      url: "https://example.com/geoip-cn.mrs"
      every: 24h
```

### DSL 字符串行

```yaml
route:
  preset: custom
  final: proxy
  steps:
    - "*.cn          -> direct"            # 后缀简写（前导 *.）
    - "geosite:cn    -> direct"            # 内置/外部规则集前缀
    - "geoip:cn      -> direct"
    - "process:dnf   -> direct"            # 进程名匹配
    - "192.168.0.0/16 -> direct"           # CIDR
    - "443           -> proxy"             # 端口（int 形式）
    - "tcp           -> proxy"             # 网络类型
    - "stun          -> proxy"             # L7 嗅探协议（stun/dtls/quic/sni/http）
    - "any           -> proxy"             # 通配
```

### 结构化对象行

每个对象**必须**有恰好一个 matcher 字段 + 一个 outbound 字段。

```yaml
route:
  preset: custom
  final: proxy
  steps:
    - { domain:  "youtube.com",  outbound: streaming }
    - { suffix:  ".cn",          outbound: direct    }
    - { keyword: "ad",           outbound: block     }
    - { ip:      "8.8.8.8",      outbound: proxy     }
    - { ip:      "10.0.0.0/8",   outbound: direct    }
    - { port:    "443",          outbound: proxy     }
    - { port:    "1024-65535",   outbound: proxy     }
    - { process: "discord.exe",  outbound: proxy     }
    - { set:     "geoip-cn",     outbound: direct    }
    - { network: "udp",          outbound: proxy     }
    - { proto:   "quic",         outbound: proxy     }
```

`match: any` 是兜底通配（与 final 等价但更显式）。

### matcher 类型

| matcher | 含义 | 示例 |
|---|---|---|
| `domain` | 精确域名 | `youtube.com` |
| `suffix` | 后缀（含点） | `.cn`、`.googleapis.com` |
| `keyword` | 任意位置子串 | `cdn`、`ad` |
| `ip` | 单个 IP 或 CIDR | `8.8.8.8`、`10.0.0.0/8`、`fe80::/10` |
| `port` | 端口或区间 | `443`、`1024-65535` |
| `process` | 进程名（启用 `find-process-mode`） | `chrome.exe` |
| `set` | 引用 `route.sets` 名 | `geoip-cn`、`category-ads` |
| `network` | `tcp` / `udp` | `udp` |
| `proto` | L7 嗅探协议 | `quic`、`stun`、`sni`、`dtls`、`http` |
| `home` / `cn` / `ads` | 内置语义类别 | 等价于 `set: home` 等 |

### And / Or 复合

```yaml
- and:
    - suffix: .cn
    - port: 443
  outbound: direct

- or:
    - keyword: ad
    - keyword: tracker
  outbound: block

- and:
    - suffix: .corp.example.com
    - or:
        - ip: 10.0.0.0/8
        - ip: 172.16.0.0/12
  outbound: home_lan
```

### route preset

| preset | 行为 |
|---|---|
| `cn_smart` | 中国大陆域名 + 内网 → direct；其余 → final（默认 proxy） |
| `global`   | 全部 → final（默认 proxy）；本地直连保留 |
| `direct`   | 全部 → direct |
| `privacy`  | 广告/追踪域 → block；DNS 强制走加密上游；其余 → final |
| `custom`   | 完全由 `route.final` + `route.steps` 决定 |

`preset != custom` 时若另填 `steps`，preset 作为兜底层被覆盖：自定义 step 优先匹配，未命中再走 preset。

### 外部规则集（route.sets）

```yaml
route:
  preset: custom
  final: proxy
  steps:
    - { set: geoip-cn, outbound: direct }
    - { set: ads,      outbound: block  }
    - { set: home_lan, outbound: home   }
  sets:
    geoip-cn:
      type: ipcidr
      url:  "https://example.com/geoip-cn.mrs"
      every: 24h
    ads:
      type: domain
      url:  "https://example.com/ads.txt"
      every: 12h
    home_lan:
      type: ipcidr
      payload:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        - fc00::/7
```

支持的 `type`：`domain` / `ipcidr` / `classical` / `mixed`。  
支持的 format（自动嗅探，可显式指定）：

| 格式 | 说明 |
|---|---|
| `yaml` | 广泛使用的 YAML payload（domain / ipcidr / classical） |
| `txt` / `list` | 纯文本（含 `+.suffix`、`.suffix`、CIDR、policy 短写法） |
| `json` | 主流 JSON rule-set（v1 / v2 + logical 嵌套） |
| `mrs` / `srs` | 主流二进制规则集（嗅探识别，提示用 `ruleset convert` 转文本） |
| `rrs` | 自研二进制（CRC32 校验，体积约为 YAML 的 45%） |

#### RRS 格式

```
24 字节 header
  magic       "RRS\0"
  version     2 字节
  flags       2 字节
  created_at  8 字节
  body_len    4 字节
  body_crc32  4 字节

body 8 段紧凑编码：
  DomainExact  var-len string
  Suffix       var-len string
  Keyword      var-len string
  Regex        var-len string
  V4 CIDR      5  字节 (4B addr  + 1B prefix)
  V6 CIDR      17 字节 (16B addr + 1B prefix)
  Port         2  字节
  Process      var-len string
```

转换：

```bash
proxy-core ruleset convert in.yaml  out.rrs
proxy-core ruleset convert in.json  out.rrs
proxy-core ruleset convert in.rrs   out.yaml
proxy-core ruleset convert in.txt   out.rrs --output-format rrs
```

#### 匹配性能

后缀 trie + AHashSet 精确 + Vec 关键字 + RegexSet + 按掩码长度倒序 CIDR + 端口区间 + 进程名集合，10 万条规则量级下命中约 100 µs。

---

## DNS（resolver）

```yaml
resolver:
  enable: true
  ipv6: true                          # 全局 AAAA 开关
  ipv6-timeout: 100ms                 # AAAA 超时不阻塞 A
  enhanced-mode: fake-ip              # off | redir-host | fake-ip
  fake-ip-range: "198.18.0.0/16"
  fake-ip-filter:
    - "+.lan"
    - "+.local"
    - "stun.*.*"
  use-hosts: true
  use-system-hosts: true
  hosts:
    "router.local": "192.168.1.1"
    "ad-server":    "0.0.0.0"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - "https://dns.google/dns-query"
    - "tls://1.1.1.1"
    - "udp://223.5.5.5:53"
  fallback:
    - "https://1.1.1.1/dns-query"
    - "tls://8.8.8.8"
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite: [gfw]
    ipcidr:  [240.0.0.0/4]
    domain:  ["+.google.com"]
  nameserver-policy:
    "+.cn":            ["udp://223.5.5.5:53"]
    "geosite:category-ads": ["rcode://refused"]
  proxy-server-nameserver:
    - "https://1.1.1.1/dns-query"
  listen: "0.0.0.0:5353"              # 独立 DNS 服务器（可选）
  prefer-h3: false
```

### 字段总览

| 字段 | 默认 | 说明 |
|---|---|---|
| `enable` | `true` | 关闭后内核走系统解析器 |
| `ipv6` | `true` | 全局 AAAA 开关；关闭后 TUN 也丢弃 IPv6 包 |
| `ipv6-timeout` | `100ms` | A+AAAA 并发时 AAAA 超时不阻塞返回 |
| `enhanced-mode` | `off` | `off` / `redir-host` / `fake-ip` |
| `fake-ip-range` | `198.18.0.0/16` | Fake-IP 池；不能与真实路由冲突 |
| `fake-ip-filter` | `[]` | 跳过 Fake-IP 分配的域名（支持 `+.lan` 等） |
| `use-hosts` | `true` | 是否使用 `hosts:` 字段 |
| `use-system-hosts` | `true` | 是否使用系统 hosts 文件 |
| `hosts` | `{}` | 用户自定义域名 → IP 直接映射 |
| `nameserver` | profile 决定 | 主上游列表 |
| `fallback` | `[]` | 备用上游；命中 fallback-filter 时启用 |
| `fallback-filter` | —— | 触发 fallback 的条件（geoip / geosite / ipcidr / domain） |
| `nameserver-policy` | `{}` | 域名/规则集 → 自定义上游覆盖 |
| `proxy-server-nameserver` | profile 决定 | 解析代理节点本身域名所用 DNS（独立第三层） |
| `default-nameserver` | profile 决定 | bootstrap 阶段用，必须是直连 IP 的纯文本 DNS |
| `listen` | `null` | 独立 DNS 服务器（UDP+TCP 同端口） |
| `prefer-h3` | `false` | DoH 优先尝试 HTTP/3 |

### DNS DSL

字符串简写与结构化对象两种写法并存。`nameserver-policy` 的 value 既可以是上游列表，也可以借助 friendly DSL 映射到内置动作：

```yaml
nameserver-policy:
  # 字符串简写
  "ads.com":              "drop"            # 直接拒答
  "tracker.example.com":  "refuse"          # 返回 REFUSED
  "*.cn":                 "direct:mainland" # group=mainland 解析
  "=foo.local":           "hosts:127.0.0.1" # 等价 hosts 注入
  "geosite:cn":           "direct:mainland"

  # 结构化
  "+.ads.example":        { drop: true }
  "stale.example":        { suffix: stale.example, hosts: ["127.0.0.1", "::1"] }
  "+.cn":                 { set: cn, direct: mainland, ecs: 1.2.3.0/24, no_cache: true, ttl: 60 }
  "any":                  { match: any, evaluate: overseas, no_cache: true }
  "rev":                  { match_response: 1.1.1.0/24, respond: true }
  "nx.local":             { suffix: nx.local, nxdomain: true }
```

### Group 调度与三层 fallback

DNS 上游分三层，互不串扰：

```
1. main         resolver.nameserver / nameserver-policy 命中的上游
2. proxy-server resolver.proxy-server-nameserver（解析代理节点域名专用）
3. direct       resolver.default-nameserver（bootstrap，必须是 IP 纯文本上游）
```

`fallback-filter` 命中时，main 解析结果会与 fallback 解析结果做 IP 校验（如 geoip-cn 命中），不通过则采用 fallback 结果。

### Fake-IP

启用 `fake-ip` 后：

- A/AAAA 查询返回 `fake-ip-range` 池里的虚拟地址
- TUN 流量中遇到该虚拟 IP，反查为真实域名后再做路由决策
- `fake-ip-filter` 命中的域名跳过分配（仍走真实解析）
- IP↔Host 反向映射 LRU 持久化在 redb，重启不丢

### Hosts 与 IPv6 开关

- `use-system-hosts: true` 时读取：Windows `%SystemRoot%\System32\drivers\etc\hosts`，Unix `/etc/hosts`
- `hosts:` 内的条目优先于一切上游与 nameserver-policy
- `ipv6: false` 同时影响三层：DNS 不发 AAAA / TUN 丢弃 IPv6 包 / 出站 socket 不绑 IPv6

---

## 节点分组（groups）

```yaml
groups:
  proxy:
    choose: smart                 # manual | smart | fast | stable | spread | chain
    use:    [airport]             # 节点来源：feed 名 / 节点名
    prefer: ["{country}=hk"]      # 偏好（可选）
    avoid:  ["{name}~=test"]      # 避免（可选）
    check:
      url: "https://www.gstatic.com/generate_204"
      every: 60s
      tolerance: 50ms             # URLTest 抖动容忍
    sticky:
      domain: 5m                  # 同 host 在 N 秒内复用上次最优
      negative: 30s               # 失败节点冷却

  streaming:
    choose: fast
    use: [airport]
    prefer: ["{country}=us", "{country}=jp"]
    check:
      url: "https://www.netflix.com/title/70143836"
      every: 5m
```

### choose 策略

| 策略 | 说明 |
|---|---|
| `manual` | 用户经面板手动选择；持久化到 redb，重启保留 |
| `smart` | EWMA 评分 + domain_best + cooldown，连接时即时决策 |
| `fast` | 取 URLTest 最低延迟节点 |
| `stable` | 取抖动最小节点（连续 N 次 URLTest 方差最低） |
| `spread` | 每次连接轮转（round-robin），分担负载 |
| `chain` | 按 `use` 顺序串联，构成 multi-hop 链 |

### prefer / avoid 表达式

`{country}=hk` 国家 ISO；`{name}~=keyword` 名称包含；`{port}=443`；可叠加。

---

## Smart 选节点

```yaml
smart:
  goal: balanced               # balanced | speed | stability | low_cost | privacy
  ewma-alpha: 0.3              # EWMA 衰减因子
  domain-best-ttl: 5m
  negative-base: 30s
  negative-max: 30m
  url-test:
    url: "https://www.gstatic.com/generate_204"
    every: 60s
    concurrency: 8
  sticky:
    enabled: true
    domain: 5m
```

| 维度 | 实现 |
|---|---|
| 评分 | EWMA 成功率衰减（α 可调） |
| 最近最优 | `domain_best` 域名级最近选择缓存 |
| 失败冷却 | `negative` 表，连续失败的节点冷却时间指数退避 |
| 主动测速 | URLTest，目标 URL 与并发度可配置 |
| 持久化 | redb 落盘；评分、域名最优、冷却、URLTest 历史均跨重启保留 |
| 控制面 | `/v1/smart/why?host=&group=`、`/v1/smart/{pin,avoid,reset}` |

### goal 解释

| goal | 评分权重 |
|---|---|
| `balanced` | 默认；成功率 / 延迟 / 抖动 各占 1/3 |
| `speed` | 偏向带宽与延迟（URLTest 权重↑） |
| `stability` | 偏向抖动小、失败少 |
| `low_cost` | 偏向廉价或免费节点（按 feed metadata 标签） |
| `privacy` | 偏向加密强度高、不允许日志的节点（按节点名 / 标签） |

---

## 透明代理（capture）

```yaml
capture:
  on: true
  method: auto                  # auto | virtual_nic | tproxy | redirect
  stack:  system                # system | mixed | native | smoltcp | gvisor
  mtu:    1500
  exclude:
    addresses: [10.0.0.0/8, 172.16.0.0/12, fe80::/10]
    processes: ["docker.exe", "tailscaled"]
    interfaces: ["tailscale0"]
  fwmark:
    auto-redirect-input: 0x2023
    output:              0x2024
    reset:               0x2025
    nfqueue:             100
  android:
    vpnservice:           # 仅 Android profile
      mtu: 1500
      addresses: ["198.18.0.1/15"]
      routes:    ["0.0.0.0/0", "::/0"]
      dns:       ["198.18.0.1"]
      bypass-applications: ["com.google.android.youtube"]
```

### method × stack

| method | 适用 |
|---|---|
| `auto` | 探测系统能力，按 NftablesFull → IptablesV4V6Tproxy → IptablesV4V6Redirect → IptablesV4Only → VirtualNic 顺序降级 |
| `virtual_nic` | TUN 设备（Windows wintun / macOS utun / Linux tun / Android VpnService fd） |
| `tproxy` | Linux TPROXY（不修改包头，零拷贝转发） |
| `redirect` | Linux NAT REDIRECT（UDP 受限） |

| stack | 用于 |
|---|---|
| `system` | 内核协议栈（TPROXY / REDIRECT 路径默认） |
| `mixed` | TCP 走系统，UDP 走用户态（兼顾性能与可控性） |
| `native` | 用户态 TCP + native UDP（默认 TUN 路径） |
| `smoltcp` | 纯 smoltcp 用户态栈（无 IP 转发权限时备选） |
| `gvisor` | gvisor netstack（实验，仅 Linux） |

### Linux TProxy / Redirect

`fwmark` 三个 mark 的角色：

| mark | 用途 |
|---|---|
| `auto-redirect-input` (`0x2023`) | TUN 反向回注流量识别 |
| `output` (`0x2024`) | 出站 socket 标记（绕过自身 TPROXY 链） |
| `reset` (`0x2025`) | block 路径上发 RST 时使用 |
| `nfqueue` (`100`) | nftables/iptables NFQUEUE 编号 |

`route.sets` 的 `ipcidr` 集合可注入到 capture supervisor，用作 `route_address_set: [geoip-cn]` 形式的快速白/黑名单。

### Android VpnService

未 root 的 `virtual_nic` 模式必须由宿主 App 调用：

```kotlin
val cfg = VpnBridge.vpnServiceConfigJson(configPath) // 内核解析后的 VpnService 字段
// 把 cfg 的 addresses / routes / dns / bypass-applications 写入 VpnService.Builder
val fd = builder.establish()!!.detachFd()
VpnBridge.setVpnService(this)
VpnBridge.setVpnFd(fd)
```

Root 路径按可用能力降级，共 4 层：

| 层级 | 名称 | 条件 |
|---|---|---|
| 1 | NftablesFull | 有 nft + ip6 nat + IPv4/v6 TPROXY |
| 2 | IptablesV4V6Tproxy | iptables + ip6tables + 双栈 TPROXY |
| 3 | IptablesV4V6Redirect | iptables + ip6tables NAT REDIRECT；UDP 受限 |
| 4 | IptablesV4Only | 仅 iptables v4 NAT REDIRECT |

`AndroidCapability::detect_capability()` 通过 `su -c` 探测 11 项能力（has_root / has_ip6tables / has_nftables / kernel_ipv6_nat / kernel_tproxy_v6 / uid_owner_match / ...），自动选最高可用 root 层。

---

## 入站与控制面板

```yaml
listen:
  local: "127.0.0.1:7890"        # Mixed 入站（HTTP + SOCKS5 自动嗅探）
  panel: "127.0.0.1:9090"        # 控制面板 / API
  share: false                   # 是否允许 0.0.0.0 监听
  auth:
    - { username: "u", password: "p" }

ui:
  on: true
  secret: "your-api-secret"      # /v1 与 Clash 兼容 API 共用
  cors:
    - "https://yacd.example.com"
  api:
    clash-compat: true           # 同时暴露 /proxies / /connections / ...
```

入站说明：

- `local`: 同端口同时支持 HTTP CONNECT、HTTP 代理、SOCKS5（含 UDP ASSOCIATE）
- `auth`: 留空表示无鉴权；填了用户名密码即两种协议都强制鉴权
- `share: false` 时强制 bind 127.0.0.1；`true` 时允许 0.0.0.0
- 启动钩子检测特权失败时自动降级（绑高端口 / 跳过 capture 改 socks 模式）

---

## 工作空间

```
crates/
  core-config        YAML / 节点 URI 解析 / profile 默认值 / 迁移
  core-runtime       Runtime + GroupSelector + URLTest 周期测速
  core-fetch         HTTP/HTTPS 抓取（feeds / ruleset 共用）
  core-inbound       Mixed (HTTP+SOCKS5) + 权限检测 + 端口降级
  core-outbound      22 种代理协议 + 7 种传输层
  core-route         规则引擎 + 内置 preset + L7 嗅探（STUN/DTLS/QUIC/SNI/HTTP）
  core-resolver      DNS：多 group / 乐观缓存 / 完整动作集 / ECS 三层 / Fake-IP
  core-ruleset       YAML / TXT / LIST / JSON / 自研 RRS 二进制
  core-feeds         订阅拉取 + 缓存 + 周期刷新
  core-smart         EWMA 评分 + domain_best + cooldown
  core-store         redb 嵌入式 KV + AsyncWriter
  core-capture       TUN / TPROXY / REDIRECT + Android 5 层降级
  core-process       4 平台进程查找（Win/Linux/Mac/Android），sync trait + LRU
  core-mesh          Tailscale 协同
  core-observe       tracing / metrics / connections + watchdog
  core-api           /v1 原生 API + Clash 兼容 + URLTest delay
  proxy-core         CLI 入口

tests-e2e/           端到端测试
examples/            6 个示例配置
docs/                构建性能优化等文档
scripts/             多平台一键构建脚本
```

---

## 构建

### 基本编译

```bash
cargo build --release -p proxy-core
cargo test  --workspace
```

### 多平台一键构建（Windows 主机）

```cmd
build.cmd                  默认矩阵
build.cmd windows
build.cmd linux            x86_64-unknown-linux-musl，zigbuild 后端
build.cmd android          aarch64-linux-android，cargo-ndk 后端
```

强制指定后端：

```powershell
pwsh -File scripts/build-all.ps1 -Backend zigbuild -Targets "x86_64-unknown-linux-musl"
```

### 编译目标矩阵

| 目标 | 后端 | Windows 主机可用 |
|---|---|---|
| x86_64-pc-windows-msvc | cargo | 是 |
| aarch64-pc-windows-msvc | cargo | 是 |
| x86_64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-unknown-linux-musl / gnu | cargo-zigbuild | 是 |
| aarch64-linux-android | cargo-ndk + 自动从 `%LOCALAPPDATA%\Android\Sdk\ndk` 发现 NDK | 是 |
| x86_64 / aarch64-apple-darwin | 仅 macOS 主机 | 否 |

### 编译性能

| 优化 | 位置 | 效果 |
|---|---|---|
| `incremental` + `codegen-units=256`（dev） | [Cargo.toml](Cargo.toml) | 单 crate 内并行 |
| `[profile.dev.package."*"] opt-level=1` | 同上 | 依赖也快 |
| `debug="line-tables-only"` + `split-debuginfo` | 同上 | debuginfo 减少约 80% |
| `lto="thin"` + `codegen-units=16`（release） | 同上 | 性能差约 1%，构建时间减少约 60% |
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
GET    /v1/logs                                WebSocket 日志流
GET    /v1/providers/proxies                   订阅 provider 列表
GET    /v1/providers/rules                     规则集 provider 列表
```

### Clash 兼容路径

`/proxies` · `/proxies/:name` · `/proxies/:name/delay` · `/group/:name/delay` · `/connections` · `/configs` · `/version` · `/traffic` · `/logs`

控制面板（如 yacd / metacubexd）直接连入 `panel` 监听端口即可使用。

---

## 测试

```bash
cargo test --workspace
```

主要 crate 覆盖：

| crate | 关注点 |
|---|---|
| core-config | YAML 加载、profile 兜底、节点 URI 解析、迁移 |
| core-route | matcher 优先级、preset、ruleset 集成、L7 嗅探 |
| core-resolver | 完整动作集、ECS 三层、fallback-filter、Fake-IP |
| core-outbound | 22 种协议握手、7 种传输层、TLS 包装、UDP 隧道 |
| core-ruleset | yaml/txt/json/rrs 互转的字节级一致性 |
| core-capture | 4 种 method × 5 种 stack 的诊断与降级 |
| core-smart | EWMA / domain_best / cooldown / sticky |
| core-api | /v1 与兼容路径的契约 |
| tests-e2e | 端到端跨 crate 集成 |

---

## 许可证

[MIT](LICENSE-MIT) 或 [Apache-2.0](LICENSE-APACHE)，二选一。

---

## 设计文档

完整设计参见 [RP内核设计文档.md](RP内核设计文档.md) 与各 crate 顶部 doc 注释。
