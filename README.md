# RPKernel

> 0.3 Friendly YAML 设计版的 Rust 代理内核 —— 配置字段独立于 Mihomo，能力面对齐 Mihomo / Smart 更可解释、更稳定、更高性能。

参见 [RP内核设计文档.md](RP内核设计文档.md) 获取完整设计；本仓库按 M1-M8 路线推进，当前阶段聚焦 **M1 配置与普通代理** 的可运行 MVP，并搭建好后续 M2-M8 的 crate 骨架与扩展点。

## 用户只需要理解 10 个词

| 词       | 小白理解               | 内核含义                                      |
|----------|------------------------|-----------------------------------------------|
| listen   | 软件在哪个端口等你连接 | HTTP/SOCKS/Mixed/控制面板/API 入站监听        |
| feeds    | 机场订阅链接           | 远程或本地节点 Provider，支持过滤、重命名     |
| nodes    | 自己手动添加的节点     | 结构化或 URI 出站代理定义                     |
| groups   | 一堆节点怎么选         | manual/smart/fast/stable/spread/chain         |
| route    | 哪些直连，哪些走代理   | 规则引擎 + preset                             |
| resolver | 域名怎么查             | DNS 缓存、DoH/DoT、Fake 地址、防泄漏          |
| capture  | 是否接管全设备流量     | TUN / TProxy / redirect / DNS 劫持            |
| smart    | 自动选最合适节点       | 启发式 + 学习评分 + 解释                      |
| ui       | 面板和 API             | 原生 /v1 + Clash/Mihomo 兼容 API              |
| mesh     | 和内网/VPN 协同        | Tailscale / WireGuard / 局域网保护            |

## 最小有效配置

```yaml
version: 1
profile: desktop
feeds:
  my_airport: "https://example.com/your-subscription"
```

## 快速使用

```bash
# 编译
cargo build --release

# 校验配置
./target/release/proxy-core check examples/desktop.yaml

# 解释配置展开后的运行时
./target/release/proxy-core explain examples/desktop.yaml

# 运行内核
./target/release/proxy-core run -c examples/desktop.yaml
```

## 工作空间布局

```
crates/
  core-config    # Friendly YAML 解析、默认值合并、schema 校验、迁移
  core-runtime   # 运行时 graph、生命周期、热重载、任务编排
  core-inbound   # Mixed/HTTP/SOCKS/TUN/TProxy/redirect listener
  core-outbound  # 协议适配器与 direct/block/resolver 出口
  core-route     # 规则引擎、规则集、进程/端口/IP/域名匹配
  core-resolver  # DNS、Fake 地址、缓存、DoH/DoT/DoQ
  core-smart     # Smart 评分、学习、缓存、解释
  core-api       # 原生 API、兼容 API、Dashboard
  core-capture   # TUN/TProxy/防火墙/路由表平台适配
  core-mesh      # Tailscale/WireGuard/局域网协同
  core-observe   # tracing、metrics、pprof、日志
proxy-core/      # 顶层 CLI
examples/        # 模板 A/B/C/D
```

## 当前实现状态

- M1 配置与普通代理：✅ Friendly YAML、Mixed (HTTP+SOCKS5) 入站、direct/block/http/socks5 出站、route preset/steps、基础 resolver。
- M2-M8：✅ 接口骨架已就位，按里程碑逐步实现协议、Smart、TUN/TProxy、API、Tailscale。
