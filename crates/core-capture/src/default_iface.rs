//! 跨平台默认物理网卡探测 —— 给出站 socket 的 SO_BINDTODEVICE /
//! IP_UNICAST_IF / IP_BOUND_IF 提供参数源。
//!
//! 之前的代码三个平台各自一份探测函数：
//! * `platform/windows.rs::probe_default_interface_indices()` 仅 ifindex，启动一次
//! * `platform/macos.rs::probe_default_interface_indices()` 仅 ifindex，启动一次
//! * `net_monitor::detect_default_interface()` 仅 Linux/Android，轮询 name
//!
//! 每个探测都缺一半信息，且 watcher 只覆盖 Linux/Android。本模块统一返回
//! `DefaultInterface { name, v4_index, v6_index }`，让 `net_monitor` 在所有平台
//! 上都能监听变化、同步 name + ifindex。

use std::collections::HashSet;

/// 默认物理出口的探测结果。
///
/// `name` —— 接口名（如 `eth0`、`Wi-Fi`、`en0`）。Linux/Android `SO_BINDTODEVICE`
/// 只接受名字。
///
/// `v4_index` / `v6_index` —— `if_nametoindex` 返回的内核接口编号。Windows
/// `IP_UNICAST_IF` / `IPV6_UNICAST_IF`、Darwin `IP_BOUND_IF` / `IPV6_BOUND_IF`
/// 必须按 ifindex 绑定。两族独立给（多宿主机 v4 / v6 可走不同物理接口）。
///
/// 三者都有可能 `None`：未启动 / 系统没默认路由 / 探测被排除（命中 TUN 自身）。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DefaultInterface {
    pub name: Option<String>,
    pub v4_index: Option<u32>,
    pub v6_index: Option<u32>,
}

impl DefaultInterface {
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.v4_index.is_none() && self.v6_index.is_none()
    }
}

/// 跨平台探测当前默认物理出口。
///
/// `exclude` —— 排除集合：完整接口名（plan.interface_name）+ 常见 TUN 前缀
/// （utun / tun / wintun ...）都会被剔除，否则 TUN 接管默认路由后再探就拿到
/// 自己 → 出站 socket 又绑回 TUN 形成死循环。
pub fn probe(exclude: &ExcludeList) -> DefaultInterface {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        linux_probe(exclude)
    }
    #[cfg(target_os = "windows")]
    {
        windows_probe(exclude)
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        darwin_probe(exclude)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "windows",
        target_os = "macos",
        target_os = "ios"
    )))]
    {
        let _ = exclude;
        DefaultInterface::default()
    }
}

/// 探测时要排除的接口集合。完整名走 `names`（精确匹配），前缀走 `prefixes`
/// （`starts_with`）—— 用前缀是因为 macOS 给我们的 utun 名字是动态的（utun3 /
/// utun5 ...），又因为这些前缀本身就属于 VPN/TUN 类设备，永远不该被选作"物理"
/// 默认出口。
#[derive(Debug, Default, Clone)]
pub struct ExcludeList {
    pub names: HashSet<String>,
    pub prefixes: Vec<String>,
}

impl ExcludeList {
    pub fn from_plan_iface(iface_name: impl Into<String>) -> Self {
        let mut names = HashSet::new();
        let n = iface_name.into();
        if !n.is_empty() {
            names.insert(n);
        }
        Self {
            names,
            prefixes: default_tun_prefixes(),
        }
    }

    pub fn matches(&self, candidate: &str) -> bool {
        if self.names.contains(candidate) {
            return true;
        }
        let lower = candidate.to_ascii_lowercase();
        self.prefixes
            .iter()
            .any(|p| lower.starts_with(&p.to_ascii_lowercase()))
    }
}

fn default_tun_prefixes() -> Vec<String> {
    vec![
        "utun".into(),
        "tun".into(),
        "tap".into(),
        "wintun".into(),
        "wuthercore".into(),
        "meta".into(),
    ]
}

/* ---------------- Linux / Android ---------------- */

#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_probe(exclude: &ExcludeList) -> DefaultInterface {
    let name = parse_proc_net_route_default(
        std::fs::read_to_string("/proc/net/route").unwrap_or_default().as_str(),
        exclude,
    );
    let (v4, v6) = match name.as_deref() {
        Some(n) => {
            let v4 = nametoindex(n);
            // v6 默认路由在 /proc/net/ipv6_route，取首个。共用 name 在大多数
            // 单 NIC 主机上是对的；多家庭 / 多 NIC 这里可能不准，但 setsockopt
            // 用 ifindex=0 表示"系统默认"，所以 None 也是安全 fallback。
            let v6_name = parse_proc_net_ipv6_route_default(
                std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default().as_str(),
                exclude,
            );
            let v6 = v6_name.as_deref().and_then(nametoindex);
            (v4, v6)
        }
        None => (None, None),
    };
    DefaultInterface {
        name,
        v4_index: v4,
        v6_index: v6,
    }
}

/// 解析 /proc/net/route，返回最小 metric 的 IPv4 默认路由接口名。
/// destination 全 0、mask 全 0 即默认路由；`exclude` 命中则跳过。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn parse_proc_net_route_default(content: &str, exclude: &ExcludeList) -> Option<String> {
    let mut best: Option<(String, u32)> = None;
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 11 {
            continue;
        }
        if f[1] != "00000000" || f[7] != "00000000" {
            continue;
        }
        let iface = f[0].to_string();
        if exclude.matches(&iface) {
            continue;
        }
        let metric = f[6].parse::<u32>().unwrap_or(u32::MAX);
        match &best {
            Some((_, m)) if metric < *m => best = Some((iface, metric)),
            None => best = Some((iface, metric)),
            _ => {}
        }
    }
    best.map(|(i, _)| i)
}

/// 解析 /proc/net/ipv6_route，返回最小 metric 的 ::/0 默认路由接口名。
/// 字段格式：`dest dest_prefix src src_prefix next_hop metric refcount use flags iface`。
#[cfg(any(test, target_os = "linux", target_os = "android"))]
pub(crate) fn parse_proc_net_ipv6_route_default(
    content: &str,
    exclude: &ExcludeList,
) -> Option<String> {
    let mut best: Option<(String, u32)> = None;
    for line in content.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        // dest = 32 zeros、dest_prefix = "00" 即 ::/0
        if f[0] != "00000000000000000000000000000000" || f[1] != "00" {
            continue;
        }
        let iface = f[9].to_string();
        if exclude.matches(&iface) {
            continue;
        }
        let metric = u32::from_str_radix(f[5], 16).unwrap_or(u32::MAX);
        match &best {
            Some((_, m)) if metric < *m => best = Some((iface, metric)),
            None => best = Some((iface, metric)),
            _ => {}
        }
    }
    best.map(|(i, _)| i)
}

#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))]
fn nametoindex(name: &str) -> Option<u32> {
    nix::net::if_::if_nametoindex(name)
        .ok()
        .filter(|&v| v != 0)
        .map(|v| v as u32)
}

/* ---------------- Windows ---------------- */

#[cfg(target_os = "windows")]
fn windows_probe(exclude: &ExcludeList) -> DefaultInterface {
    let v4 = windows_probe_family("IPv4", exclude);
    let v6 = windows_probe_family("IPv6", exclude);
    let name = v4
        .as_ref()
        .map(|(_, n)| n.clone())
        .or_else(|| v6.as_ref().map(|(_, n)| n.clone()));
    DefaultInterface {
        name,
        v4_index: v4.map(|(i, _)| i),
        v6_index: v6.map(|(i, _)| i),
    }
}

#[cfg(target_os = "windows")]
fn windows_probe_family(family: &str, exclude: &ExcludeList) -> Option<(u32, String)> {
    let prefix = if family == "IPv6" { "::/0" } else { "0.0.0.0/0" };
    // 取 metric 最低的 5 条默认路由（按 InterfaceIndex|InterfaceAlias 输出），
    // Rust 侧再用 exclude 过滤——这样用户自定义 TUN 名字也能被排除。
    let script = format!(
        "$r = Get-NetRoute -AddressFamily {family} -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue \
         | Where-Object {{ $_.NextHop -ne '::' -and $_.NextHop -ne '0.0.0.0' }} \
         | Sort-Object -Property RouteMetric \
         | Select-Object -First 5; \
         foreach ($x in $r) {{ Write-Host \"$($x.InterfaceIndex)|$($x.InterfaceAlias)\" }}"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_windows_route_lines(&stdout, exclude)
}

/// 解析 `Write-Host "INDEX|ALIAS"` 输出，返回第一个未被 exclude 命中的
/// `(ifindex, alias)`。已按 metric 升序，第一行命中即返回。
#[cfg(any(test, target_os = "windows"))]
pub(crate) fn parse_windows_route_lines(
    stdout: &str,
    exclude: &ExcludeList,
) -> Option<(u32, String)> {
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, '|');
        let Some(idx_s) = parts.next() else { continue };
        let Some(alias_raw) = parts.next() else { continue };
        let alias = alias_raw.trim().to_string();
        // ifindex == 0 是哨兵值（"系统默认"），跳过当前行而不是终止整个迭代 ——
        // 否则一行无效输出就会让后续合法行也被丢弃。
        let Some(idx) = idx_s.trim().parse::<u32>().ok().filter(|&v| v != 0) else {
            continue;
        };
        if exclude.matches(&alias) {
            continue;
        }
        return Some((idx, alias));
    }
    None
}

/* ---------------- macOS / iOS ---------------- */

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn darwin_probe(exclude: &ExcludeList) -> DefaultInterface {
    let v4_name = darwin_probe_family("inet", exclude);
    let v6_name = darwin_probe_family("inet6", exclude);
    let name = v4_name.clone().or_else(|| v6_name.clone());
    DefaultInterface {
        name,
        v4_index: v4_name.as_deref().and_then(nametoindex),
        v6_index: v6_name.as_deref().and_then(nametoindex),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn darwin_probe_family(family: &str, exclude: &ExcludeList) -> Option<String> {
    let args: &[&str] = match family {
        "inet6" => &["-n", "get", "-inet6", "default"],
        _ => &["-n", "get", "default"],
    };
    let out = std::process::Command::new("route").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    parse_darwin_route_default(&stdout, exclude)
}

/// 从 `route -n get default` 抽 `interface: <name>` 行的值，命中 exclude 返回 None。
#[cfg(any(test, target_os = "macos", target_os = "ios"))]
pub(crate) fn parse_darwin_route_default(stdout: &str, exclude: &ExcludeList) -> Option<String> {
    let iface = stdout.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("interface:")
            .map(|rest| rest.trim().to_string())
            .filter(|s| !s.is_empty())
    })?;
    if iface == "lo0" || exclude.matches(&iface) {
        return None;
    }
    Some(iface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn excl(name: &str) -> ExcludeList {
        ExcludeList::from_plan_iface(name)
    }

    #[test]
    fn exclude_matches_exact_name() {
        let e = excl("WutherCore");
        assert!(e.matches("WutherCore"));
        assert!(!e.matches("eth0"));
    }

    #[test]
    fn exclude_matches_prefix_case_insensitive() {
        let e = excl("");
        assert!(e.matches("utun3"));
        assert!(e.matches("UTUN5"));
        assert!(e.matches("wintun-1"));
        assert!(e.matches("Meta"));
        assert!(!e.matches("eth0"));
        assert!(!e.matches("Wi-Fi"));
    }

    #[test]
    fn proc_route_picks_lowest_metric_default() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t00000000\t01010101\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                       wlan0\t00000000\t02020202\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
                       eth0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        let e = excl("");
        assert_eq!(
            parse_proc_net_route_default(content, &e),
            Some("wlan0".to_string())
        );
    }

    #[test]
    fn proc_route_skips_excluded_iface_even_if_lowest_metric() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       utun3\t00000000\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
                       eth0\t00000000\t01010101\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        let e = excl("");
        assert_eq!(
            parse_proc_net_route_default(content, &e),
            Some("eth0".to_string())
        );
    }

    #[test]
    fn proc_route_returns_none_when_no_default() {
        let content = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                       eth0\t0000FEA9\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route_default(content, &excl("")), None);
    }

    #[test]
    fn proc_ipv6_route_picks_lowest_metric_default() {
        // dest=::/0 表示 32 个 0 + prefix 00；metric 是十六进制
        let content = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000201020304050607 00000400 00000001 00000000 00000003 wlan0\n\
                       00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000201020304050608 00000200 00000001 00000000 00000003 eth0\n";
        let e = excl("");
        assert_eq!(
            parse_proc_net_ipv6_route_default(content, &e),
            Some("eth0".to_string())
        );
    }

    #[test]
    fn windows_route_lines_pick_first_non_excluded() {
        let stdout = "12|WutherCore TUN\n7|Wi-Fi\n3|Ethernet\n";
        let e = excl("WutherCore TUN");
        assert_eq!(
            parse_windows_route_lines(stdout, &e),
            Some((7, "Wi-Fi".to_string()))
        );
    }

    #[test]
    fn windows_route_lines_filter_via_prefix() {
        let stdout = "9|wintun_v2\n5|Ethernet 2\n";
        let e = excl("");
        assert_eq!(
            parse_windows_route_lines(stdout, &e),
            Some((5, "Ethernet 2".to_string()))
        );
    }

    #[test]
    fn windows_route_lines_skip_zero_index() {
        let stdout = "0|Bogus\n4|Wi-Fi\n";
        let e = excl("");
        assert_eq!(
            parse_windows_route_lines(stdout, &e),
            Some((4, "Wi-Fi".to_string()))
        );
    }

    #[test]
    fn windows_route_lines_returns_none_when_all_excluded() {
        let stdout = "9|utun3\n10|tap-windows\n";
        let e = excl("");
        assert_eq!(parse_windows_route_lines(stdout, &e), None);
    }

    #[test]
    fn darwin_route_default_extracts_interface_line() {
        let stdout = "   route to: default\n\
                      destination: default\n\
                          gateway: 192.168.1.1\n\
                        interface: en0\n\
                            flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(
            parse_darwin_route_default(stdout, &excl("")),
            Some("en0".to_string())
        );
    }

    #[test]
    fn darwin_route_default_excludes_loopback_and_tun() {
        let lo = "interface: lo0\n";
        let utun = "interface: utun4\n";
        assert_eq!(parse_darwin_route_default(lo, &excl("")), None);
        assert_eq!(parse_darwin_route_default(utun, &excl("")), None);
    }
}
