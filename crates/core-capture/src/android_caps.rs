//! Android root 透明代理能力枚举 + 自动降级（Tier 选择）。
//!
//! 类型放在这里（**无 cfg**）以便跨平台编译/单元测试；实际 `su -c` 命令调用与
//! 规则安装放在 [`crate::platform::android`] 模块（仅 `target_os = "android"` 编译）。
//!
//! ## 4 层 root Tier 自动降级（与 mihomo Android root 模式对齐）
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────────┐
//!   │ Tier 1  NftablesFull         nft + ip6 nat + ipv4/v6 TPROXY      │ ← 推荐：完整 IPv4 + IPv6 透明代理
//!   ├──────────────────────────────────────────────────────────────────┤
//!   │ Tier 2  IptablesV4V6Tproxy   iptables + ip6tables + TPROXY 双栈   │
//!   ├──────────────────────────────────────────────────────────────────┤
//!   │ Tier 3  IptablesV4V6Redirect iptables + ip6tables NAT REDIRECT    │ ← 双栈 TCP；UDP 受限
//!   ├──────────────────────────────────────────────────────────────────┤
//!   │ Tier 4  IptablesV4Only       仅 iptables v4 NAT REDIRECT          │
//!   └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! 由 [`AndroidCapability::select_tier`] 自动按检测结果挑选最高可用 root 透明代理层。
//! VpnService 是 virtual_nic/TUN 输入，不属于 root 透明代理能力。

use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct AndroidCapability {
    /// `su -c id` 返回 uid=0
    pub has_root: bool,
    /// `iptables --version` 可执行
    pub has_iptables: bool,
    /// **关键**：`ip6tables --version` 可执行
    pub has_ip6tables: bool,
    /// `nft --version` 可执行（推荐）
    pub has_nftables: bool,
    /// **关键**：内核编译了 IPv6 NAT（`ip6tables -t nat -L` 不报 No chain）
    pub kernel_ipv6_nat: bool,
    /// 内核支持 TPROXY 模块（`/proc/net/ip_tables_matches` 含 TPROXY）
    pub kernel_tproxy: bool,
    /// **关键**：IPv6 TPROXY 也可用
    pub kernel_tproxy_v6: bool,
    /// `-m owner --uid-owner` 可用 —— 排除自身流量必备
    pub uid_owner_match: bool,
    /// raw socket 可用（直接发包，少数场景用）
    pub raw_socket_supported: bool,
    /// `tun` 模块（`/dev/tun` 或 `ip tuntap` 可用）
    pub tun_module: bool,
    /// 探测中收集的额外笔记（人类可读）
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AndroidTier {
    /// nft + ipv6 + tproxy —— 完整能力，推荐 Android 12+ 现代内核
    NftablesFull,
    /// iptables + ip6tables + 双栈 TPROXY（含 UDP 透明代理）
    IptablesV4V6Tproxy,
    /// iptables + ip6tables NAT REDIRECT（仅 TCP；UDP 走 fake-ip + TUN）
    IptablesV4V6Redirect,
    /// 仅 IPv4 —— 旧设备/特定 ROM
    IptablesV4Only,
}

impl AndroidTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::NftablesFull => "nftables-full",
            Self::IptablesV4V6Tproxy => "iptables-v4v6-tproxy",
            Self::IptablesV4V6Redirect => "iptables-v4v6-redirect",
            Self::IptablesV4Only => "iptables-v4-only",
        }
    }
    pub fn supports_ipv6(&self) -> bool {
        matches!(
            self,
            Self::NftablesFull | Self::IptablesV4V6Tproxy | Self::IptablesV4V6Redirect
        )
    }
    pub fn supports_udp_transparent(&self) -> bool {
        matches!(self, Self::NftablesFull | Self::IptablesV4V6Tproxy)
    }
    pub fn requires_root(&self) -> bool {
        true
    }
}

impl AndroidCapability {
    /// 按检测结果挑选最高可用 Tier。
    pub fn select_tier(&self) -> Option<AndroidTier> {
        if !self.has_root {
            return None;
        }
        // Tier 1：nftables + 全套
        if self.has_nftables
            && self.kernel_tproxy
            && self.kernel_tproxy_v6
            && self.kernel_ipv6_nat
            && self.uid_owner_match
        {
            return Some(AndroidTier::NftablesFull);
        }
        // Tier 2：双栈 TPROXY
        if self.has_iptables && self.has_ip6tables && self.kernel_tproxy && self.kernel_tproxy_v6 {
            return Some(AndroidTier::IptablesV4V6Tproxy);
        }
        // Tier 3：双栈 NAT REDIRECT
        if self.has_iptables && self.has_ip6tables && self.kernel_ipv6_nat {
            return Some(AndroidTier::IptablesV4V6Redirect);
        }
        // Tier 4：v4 only
        if self.has_iptables {
            return Some(AndroidTier::IptablesV4Only);
        }
        None
    }

    /// 给定降级理由的 `notes`，便于 doctor 输出。
    pub fn explain_degradation(&self, picked: Option<AndroidTier>) -> Vec<String> {
        let mut out = Vec::new();
        if !self.has_root {
            out.push("无 root（su 不可用）→ 无法安装 Android root 透明代理规则".into());
            return out;
        }
        if picked != Some(AndroidTier::NftablesFull) {
            if !self.has_nftables {
                out.push("缺少 nft（未升级到 nftables 路径）".into());
            }
            if !self.kernel_tproxy {
                out.push("内核未启用 TPROXY 模块".into());
            }
            if !self.kernel_tproxy_v6 {
                out.push("内核未启用 IPv6 TPROXY".into());
            }
            if !self.kernel_ipv6_nat {
                out.push("内核未启用 IPv6 NAT (ip6_nat) → IPv6 流量将不能 REDIRECT".into());
            }
            if !self.uid_owner_match {
                out.push("缺少 -m owner --uid-owner，无法排除自身流量".into());
            }
        }
        if picked.is_none() && !self.has_iptables {
            out.push("iptables 不可用 → 无可用 Android root 透明代理后端".into());
        }
        if !self.has_ip6tables && (picked == Some(AndroidTier::IptablesV4Only)) {
            out.push("ip6tables 不可用 → IPv6 透明代理被禁用，IPv6 流量将走系统直连".into());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> AndroidCapability {
        AndroidCapability {
            has_root: true,
            has_iptables: true,
            has_ip6tables: true,
            has_nftables: true,
            kernel_ipv6_nat: true,
            kernel_tproxy: true,
            kernel_tproxy_v6: true,
            uid_owner_match: true,
            raw_socket_supported: true,
            tun_module: true,
            notes: vec![],
        }
    }

    #[test]
    fn full_capability_picks_nftables() {
        assert_eq!(full().select_tier(), Some(AndroidTier::NftablesFull));
    }

    #[test]
    fn no_nftables_falls_to_iptables_tproxy() {
        let mut c = full();
        c.has_nftables = false;
        assert_eq!(c.select_tier(), Some(AndroidTier::IptablesV4V6Tproxy));
    }

    #[test]
    fn no_tproxy_falls_to_redirect() {
        let mut c = full();
        c.has_nftables = false;
        c.kernel_tproxy = false;
        c.kernel_tproxy_v6 = false;
        assert_eq!(c.select_tier(), Some(AndroidTier::IptablesV4V6Redirect));
    }

    #[test]
    fn no_ipv6_nat_falls_to_v4_only() {
        let mut c = full();
        c.has_nftables = false;
        c.kernel_tproxy = false;
        c.kernel_tproxy_v6 = false;
        c.kernel_ipv6_nat = false;
        c.has_ip6tables = false;
        assert_eq!(c.select_tier(), Some(AndroidTier::IptablesV4Only));
    }

    #[test]
    fn no_root_has_no_transparent_proxy_tier() {
        let mut c = full();
        c.has_root = false;
        assert_eq!(c.select_tier(), None);
    }

    #[test]
    fn no_iptables_has_no_transparent_proxy_tier() {
        let mut c = full();
        c.has_nftables = false;
        c.has_iptables = false;
        c.has_ip6tables = false;
        assert_eq!(c.select_tier(), None);
    }

    #[test]
    fn capability_flags_reflect_tier() {
        assert!(AndroidTier::NftablesFull.supports_ipv6());
        assert!(AndroidTier::NftablesFull.supports_udp_transparent());
        assert!(AndroidTier::IptablesV4V6Tproxy.supports_udp_transparent());
        assert!(!AndroidTier::IptablesV4V6Redirect.supports_udp_transparent());
        assert!(!AndroidTier::IptablesV4Only.supports_ipv6());
    }

    #[test]
    fn explain_degradation_messages() {
        // 没有 ip6_nat 但保留 ip6tables → 不能 NAT v6 → 降到仅 v4
        let mut c = full();
        c.kernel_ipv6_nat = false;
        c.has_nftables = false;
        c.kernel_tproxy = false;
        c.kernel_tproxy_v6 = false;
        let picked = c.select_tier();
        assert_eq!(picked, Some(AndroidTier::IptablesV4Only));
        let notes = c.explain_degradation(picked);
        assert!(!notes.is_empty());
        assert!(notes
            .iter()
            .any(|n| n.contains("nft") || n.contains("TPROXY") || n.contains("NAT")));
    }
}
