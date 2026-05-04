//! 内置规则集 —— home / cn / ads / service。
//!
//! MVP：直接内嵌一份小规模列表（足以让模板 A/B 默认行为合理），
//! M3 之后可改为读取外部规则集（geosite / geoip）。

use ipnet::IpNet;
use once_cell::sync::Lazy;

/// 局域网/私有 CIDR。
pub static HOME_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "fd7a:115c:a1e0::/48",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
});

/// 局域网/Bonjour 域名后缀。
pub static HOME_SUFFIXES: &[&str] = &["local", "lan", "home", "internal"];

/// 极小化 cn 域名集合 —— 实际部署应替换为 geosite。
pub static CN_SUFFIXES: &[&str] = &[
    "cn",
    "com.cn",
    "org.cn",
    "net.cn",
    "edu.cn",
    "gov.cn",
    "qq.com",
    "baidu.com",
    "alipay.com",
    "taobao.com",
    "tmall.com",
    "jd.com",
    "weibo.com",
    "bilibili.com",
    "163.com",
    "126.com",
    "iqiyi.com",
    "youku.com",
    "douyin.com",
    "tencent.com",
    "aliyun.com",
    "alicdn.com",
    "tencentcs.com",
    "wechat.com",
];

/// 极小化 cn IP 段。M3 替换为 geoip。
pub static CN_CIDRS: Lazy<Vec<IpNet>> = Lazy::new(|| {
    [
        "1.0.1.0/24",
        "1.0.32.0/19",
        "1.1.0.0/24",
        "14.16.0.0/12",
        "27.0.128.0/18",
        "36.0.0.0/14",
        "39.64.0.0/11",
        "42.48.0.0/12",
        "58.16.0.0/13",
        "60.0.0.0/13",
        "61.128.0.0/10",
        "101.0.0.0/12",
        "106.0.0.0/13",
        "110.16.0.0/12",
        "112.0.0.0/9",
        "115.24.0.0/13",
        "116.0.0.0/8",
        "119.176.0.0/12",
        "120.192.0.0/10",
        "121.16.0.0/12",
        "180.96.0.0/11",
        "203.79.0.0/16",
        "210.16.0.0/13",
        "218.0.0.0/10",
        "219.128.0.0/11",
        "220.96.0.0/11",
        "221.128.0.0/9",
        "222.0.0.0/8",
        "223.0.0.0/12",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
});

pub static ADS_SUFFIXES: &[&str] = &[
    "doubleclick.net",
    "googlesyndication.com",
    "googletagservices.com",
    "googletagmanager.com",
    "google-analytics.com",
    "adservice.google.com",
    "scorecardresearch.com",
    "adsrvr.org",
    "adnxs.com",
    "adsymptotic.com",
    "adcolony.com",
];

pub fn service_suffixes(name: &str) -> &'static [&'static str] {
    match name {
        "telegram" => &["telegram.org", "t.me", "tdesktop.com", "telegra.ph"],
        "youtube" => &["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"],
        "netflix" => &[
            "netflix.com",
            "nflxvideo.net",
            "nflxext.com",
            "nflximg.net",
            "nflxso.net",
        ],
        "github" => &[
            "github.com",
            "githubusercontent.com",
            "githubassets.com",
            "ghcr.io",
        ],
        "apple" => &["apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com"],
        "google" => &[
            "google.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "withgoogle.com",
        ],
        _ => &[],
    }
}
