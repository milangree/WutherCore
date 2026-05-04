//! L7 协议嗅探 —— 第一段 packet 即可识别 STUN / DTLS / QUIC / TLS+SNI / HTTP。
//!
//! 用途：
//! 1. **WebRTC / STUN 流量识别**：默认 mihomo 行为 —— 业务代理通常会改写 IP，
//!    导致 STUN binding 拿到错误的对端 IP，进而 P2P 不通且暴露真实 IP。
//!    内核检测到 STUN 流量后可由规则强制：
//!    - `proto:stun -> reject`（最安全）
//!    - `proto:stun -> direct`（让 STUN 走真实出口）
//!    - `proto:webrtc -> some-group`（统一打到一个组）
//! 2. **DTLS / QUIC**：WebRTC 媒体流走 DTLS-SRTP；HTTP/3 走 QUIC。
//! 3. **TLS SNI 提取**：第一字节 0x16 + ClientHello 解析；命中后写入
//!    [`L7Proto::Sni`] 让 route 引擎按 SNI 而不是仅 IP 决策。
//!
//! 全部在第一段 datagram / TCP 首包内完成；无握手往返，对热路径几乎零开销。

use serde::Serialize;

/// 应用层协议指纹。`Sni` 内含 host，可让 route 引擎按 SNI 直接命中域名规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum L7Proto {
    /// STUN binding / ICE 探测（WebRTC 必经，UDP）
    Stun,
    /// DTLS（WebRTC 媒体加密 / DTLS-SRTP）
    Dtls,
    /// QUIC（HTTP/3 / WebRTC over QUIC）
    Quic,
    /// 通用 TLS（无 SNI 或解析失败）
    Tls,
    /// 含 SNI 的 TLS ClientHello —— SNI 直接给 route 用
    Sni(String),
    /// 明文 HTTP（GET/POST/...）
    Http,
    /// 未识别
    Other,
}

impl L7Proto {
    /// 是否属于 WebRTC 家族（STUN / DTLS / QUIC）。
    pub fn is_webrtc(&self) -> bool {
        matches!(self, L7Proto::Stun | L7Proto::Dtls | L7Proto::Quic)
    }
    pub fn name(&self) -> &'static str {
        match self {
            L7Proto::Stun => "stun",
            L7Proto::Dtls => "dtls",
            L7Proto::Quic => "quic",
            L7Proto::Tls => "tls",
            L7Proto::Sni(_) => "sni",
            L7Proto::Http => "http",
            L7Proto::Other => "other",
        }
    }
}

/// 嗅探 UDP 第一段 datagram。
pub fn sniff_udp(buf: &[u8]) -> L7Proto {
    if buf.len() < 8 {
        return L7Proto::Other;
    }
    // STUN: RFC 5389 magic cookie 0x2112A442 at byte 4..8
    // 同时 first 2 bits 必须为 0（message type 高 2 位 = 00）
    if buf[4..8] == [0x21, 0x12, 0xA4, 0x42] && (buf[0] & 0xc0) == 0 {
        return L7Proto::Stun;
    }
    // DTLS: RFC 6347 record layer
    //   byte0 ContentType: 20-25 (CCS/Alert/Handshake/AppData/Heartbeat)
    //   byte1-2 Version: 0xfeff (DTLS 1.0) / 0xfefd (DTLS 1.2) / 0xfefc (DTLS 1.3)
    if (buf[0] >= 0x14 && buf[0] <= 0x19)
        && buf[1] == 0xfe
        && (buf[2] == 0xff || buf[2] == 0xfd || buf[2] == 0xfc)
    {
        return L7Proto::Dtls;
    }
    // QUIC long header: byte0 bit7 = 1，version 4 字节非 0（draft & v1）
    if (buf[0] & 0x80) != 0 && buf.len() >= 5 {
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        // version 0 是 negotiation；非 0 视为 QUIC v1 / draft
        if version != 0 {
            return L7Proto::Quic;
        }
    }
    L7Proto::Other
}

/// 嗅探 TCP 第一段 payload。
pub fn sniff_tcp(buf: &[u8]) -> L7Proto {
    if buf.len() < 5 {
        return L7Proto::Other;
    }
    // TLS ClientHello: 0x16 0x03 0x0[1-4]
    if buf[0] == 0x16 && buf[1] == 0x03 && buf[2] <= 0x04 {
        if let Some(sni) = parse_tls_sni(buf) {
            return L7Proto::Sni(sni);
        }
        return L7Proto::Tls;
    }
    // HTTP 方法
    let prefixes: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"CONNECT ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
    ];
    for p in prefixes {
        if buf.starts_with(p) {
            return L7Proto::Http;
        }
    }
    L7Proto::Other
}

/// 从 TLS ClientHello 提取 SNI 域名。
///
/// TLS Record:
///   0       ContentType=22
///   1..3    Version
///   3..5    Length
///   5..     Handshake:
///             0     Type=ClientHello (1)
///             1..4  Length (3 bytes)
///             4..6  Version
///             6..38 Random (32B)
///             38    SessionID Length
///             39..  SessionID
///             ...   CipherSuites + Compression + Extensions
fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 || buf[0] != 0x16 || buf[5] != 0x01 {
        return None;
    }
    let mut i: usize = 5 + 4 + 2 + 32; // skip handshake header + version + random
    if i >= buf.len() {
        return None;
    }
    // Session ID
    let sid_len = buf[i] as usize;
    i += 1 + sid_len;
    if i + 2 > buf.len() {
        return None;
    }
    // Cipher Suites
    let cs_len = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2 + cs_len;
    if i + 1 > buf.len() {
        return None;
    }
    // Compression Methods
    let cm_len = buf[i] as usize;
    i += 1 + cm_len;
    if i + 2 > buf.len() {
        return None;
    }
    // Extensions
    let ext_total = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    let ext_end = i + ext_total;
    while i + 4 <= buf.len() && i + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let ext_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + ext_len > buf.len() {
            return None;
        }
        if ext_type == 0x0000 {
            // server_name extension
            // 2B list length + list:
            //   1B name type (0=host_name)
            //   2B name length
            //   N  name bytes
            if ext_len < 5 {
                return None;
            }
            let _list_len = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let name_type = buf[i + 2];
            if name_type != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([buf[i + 3], buf[i + 4]]) as usize;
            if i + 5 + name_len > buf.len() {
                return None;
            }
            let name = &buf[i + 5..i + 5 + name_len];
            return std::str::from_utf8(name).ok().map(String::from);
        }
        i += ext_len;
    }
    None
}

/// 输入字符串 matcher 名（"stun"/"webrtc"/"quic"/...），匹配协议。
/// `webrtc` 等价于 STUN ∪ DTLS ∪ QUIC。
pub fn proto_name_matches(name: &str, p: &L7Proto) -> bool {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "stun" => matches!(p, L7Proto::Stun),
        "dtls" => matches!(p, L7Proto::Dtls),
        "quic" => matches!(p, L7Proto::Quic),
        "tls" | "ssl" => matches!(p, L7Proto::Tls | L7Proto::Sni(_)),
        "http" => matches!(p, L7Proto::Http),
        "sni" => matches!(p, L7Proto::Sni(_)),
        "webrtc" | "rtc" => p.is_webrtc(),
        "any" => !matches!(p, L7Proto::Other),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真实 STUN binding request 头部（RFC 5389）
    fn stun_binding() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x01, 0x00, 0x08]); // type=Binding Request, len=8
        v.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        v.extend_from_slice(&[0u8; 12]); // transaction id
        v.extend_from_slice(&[0x00, 0x06, 0x00, 0x04]); // attr USERNAME
        v.extend_from_slice(b"abcd");
        v
    }

    /// DTLS 1.2 ClientHello record
    fn dtls_handshake() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x16, 0xfe, 0xfd, 0x00, 0x00]); // ContentType=22, ver=DTLS1.2, epoch=0
        v.extend_from_slice(&[0u8; 16]); // seq + length placeholder
        v
    }

    /// QUIC v1 long header
    fn quic_initial() -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0xc0); // long header, type=Initial
        v.extend_from_slice(&0x00000001u32.to_be_bytes()); // version=1
        v.extend_from_slice(&[0u8; 8]);
        v
    }

    /// TLS ClientHello with SNI = "example.com"
    fn tls_clienthello_sni(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        let mut v = Vec::new();
        // Record header: ContentType=0x16, Version=0x0303, Length=fillin
        v.extend_from_slice(&[0x16, 0x03, 0x03]);
        let len_off = v.len();
        v.extend_from_slice(&[0, 0]);
        // Handshake: Type=1 ClientHello, len fillin
        v.extend_from_slice(&[0x01, 0, 0, 0]);
        // Version (0x0303), Random (32B)
        v.extend_from_slice(&[0x03, 0x03]);
        v.extend_from_slice(&[0u8; 32]);
        // SessionID len = 0
        v.push(0x00);
        // CipherSuites len = 2 + suite
        v.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        // Compression methods: 1 byte len + null
        v.extend_from_slice(&[0x01, 0x00]);
        // Extensions length placeholder
        let ext_len_off = v.len();
        v.extend_from_slice(&[0, 0]);
        // SNI extension
        v.extend_from_slice(&[0x00, 0x00]); // type
        let inner_off = v.len();
        v.extend_from_slice(&[0, 0]); // length placeholder
                                      // server_name list:
                                      //   list_length(2)  name_type(1)  name_length(2)  name
        let list_payload_len = 1 + 2 + h.len();
        v.extend_from_slice(&(list_payload_len as u16).to_be_bytes());
        v.push(0x00); // host_name
        v.extend_from_slice(&(h.len() as u16).to_be_bytes());
        v.extend_from_slice(h);
        let inner_len = v.len() - inner_off - 2;
        v[inner_off..inner_off + 2].copy_from_slice(&(inner_len as u16).to_be_bytes());
        let total_ext_len = v.len() - ext_len_off - 2;
        v[ext_len_off..ext_len_off + 2].copy_from_slice(&(total_ext_len as u16).to_be_bytes());
        let record_body_len = v.len() - 5;
        v[len_off..len_off + 2].copy_from_slice(&(record_body_len as u16).to_be_bytes());
        v
    }

    #[test]
    fn sniffs_stun_binding() {
        assert_eq!(sniff_udp(&stun_binding()), L7Proto::Stun);
    }

    #[test]
    fn sniffs_dtls_handshake() {
        assert_eq!(sniff_udp(&dtls_handshake()), L7Proto::Dtls);
    }

    #[test]
    fn sniffs_quic_initial() {
        assert_eq!(sniff_udp(&quic_initial()), L7Proto::Quic);
    }

    #[test]
    fn sniffs_tls_sni() {
        let buf = tls_clienthello_sni("example.com");
        match sniff_tcp(&buf) {
            L7Proto::Sni(s) => assert_eq!(s, "example.com"),
            other => panic!("expected SNI, got {:?}", other),
        }
    }

    #[test]
    fn sniffs_http_methods() {
        for m in [
            "GET / HTTP/1.1\r\n",
            "POST /a HTTP/1.1\r\n",
            "CONNECT host:443 HTTP/1.1\r\n",
        ] {
            assert_eq!(sniff_tcp(m.as_bytes()), L7Proto::Http);
        }
    }

    #[test]
    fn webrtc_alias_matches_stun_dtls_quic() {
        assert!(proto_name_matches("webrtc", &L7Proto::Stun));
        assert!(proto_name_matches("webrtc", &L7Proto::Dtls));
        assert!(proto_name_matches("webrtc", &L7Proto::Quic));
        assert!(!proto_name_matches("webrtc", &L7Proto::Http));
        assert!(proto_name_matches("rtc", &L7Proto::Stun));
        assert!(!proto_name_matches("stun", &L7Proto::Dtls));
    }

    #[test]
    fn unknown_payload_is_other() {
        assert_eq!(sniff_udp(b"random garbage data here"), L7Proto::Other);
        assert_eq!(sniff_tcp(b"hi"), L7Proto::Other);
    }
}
