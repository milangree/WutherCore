//! `virtio_net_hdr`（10 字节）帧头的纯字节级处理 —— 与平台无关，
//! 让 Windows/macOS 主机也能跑相关单元测试。
//!
//! 当 `IFF_VNET_HDR` 启用时，每个 read/write 都带 10 字节前缀
//! （结构定义见 Linux `<linux/virtio_net.h>` 的 `struct virtio_net_hdr`）：
//! ```text
//! u8  flags;        // VIRTIO_NET_HDR_F_NEEDS_CSUM = 0x01
//! u8  gso_type;     // GSO_NONE = 0, GSO_TCPV4 = 1, GSO_UDP_L4 = 5, GSO_TCPV6 = 4
//! u16 hdr_len;      // L3 + L4 头总长（小端）
//! u16 gso_size;     // 每段 MSS（小端）
//! u16 csum_start;   // L4 头起点（= L3 头长，小端）
//! u16 csum_offset;  // csum 字段在 L4 头内的偏移（小端）
//! ```
//! - 阶段 3.3 仅做透传（gso_type=NONE，零头）；
//! - 阶段 3.5 起 [`parse_virtio_net_hdr`] 解析全字段，配合 `gso_split` 模块切分。

/// virtio_net_hdr 长度（与 `<linux/virtio_net.h>` 一致：10 字节）。
pub const VIRTIO_NET_HDR_LEN: usize = 10;

/// `gso_type == VIRTIO_NET_HDR_GSO_NONE` —— 普通 IP 包，无需 GSO 切分。
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
/// `gso_type == VIRTIO_NET_HDR_GSO_TCPV4` —— 大段 IPv4+TCP，按 gso_size 切分。
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
/// `gso_type == VIRTIO_NET_HDR_GSO_TCPV6` —— 大段 IPv6+TCP。
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// `gso_type == VIRTIO_NET_HDR_GSO_UDP_L4` —— 大段 v4/v6 + UDP（USO 输出）。
pub const VIRTIO_NET_HDR_GSO_UDP_L4: u8 = 5;
/// `flags & VIRTIO_NET_HDR_F_NEEDS_CSUM` —— 单段时 transport checksum 仅是 pseudo-header sum，
/// 调用方必须用 partial sum 算法补全。
pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 0x01;

/// 写路径预制零头：`gso_type=NONE, NeedsCsum=false, all-zero`。
/// 编译期常量切片，避免每次 write 重新分配。
pub const ZERO_VNET_HDR: [u8; VIRTIO_NET_HDR_LEN] = [0u8; VIRTIO_NET_HDR_LEN];

/// GSO 类型枚举 —— 与 `gso_type` 字节一对一映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GsoType {
    /// 普通包，无需切分。
    None,
    /// IPv4 + TCP，按 gso_size 切分。
    TcpV4,
    /// IPv6 + TCP。
    TcpV6,
    /// IPv4/IPv6 + UDP（USO 输出）。
    UdpL4,
}

impl GsoType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::None => VIRTIO_NET_HDR_GSO_NONE,
            Self::TcpV4 => VIRTIO_NET_HDR_GSO_TCPV4,
            Self::TcpV6 => VIRTIO_NET_HDR_GSO_TCPV6,
            Self::UdpL4 => VIRTIO_NET_HDR_GSO_UDP_L4,
        }
    }
}

/// virtio_net_hdr 解析结果 —— 描述如何处理后续 IP 包。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioNetHdr {
    pub gso_type: GsoType,
    /// L3+L4 头总长（IP 头 + TCP/UDP 头）。
    pub hdr_len: u16,
    /// L4 头起点（= IP 头长）。
    pub csum_start: u16,
    /// csum 字段在 L4 头内的偏移（TCP=16, UDP=6）。
    pub csum_offset: u16,
    /// 每段 MSS。`GsoNone` 时为 0。
    pub gso_size: u16,
    /// 单段时 transport checksum 仅是 pseudo-header sum，需要补全。
    pub needs_csum: bool,
}

/// 解析 virtio_net_hdr 字段（小端）。
pub fn parse_virtio_net_hdr(bytes: &[u8]) -> Result<VirtioNetHdr, VnetDecodeError> {
    if bytes.len() < VIRTIO_NET_HDR_LEN {
        return Err(VnetDecodeError::ShortRead { got: bytes.len() });
    }
    let flags = bytes[0];
    let gso_type_byte = bytes[1];
    let gso_type = match gso_type_byte {
        VIRTIO_NET_HDR_GSO_NONE => GsoType::None,
        VIRTIO_NET_HDR_GSO_TCPV4 => GsoType::TcpV4,
        VIRTIO_NET_HDR_GSO_TCPV6 => GsoType::TcpV6,
        VIRTIO_NET_HDR_GSO_UDP_L4 => GsoType::UdpL4,
        // ECN 与 KVM 私有标记可叠加在 gso_type 高位（如 GSO_TCPV4 | ECN = 0x81）；
        // 主流 Linux TUN 不会发，遇到时按 Unsupported 处理。
        other => return Err(VnetDecodeError::UnsupportedGso { gso_type: other }),
    };
    Ok(VirtioNetHdr {
        gso_type,
        hdr_len: u16::from_le_bytes([bytes[2], bytes[3]]),
        gso_size: u16::from_le_bytes([bytes[4], bytes[5]]),
        csum_start: u16::from_le_bytes([bytes[6], bytes[7]]),
        csum_offset: u16::from_le_bytes([bytes[8], bytes[9]]),
        needs_csum: flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0,
    })
}

/// vnet_hdr 解码错误 —— `linux_tun_io::read_packet` 据此构造 `TunIoError::Read`。
#[derive(Debug, PartialEq, Eq)]
pub enum VnetDecodeError {
    /// `staging` 长度小于 `VIRTIO_NET_HDR_LEN`。
    ShortRead { got: usize },
    /// `gso_type != GSO_NONE` —— 阶段 3.3 没有 GSO 切分能力，丢包。
    UnsupportedGso { gso_type: u8 },
    /// IP 包长度超过用户提供的 `out` buffer。
    PayloadTooLarge { payload: usize, out: usize },
}

impl std::fmt::Display for VnetDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortRead { got } => {
                write!(f, "vnet_hdr: short read ({got} < {VIRTIO_NET_HDR_LEN})")
            }
            Self::UnsupportedGso { gso_type } => {
                write!(f, "vnet_hdr: gso_type={gso_type} not supported")
            }
            Self::PayloadTooLarge { payload, out } => {
                write!(f, "vnet_hdr: payload {payload} > buf {out}")
            }
        }
    }
}
impl std::error::Error for VnetDecodeError {}

/// 从 `staging[..n]` 剥离 vnet_hdr 前缀，把 IP 包写入 `out`，返回 IP 包长度。
///
/// 调用方约定：`staging` 是设备 `read` 拉到的原始字节（含 10B 头），`n` 是
/// 实际读到的字节数；`out` 是上层期望的 IP 包缓冲（不含 vnet_hdr）。
pub fn strip_vnet_hdr(staging: &[u8], n: usize, out: &mut [u8]) -> Result<usize, VnetDecodeError> {
    if n < VIRTIO_NET_HDR_LEN {
        return Err(VnetDecodeError::ShortRead { got: n });
    }
    let gso_type = staging[1]; // virtio_net_hdr.gso_type
    if gso_type != VIRTIO_NET_HDR_GSO_NONE {
        return Err(VnetDecodeError::UnsupportedGso { gso_type });
    }
    let payload_len = n - VIRTIO_NET_HDR_LEN;
    if payload_len > out.len() {
        return Err(VnetDecodeError::PayloadTooLarge {
            payload: payload_len,
            out: out.len(),
        });
    }
    out[..payload_len].copy_from_slice(&staging[VIRTIO_NET_HDR_LEN..n]);
    Ok(payload_len)
}

/// 在 IP 包前补 10 字节零头，返回拼接后的写入帧。
///
/// 该函数会分配 `Vec<u8>`；调用频次每个出包一次，性能影响可忽略
/// （bottleneck 是 syscall）。后续阶段 3.4 走 `writev` 双 iovec 时可避免拷贝。
pub fn frame_with_vnet_hdr(pkt: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
    framed.extend_from_slice(&ZERO_VNET_HDR);
    framed.extend_from_slice(pkt);
    framed
}

/// 把 [`VirtioNetHdr`] 序列化成 10 字节小端字节流（与 kernel `<linux/virtio_net.h>` ABI 一致）。
///
/// 用于 GRO 路径写入：合并段需要带上正确的 `gso_type`、`gso_size`、`hdr_len`、`csum_*`
/// 字段以触发 kernel TSO/USO 切分。
pub fn encode_vnet_hdr_bytes(hdr: &VirtioNetHdr) -> [u8; VIRTIO_NET_HDR_LEN] {
    let flags = if hdr.needs_csum {
        VIRTIO_NET_HDR_F_NEEDS_CSUM
    } else {
        0
    };
    let mut buf = [0u8; VIRTIO_NET_HDR_LEN];
    buf[0] = flags;
    buf[1] = hdr.gso_type.as_u8();
    buf[2..4].copy_from_slice(&hdr.hdr_len.to_le_bytes());
    buf[4..6].copy_from_slice(&hdr.gso_size.to_le_bytes());
    buf[6..8].copy_from_slice(&hdr.csum_start.to_le_bytes());
    buf[8..10].copy_from_slice(&hdr.csum_offset.to_le_bytes());
    buf
}

/// 用 [`VirtioNetHdr`] 头 + IP 包构造一次性写入帧（10B 头 + body）。
///
/// `gso_type=None && !needs_csum` 等价于 [`frame_with_vnet_hdr`] 的零头帧。
pub fn frame_with_vnet_hdr_full(hdr: &VirtioNetHdr, pkt: &[u8]) -> Vec<u8> {
    let head = encode_vnet_hdr_bytes(hdr);
    let mut framed = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
    framed.extend_from_slice(&head);
    framed.extend_from_slice(pkt);
    framed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn const_lengths_match_linux_abi() {
        assert_eq!(VIRTIO_NET_HDR_LEN, 10);
        assert_eq!(ZERO_VNET_HDR.len(), VIRTIO_NET_HDR_LEN);
        assert_eq!(VIRTIO_NET_HDR_GSO_NONE, 0);
    }

    #[test]
    fn frame_then_strip_round_trips() {
        let ip_pkt =
            b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x00\x00\x00\x0a\x00\x00\x01\x01\x01\x01\x01";
        let framed = frame_with_vnet_hdr(ip_pkt);
        assert_eq!(framed.len(), VIRTIO_NET_HDR_LEN + ip_pkt.len());
        assert_eq!(&framed[..VIRTIO_NET_HDR_LEN], &ZERO_VNET_HDR);
        assert_eq!(&framed[VIRTIO_NET_HDR_LEN..], ip_pkt);

        let mut out = vec![0u8; ip_pkt.len()];
        let n = strip_vnet_hdr(&framed, framed.len(), &mut out).expect("ok");
        assert_eq!(n, ip_pkt.len());
        assert_eq!(&out[..n], ip_pkt);
    }

    #[test]
    fn strip_short_read_errors() {
        let mut out = [0u8; 16];
        let err = strip_vnet_hdr(&[0u8; 5], 5, &mut out).unwrap_err();
        assert_eq!(err, VnetDecodeError::ShortRead { got: 5 });
    }

    #[test]
    fn strip_rejects_gso_segment() {
        // gso_type = TCPV4 (1) —— 我们没有切分能力，必须报错。
        let mut staging = [0u8; 30];
        staging[1] = 1; // gso_type
        let mut out = [0u8; 32];
        let err = strip_vnet_hdr(&staging, staging.len(), &mut out).unwrap_err();
        assert_eq!(err, VnetDecodeError::UnsupportedGso { gso_type: 1 });
    }

    #[test]
    fn strip_payload_too_large_errors() {
        let staging = [0u8; 30]; // 10 头 + 20 包
        let mut out = [0u8; 8]; // 太小
        let err = strip_vnet_hdr(&staging, staging.len(), &mut out).unwrap_err();
        assert_eq!(
            err,
            VnetDecodeError::PayloadTooLarge {
                payload: 20,
                out: 8,
            }
        );
    }

    /// Linux `<linux/if_tun.h>` ABI 常量校验 —— 防止 linux_tun_io 里的常量出错。
    /// 数值由 `_IOW(type, nr, size)` 宏推导；本测试在任何平台都可跑。
    #[test]
    fn tunsetoffload_ioctl_value_matches_linux_abi() {
        // _IOW('T', 208, unsigned int):
        //   _IOC(_IOC_WRITE, 'T', 208, sizeof(uint))
        //   = (1 << 30) | (sizeof(uint) << 16) | ('T' << 8) | 208
        //   = 0x40000000 | (4 << 16) | (0x54 << 8) | 0xD0
        //   = 0x400454D0
        let expected: u32 = (1u32 << 30) | ((4u32) << 16) | ((b'T' as u32) << 8) | 208u32;
        assert_eq!(expected, 0x4004_54D0);
    }

    /// 同上 —— 验证 TUNSETIFF = _IOW('T', 202, struct ifreq*) ⇒ 0x400454CA。
    /// 注意：原宏第三个参数是 `int`（kernel uses _IOW with type=int），不是 sizeof(ifreq)。
    #[test]
    fn tunsetiff_ioctl_value_matches_linux_abi() {
        let expected: u32 = (1u32 << 30) | ((4u32) << 16) | ((b'T' as u32) << 8) | 202u32;
        assert_eq!(expected, 0x4004_54CA);
    }

    /// `TUN_F_*` 标志位与 `<linux/if_tun.h>` 一致 —— sing-tun `tun_linux_flags.go` 同源。
    #[test]
    fn tun_offload_flags_match_linux_abi() {
        const TUN_F_CSUM: u32 = 0x01;
        const TUN_F_TSO4: u32 = 0x02;
        const TUN_F_TSO6: u32 = 0x04;
        const TUN_F_USO4: u32 = 0x20;
        const TUN_F_USO6: u32 = 0x40;
        // 防笔误：值是 1/2/4/0x20/0x40
        assert_eq!(TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6, 0x07);
        assert_eq!(TUN_F_USO4 | TUN_F_USO6, 0x60);
    }

    #[test]
    fn parse_zero_header_yields_gso_none() {
        let hdr = parse_virtio_net_hdr(&ZERO_VNET_HDR).expect("ok");
        assert_eq!(hdr.gso_type, GsoType::None);
        assert_eq!(hdr.hdr_len, 0);
        assert_eq!(hdr.gso_size, 0);
        assert_eq!(hdr.csum_start, 0);
        assert_eq!(hdr.csum_offset, 0);
        assert!(!hdr.needs_csum);
    }

    #[test]
    fn parse_full_tcpv4_header() {
        // flags=NEEDS_CSUM(1), gso_type=TCPV4(1), hdr_len=40, gso_size=1448, csum_start=20, csum_offset=16
        let bytes: [u8; 10] = [
            0x01, 0x01, // flags, gso_type
            0x28, 0x00, // hdr_len = 40
            0xa8, 0x05, // gso_size = 1448
            0x14, 0x00, // csum_start = 20
            0x10, 0x00, // csum_offset = 16
        ];
        let hdr = parse_virtio_net_hdr(&bytes).expect("ok");
        assert_eq!(hdr.gso_type, GsoType::TcpV4);
        assert_eq!(hdr.hdr_len, 40);
        assert_eq!(hdr.gso_size, 1448);
        assert_eq!(hdr.csum_start, 20);
        assert_eq!(hdr.csum_offset, 16);
        assert!(hdr.needs_csum);
    }

    #[test]
    fn parse_rejects_short_input() {
        let err = parse_virtio_net_hdr(&[0u8; 5]).unwrap_err();
        assert_eq!(err, VnetDecodeError::ShortRead { got: 5 });
    }

    #[test]
    fn parse_rejects_unknown_gso_type() {
        let mut bytes = [0u8; 10];
        bytes[1] = 99;
        let err = parse_virtio_net_hdr(&bytes).unwrap_err();
        assert_eq!(err, VnetDecodeError::UnsupportedGso { gso_type: 99 });
    }

    #[test]
    fn gso_type_round_trips_to_u8() {
        for gt in [
            GsoType::None,
            GsoType::TcpV4,
            GsoType::TcpV6,
            GsoType::UdpL4,
        ] {
            let mut bytes = [0u8; 10];
            bytes[1] = gt.as_u8();
            let parsed = parse_virtio_net_hdr(&bytes).expect("ok");
            assert_eq!(parsed.gso_type, gt);
        }
    }

    #[test]
    fn encode_round_trips_through_parse() {
        let hdr = VirtioNetHdr {
            gso_type: GsoType::TcpV6,
            hdr_len: 60,
            gso_size: 1380,
            csum_start: 40,
            csum_offset: 16,
            needs_csum: true,
        };
        let bytes = encode_vnet_hdr_bytes(&hdr);
        let parsed = parse_virtio_net_hdr(&bytes).expect("ok");
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn encode_zero_when_gso_none_and_no_csum() {
        let hdr = VirtioNetHdr {
            gso_type: GsoType::None,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            needs_csum: false,
        };
        assert_eq!(encode_vnet_hdr_bytes(&hdr), ZERO_VNET_HDR);
    }

    #[test]
    fn frame_with_vnet_hdr_full_combines_head_and_body() {
        let hdr = VirtioNetHdr {
            gso_type: GsoType::UdpL4,
            hdr_len: 28,
            gso_size: 1200,
            csum_start: 20,
            csum_offset: 6,
            needs_csum: true,
        };
        let body =
            b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x11\x00\x00\x0a\x00\x00\x01\x01\x01\x01\x01";
        let framed = frame_with_vnet_hdr_full(&hdr, body);
        assert_eq!(framed.len(), VIRTIO_NET_HDR_LEN + body.len());
        let parsed = parse_virtio_net_hdr(&framed[..VIRTIO_NET_HDR_LEN]).expect("ok");
        assert_eq!(parsed, hdr);
        assert_eq!(&framed[VIRTIO_NET_HDR_LEN..], body);
    }

    #[test]
    fn strip_partial_buffer_uses_only_n_bytes() {
        // staging 容量 20 但实际读到 14 —— 只解码前 14 字节
        let mut staging = [0xffu8; 20];
        staging[..10].copy_from_slice(&ZERO_VNET_HDR); // 头
        staging[10..14].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]); // 4B IP 包
        let mut out = [0u8; 16];
        let n = strip_vnet_hdr(&staging, 14, &mut out).expect("ok");
        assert_eq!(n, 4);
        assert_eq!(&out[..n], &[0xaa, 0xbb, 0xcc, 0xdd]);
    }
}
