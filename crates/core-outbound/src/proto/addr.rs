//! 公共：SOCKS5/Trojan/Shadowsocks 通用的"目标地址"编码。
//!
//! 三个协议都用同一种格式：ATYP(1) + ADDR(变长) + PORT(2 BE)。

use bytes::BufMut;

#[derive(Debug, Clone)]
pub enum Address<'a> {
    Domain(&'a str),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl<'a> Address<'a> {
    pub fn parse(host: &'a str) -> Self {
        if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            return Address::Ipv4(ip.octets());
        }
        if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
            return Address::Ipv6(ip.octets());
        }
        Address::Domain(host)
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Domain(d) => 1 + 1 + d.len() + 2,
            Self::Ipv4(_) => 1 + 4 + 2,
            Self::Ipv6(_) => 1 + 16 + 2,
        }
    }

    pub fn encode(&self, port: u16, out: &mut Vec<u8>) {
        match self {
            Self::Ipv4(b) => {
                out.put_u8(0x01);
                out.extend_from_slice(b);
            }
            Self::Domain(d) => {
                let bytes = d.as_bytes();
                let len = bytes.len().min(255);
                out.put_u8(0x03);
                out.put_u8(len as u8);
                out.extend_from_slice(&bytes[..len]);
            }
            Self::Ipv6(b) => {
                out.put_u8(0x04);
                out.extend_from_slice(b);
            }
        }
        out.put_u16(port);
    }
}

pub fn encode_socks_addr(host: &str, port: u16) -> Vec<u8> {
    let a = Address::parse(host);
    let mut buf = Vec::with_capacity(a.encoded_len());
    a.encode(port, &mut buf);
    buf
}
