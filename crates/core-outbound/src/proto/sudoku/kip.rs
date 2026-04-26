//! Sudoku KIP 握手协议 —— 与 mihomo `transport/sudoku/kip.go` + `handshake_kip.go` 等价。
//!
//! ## 消息格式
//! ```text
//! magic(3) = "kip"
//! type(1)
//! length(2 BE)
//! payload(length)
//! ```
//!
//! ## ClientHello payload
//! ```text
//! timestamp_unix(8 BE) || user_hash(8) || nonce(16) || client_pub(32)
//! || features(4 BE) || [table_hint(4 BE)]?
//! ```
//!
//! ## ServerHello payload
//! ```text
//! nonce(16) || server_pub(32) || selected_features(4 BE)
//! ```
//!
//! ## 鉴权流程
//! 1. 客户端：发送 ClientHello (含 X25519 ephemeral pub)
//! 2. 服务器：用 X25519 + 同一 nonce 派生会话密钥，发回 ServerHello
//! 3. 客户端校验 nonce 一致，用 X25519 共享秘密派生会话密钥
//! 4. 双方 rekey RecordConn

use bytes::{Buf, BufMut};
use curve25519_dalek::{montgomery::MontgomeryPoint, scalar::Scalar};
use hex::ToHex;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

const KIP_MAGIC: &[u8; 3] = b"kip";

pub const KIP_TYPE_CLIENT_HELLO: u8 = 0x01;
pub const KIP_TYPE_SERVER_HELLO: u8 = 0x02;
pub const KIP_TYPE_OPEN_TCP: u8 = 0x10;
pub const KIP_TYPE_START_MUX: u8 = 0x11;
pub const KIP_TYPE_START_UOT: u8 = 0x12;
pub const KIP_TYPE_KEEPALIVE: u8 = 0x14;

pub const KIP_FEAT_OPEN_TCP: u32 = 1 << 0;
pub const KIP_FEAT_MUX: u32 = 1 << 1;
pub const KIP_FEAT_UOT: u32 = 1 << 2;
pub const KIP_FEAT_KEEPALIVE: u32 = 1 << 4;
pub const KIP_FEAT_ALL: u32 =
    KIP_FEAT_OPEN_TCP | KIP_FEAT_MUX | KIP_FEAT_UOT | KIP_FEAT_KEEPALIVE;

pub const KIP_HELLO_USER_HASH_SIZE: usize = 8;
pub const KIP_HELLO_NONCE_SIZE: usize = 16;
pub const KIP_HELLO_PUB_SIZE: usize = 32;
pub const KIP_MAX_PAYLOAD: usize = 64 * 1024;
pub const KIP_HANDSHAKE_SKEW_SECS: i64 = 60;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct KIPMessage {
    pub typ: u8,
    pub payload: Vec<u8>,
}

pub fn encode_kip_message(typ: u8, payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > KIP_MAX_PAYLOAD {
        return Err(format!("kip payload too large: {}", payload.len()));
    }
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(KIP_MAGIC);
    out.push(typ);
    out.put_u16(payload.len() as u16);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn parse_kip_message(buf: &[u8]) -> Result<(usize, KIPMessage), String> {
    if buf.len() < 6 {
        return Err("kip header underflow".into());
    }
    if &buf[..3] != KIP_MAGIC {
        return Err("kip bad magic".into());
    }
    let typ = buf[3];
    let n = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if n > KIP_MAX_PAYLOAD {
        return Err(format!("kip payload too large: {n}"));
    }
    if buf.len() < 6 + n {
        return Err("kip body underflow".into());
    }
    Ok((
        6 + n,
        KIPMessage {
            typ,
            payload: buf[6..6 + n].to_vec(),
        },
    ))
}

#[derive(Debug, Clone)]
pub struct KIPClientHello {
    pub timestamp_unix: i64,
    pub user_hash: [u8; KIP_HELLO_USER_HASH_SIZE],
    pub nonce: [u8; KIP_HELLO_NONCE_SIZE],
    pub client_pub: [u8; KIP_HELLO_PUB_SIZE],
    pub features: u32,
    pub table_hint: u32,
    pub has_table_hint: bool,
}

impl KIPClientHello {
    pub fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.put_u64(self.timestamp_unix as u64);
        out.extend_from_slice(&self.user_hash);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.client_pub);
        out.put_u32(self.features);
        if self.has_table_hint {
            out.put_u32(self.table_hint);
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct KIPServerHello {
    pub nonce: [u8; KIP_HELLO_NONCE_SIZE],
    pub server_pub: [u8; KIP_HELLO_PUB_SIZE],
    pub selected_feats: u32,
}

pub fn parse_server_hello(payload: &[u8]) -> Result<KIPServerHello, String> {
    let want = KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE + 4;
    if payload.len() != want {
        return Err(format!("server hello bad len: {}", payload.len()));
    }
    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    nonce.copy_from_slice(&payload[..KIP_HELLO_NONCE_SIZE]);
    let mut server_pub = [0u8; KIP_HELLO_PUB_SIZE];
    server_pub.copy_from_slice(
        &payload[KIP_HELLO_NONCE_SIZE..KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE],
    );
    let off = KIP_HELLO_NONCE_SIZE + KIP_HELLO_PUB_SIZE;
    let selected_feats = u32::from_be_bytes([
        payload[off],
        payload[off + 1],
        payload[off + 2],
        payload[off + 3],
    ]);
    Ok(KIPServerHello {
        nonce,
        server_pub,
        selected_feats,
    })
}

pub fn user_hash_from_key(key: &str) -> [u8; KIP_HELLO_USER_HASH_SIZE] {
    let trimmed = key.trim();
    let mut out = [0u8; KIP_HELLO_USER_HASH_SIZE];
    if trimmed.is_empty() {
        return out;
    }
    if let Ok(bytes) = hex::decode(trimmed) {
        if !bytes.is_empty() {
            let h = Sha256::digest(&bytes);
            out.copy_from_slice(&h[..KIP_HELLO_USER_HASH_SIZE]);
            return out;
        }
    }
    let h = Sha256::digest(trimmed.as_bytes());
    out.copy_from_slice(&h[..KIP_HELLO_USER_HASH_SIZE]);
    out
}

pub fn user_hash_hex_from_key(key: &str) -> String {
    user_hash_from_key(key).encode_hex::<String>()
}

/// 计算 X25519 共享秘密
pub fn x25519_shared(priv_scalar: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let mut s = *priv_scalar;
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    let scalar = Scalar::from_bytes_mod_order(s);
    let p = MontgomeryPoint(*peer_pub);
    (scalar * p).0
}

pub fn x25519_pub(priv_scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519_shared(priv_scalar, &base)
}

/// 派生 PSK 方向密钥
pub fn derive_psk_directional_bases(psk: &str) -> ([u8; 32], [u8; 32]) {
    let sum = Sha256::digest(psk.as_bytes());
    let c2s = hkdf_expand(&sum, b"sudoku-psk-c2s", 32);
    let s2c = hkdf_expand(&sum, b"sudoku-psk-s2c", 32);
    let mut c2s_arr = [0u8; 32];
    c2s_arr.copy_from_slice(&c2s);
    let mut s2c_arr = [0u8; 32];
    s2c_arr.copy_from_slice(&s2c);
    (c2s_arr, s2c_arr)
}

pub fn derive_session_directional_bases(
    psk: &str,
    shared: &[u8],
    nonce: &[u8; KIP_HELLO_NONCE_SIZE],
) -> ([u8; 32], [u8; 32]) {
    let sum = Sha256::digest(psk.as_bytes());
    let mut ikm = Vec::with_capacity(shared.len() + nonce.len());
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(nonce);

    // HKDF-Extract: prk = HMAC(salt=sum, ikm)
    let mut mac = HmacSha256::new_from_slice(&sum).expect("hmac salt");
    mac.update(&ikm);
    let prk_bytes = mac.finalize().into_bytes();
    let prk_arr: [u8; 32] = prk_bytes.into();

    let c2s = hkdf_expand(&prk_arr, b"sudoku-session-c2s", 32);
    let s2c = hkdf_expand(&prk_arr, b"sudoku-session-s2c", 32);
    let mut c2s_arr = [0u8; 32];
    c2s_arr.copy_from_slice(&c2s);
    let mut s2c_arr = [0u8; 32];
    s2c_arr.copy_from_slice(&s2c);
    (c2s_arr, s2c_arr)
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        let mut mac = HmacSha256::new_from_slice(prk).expect("hmac prk");
        mac.update(&prev);
        mac.update(info);
        mac.update(&[i]);
        let r = mac.finalize().into_bytes();
        out.extend_from_slice(&r);
        prev = r.to_vec();
        i = i.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// 服务器 AEAD seed —— 与 mihomo ServerAEADSeed 等价（直接用 key）
pub fn server_aead_seed(key: &str) -> &str {
    key
}

/// 客户端 AEAD seed
pub fn client_aead_seed(key: &str) -> &str {
    key
}

pub fn random_nonce() -> [u8; KIP_HELLO_NONCE_SIZE] {
    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn random_x25519_priv() -> [u8; 32] {
    let mut priv_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut priv_key);
    priv_key[0] &= 248;
    priv_key[31] &= 127;
    priv_key[31] |= 64;
    priv_key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kip_message_round_trip() {
        let buf = encode_kip_message(KIP_TYPE_CLIENT_HELLO, b"hello").unwrap();
        let (consumed, msg) = parse_kip_message(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(msg.typ, KIP_TYPE_CLIENT_HELLO);
        assert_eq!(msg.payload, b"hello");
    }

    #[test]
    fn kip_bad_magic() {
        let buf = b"xxx\x01\x00\x00\x00";
        assert!(parse_kip_message(buf).is_err());
    }

    #[test]
    fn user_hash_deterministic() {
        let h1 = user_hash_from_key("mykey");
        let h2 = user_hash_from_key("mykey");
        assert_eq!(h1, h2);
        let h3 = user_hash_from_key("other");
        assert_ne!(h1, h3);
    }

    #[test]
    fn user_hash_hex_format() {
        let s = user_hash_hex_from_key("test");
        assert_eq!(s.len(), 16); // 8 bytes * 2 hex chars
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn x25519_dh_consistency() {
        let mut a_priv = [0u8; 32];
        let mut b_priv = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut a_priv);
        rand::rngs::OsRng.fill_bytes(&mut b_priv);
        let a_pub = x25519_pub(&a_priv);
        let b_pub = x25519_pub(&b_priv);
        let s_ab = x25519_shared(&a_priv, &b_pub);
        let s_ba = x25519_shared(&b_priv, &a_pub);
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn psk_keys_distinct_directions() {
        let (c2s, s2c) = derive_psk_directional_bases("test-key");
        assert_ne!(c2s, s2c);
        assert_eq!(c2s.len(), 32);
        assert_eq!(s2c.len(), 32);
    }

    #[test]
    fn session_keys_distinct_directions() {
        let nonce = [0xaau8; 16];
        let shared = [0x42u8; 32];
        let (c2s, s2c) = derive_session_directional_bases("psk", &shared, &nonce);
        assert_ne!(c2s, s2c);
    }

    #[test]
    fn client_hello_payload_format() {
        let h = KIPClientHello {
            timestamp_unix: 1700000000,
            user_hash: [1; 8],
            nonce: [2; 16],
            client_pub: [3; 32],
            features: KIP_FEAT_ALL,
            table_hint: 0xdeadbeef,
            has_table_hint: true,
        };
        let p = h.encode_payload();
        assert_eq!(p.len(), 8 + 8 + 16 + 32 + 4 + 4);
    }

    #[test]
    fn server_hello_parse_round_trip() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xaau8; 16]);
        payload.extend_from_slice(&[0xbbu8; 32]);
        payload.put_u32(KIP_FEAT_OPEN_TCP | KIP_FEAT_MUX);
        let sh = parse_server_hello(&payload).unwrap();
        assert_eq!(sh.nonce, [0xaau8; 16]);
        assert_eq!(sh.server_pub, [0xbbu8; 32]);
        assert_eq!(sh.selected_feats, KIP_FEAT_OPEN_TCP | KIP_FEAT_MUX);
    }
}
