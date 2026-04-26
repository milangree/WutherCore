//! Shadowsocks AEAD 出站 —— 与 mihomo / shadowsocks-rust 互通。
//!
//! 协议：[shadowsocks AEAD specification](https://shadowsocks.org/doc/aead.html)
//!
//! 1. **Subkey**：HKDF-SHA1(EVP_BytesToKey(password) → master_key, salt, "ss-subkey", key_len)
//! 2. **Salt**：发送端首次连接随机生成 N 字节（与 key 等长），明文置于流首。
//! 3. **TCP frame**：`AEAD( length 2B, len_tag 16B ) || AEAD( payload, payload_tag 16B )`。
//! 4. **Nonce**：每加密一次自增（小端 12B）。
//! 5. **首段 payload**：`SOCKS5 ATYP+ADDR+PORT || 真正的应用数据`。
//!
//! 支持的 cipher：
//! * `aes-128-gcm`             —— 16B key, 16B salt, 12B nonce
//! * `aes-256-gcm`             —— 32B key, 32B salt, 12B nonce
//! * `chacha20-ietf-poly1305`  —— 32B key, 32B salt, 12B nonce

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use pin_project_lite::pin_project;
#[allow(unused_imports)]
use sha2 as _;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::{BoxedStream, Capabilities, DialContext, OutboundAdapter};
use crate::proto::addr::encode_socks_addr;
use crate::transport::{tcp::TcpTransport, Transport};

const PAYLOAD_MAX: usize = 0x3fff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsCipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl SsCipher {
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
            Self::Chacha20Poly1305 => 32,
        }
    }
    pub fn tag_len(&self) -> usize { 16 }
    pub fn salt_len(&self) -> usize { self.key_len() }

    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::Chacha20Poly1305),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShadowsocksOutbound {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub cipher: SsCipher,
    pub key: Arc<[u8]>,
    pub udp: bool,
}

impl ShadowsocksOutbound {
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        cipher: SsCipher,
        password: &str,
    ) -> Self {
        let key = evp_bytes_to_key(password.as_bytes(), cipher.key_len());
        Self {
            name: name.into(),
            host: host.into(),
            port,
            cipher,
            key: Arc::from(key.into_boxed_slice()),
            udp: true,
        }
    }
}

#[async_trait]
impl OutboundAdapter for ShadowsocksOutbound {
    fn name(&self) -> &str { &self.name }
    fn protocol(&self) -> &'static str { "shadowsocks" }
    fn capabilities(&self) -> Capabilities {
        Capabilities { tcp: true, udp: self.udp, ipv6: true, multiplex: false }
    }

    async fn dial_tcp(&self, ctx: DialContext) -> std::io::Result<BoxedStream> {
        let mut stream = TcpTransport::default()
            .connect(&self.host, self.port)
            .await?;

        // 1) 发送 salt
        let salt_len = self.cipher.salt_len();
        let mut salt = vec![0u8; salt_len];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        stream.write_all(&salt).await?;

        // 2) 用 subkey 初始化 writer，把 SOCKS5 目标地址作为首段 payload
        let send_key = hkdf_subkey(&self.key, &salt, salt_len);
        let mut writer = SsCryptor::new(self.cipher, &send_key);
        let target = encode_socks_addr(&ctx.host, ctx.port);
        let head_packet = encrypt_chunk(&mut writer, &target)?;
        stream.write_all(&head_packet).await?;

        // 3) 包装成 SS 流（reader 在第一次读取时才拿到对端 salt）
        Ok(Box::pin(SsStream {
            inner: stream,
            send: writer,
            recv_state: RecvState::WaitSalt,
            master: self.key.clone(),
            cipher: self.cipher,
            cipher_buf: BytesMut::with_capacity(16 * 1024),
            plain_buf: BytesMut::with_capacity(16 * 1024),
        }))
    }
}

/* ---------------- AEAD 抽象 ---------------- */

enum Aead12 {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

impl Aead12 {
    fn new(cipher: SsCipher, key: &[u8]) -> Self {
        match cipher {
            SsCipher::Aes128Gcm => Self::Aes128(Aes128Gcm::new_from_slice(key).expect("len")),
            SsCipher::Aes256Gcm => Self::Aes256(Aes256Gcm::new_from_slice(key).expect("len")),
            SsCipher::Chacha20Poly1305 => {
                Self::Chacha(ChaCha20Poly1305::new_from_slice(key).expect("len"))
            }
        }
    }
    fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        let res = match self {
            Self::Aes128(c) => c.encrypt(n, data),
            Self::Aes256(c) => c.encrypt(n, data),
            Self::Chacha(c) => c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), data),
        };
        res.map_err(|_| io_err("ss encrypt failed"))
    }
    fn decrypt(&self, nonce: &[u8; 12], data: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = Nonce::from_slice(nonce);
        let res = match self {
            Self::Aes128(c) => c.decrypt(n, data),
            Self::Aes256(c) => c.decrypt(n, data),
            Self::Chacha(c) => c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), data),
        };
        res.map_err(|_| io_err("ss decrypt failed"))
    }
}

struct SsCryptor {
    aead: Aead12,
    nonce: [u8; 12],
}

impl SsCryptor {
    fn new(cipher: SsCipher, key: &[u8]) -> Self {
        Self { aead: Aead12::new(cipher, key), nonce: [0u8; 12] }
    }
    fn next_nonce(&mut self) -> [u8; 12] {
        let n = self.nonce;
        // little-endian +1
        for b in self.nonce.iter_mut() {
            let (v, c) = b.overflowing_add(1);
            *b = v;
            if !c { break; }
        }
        n
    }
}

fn encrypt_chunk(c: &mut SsCryptor, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let chunk = &data[..data.len().min(PAYLOAD_MAX)];
    let len_buf = (chunk.len() as u16).to_be_bytes();
    let n1 = c.next_nonce();
    let n2 = c.next_nonce();
    let mut out = Vec::with_capacity(2 + 16 + chunk.len() + 16);
    out.extend(c.aead.encrypt(&n1, &len_buf)?);
    out.extend(c.aead.encrypt(&n2, chunk)?);
    Ok(out)
}

/* ---------------- 双向流 ---------------- */

enum RecvState {
    WaitSalt,
    Ready { recv: SsCryptor, expecting_len: Option<usize> },
}

pin_project! {
    struct SsStream {
        #[pin]
        inner: BoxedStream,
        send: SsCryptor,
        recv_state: RecvState,
        master: Arc<[u8]>,
        cipher: SsCipher,
        cipher_buf: BytesMut, // 来自远端的密文
        plain_buf: BytesMut,  // 已解密但尚未交给上层的明文
    }
}

impl AsyncRead for SsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            // 1) 优先把已解密的明文给上层
            if !this.plain_buf.is_empty() {
                let n = std::cmp::min(buf.remaining(), this.plain_buf.len());
                buf.put_slice(&this.plain_buf[..n]);
                this.plain_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // 2) 尝试从 cipher_buf 解密下一段
            match try_decrypt_step(
                &mut *this.recv_state,
                this.master,
                *this.cipher,
                this.cipher_buf,
                this.plain_buf,
            )? {
                StepResult::Produced => continue,
                StepResult::NeedMore => {}
            }

            // 3) 读更多密文
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match this.inner.as_mut().poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled().len();
                    if filled == 0 {
                        return Poll::Ready(Ok(())); // EOF
                    }
                    this.cipher_buf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

enum StepResult { Produced, NeedMore }

fn try_decrypt_step(
    state: &mut RecvState,
    master: &Arc<[u8]>,
    cipher: SsCipher,
    cipher_buf: &mut BytesMut,
    plain_buf: &mut BytesMut,
) -> std::io::Result<StepResult> {
    match state {
        RecvState::WaitSalt => {
            let salt_len = cipher.salt_len();
            if cipher_buf.len() < salt_len {
                return Ok(StepResult::NeedMore);
            }
            let salt = cipher_buf.split_to(salt_len);
            let subkey = hkdf_subkey(master, &salt, salt_len);
            *state = RecvState::Ready {
                recv: SsCryptor::new(cipher, &subkey),
                expecting_len: None,
            };
            Ok(StepResult::Produced) // 让 outer loop 再走一次
        }
        RecvState::Ready { recv, expecting_len } => {
            let tag = cipher.tag_len();
            // 阶段 A：未知 length
            if expecting_len.is_none() {
                if cipher_buf.len() < 2 + tag {
                    return Ok(StepResult::NeedMore);
                }
                let n1 = recv.next_nonce();
                let dec = recv.aead.decrypt(&n1, &cipher_buf[..2 + tag])?;
                let length = u16::from_be_bytes([dec[0], dec[1]]) as usize;
                cipher_buf.advance(2 + tag);
                *expecting_len = Some(length);
            }
            // 阶段 B：已知 length，等 payload + tag
            let length = expecting_len.expect("just set");
            if cipher_buf.len() < length + tag {
                return Ok(StepResult::NeedMore);
            }
            let n2 = recv.next_nonce();
            let payload = recv.aead.decrypt(&n2, &cipher_buf[..length + tag])?;
            cipher_buf.advance(length + tag);
            plain_buf.extend_from_slice(&payload);
            *expecting_len = None;
            Ok(StepResult::Produced)
        }
    }
}

impl AsyncWrite for SsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        // 单次最多写一个 PAYLOAD_MAX；上层若给更多，由它 loop。
        let chunk = &data[..data.len().min(PAYLOAD_MAX)];
        let packet = encrypt_chunk(this.send, chunk)?;
        let mut written = 0;
        while written < packet.len() {
            match this.inner.as_mut().poll_write(cx, &packet[written..]) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => written += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(chunk.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

fn io_err(s: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, s)
}

/* ---------------- 密钥派生 ---------------- */

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    // OpenSSL EVP_BytesToKey with MD5, no salt, count=1
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        let digest = h.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

fn hkdf_subkey(master: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; len];
    hk.expand(b"ss-subkey", &mut okm).expect("hkdf");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_kdf_aes_256_deterministic() {
        let k = evp_bytes_to_key(b"hello", 32);
        let k2 = evp_bytes_to_key(b"hello", 32);
        assert_eq!(k, k2);
        assert_eq!(k.len(), 32);
    }

    #[test]
    fn cipher_parse_works() {
        assert_eq!(SsCipher::parse("AES-256-GCM"), Some(SsCipher::Aes256Gcm));
        assert_eq!(SsCipher::parse("chacha20-ietf-poly1305"), Some(SsCipher::Chacha20Poly1305));
        assert_eq!(SsCipher::parse("rc4"), None);
    }

    #[test]
    fn aead_chunk_round_trip() {
        let key = evp_bytes_to_key(b"pwd", 32);
        let salt = [7u8; 32];
        let subkey = hkdf_subkey(&key, &salt, 32);
        let mut send = SsCryptor::new(SsCipher::Aes256Gcm, &subkey);
        let mut recv = SsCryptor::new(SsCipher::Aes256Gcm, &subkey);
        // 写一段
        let pkt = encrypt_chunk(&mut send, b"hello world").unwrap();
        // 解 length
        let n1 = recv.next_nonce();
        let dec_len = recv.aead.decrypt(&n1, &pkt[..2 + 16]).unwrap();
        let length = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;
        assert_eq!(length, 11);
        let n2 = recv.next_nonce();
        let dec = recv.aead.decrypt(&n2, &pkt[2 + 16..]).unwrap();
        assert_eq!(dec, b"hello world");
    }
}
