//! rustls + webpki-roots 的 TLS 客户端。

use std::sync::Arc;

use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::adapter::BoxedStream;
use crate::transport::{TlsOptions, Transport};

#[derive(Debug, Clone)]
pub struct TlsTransport {
    pub options: TlsOptions,
    config: Arc<ClientConfig>,
}

impl TlsTransport {
    pub fn new(options: TlsOptions) -> Self {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        if !options.alpn.is_empty() {
            cfg.alpn_protocols = options.alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        }
        if options.insecure {
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoVerify));
        }
        Self {
            options,
            config: Arc::new(cfg),
        }
    }
}

#[async_trait]
impl Transport for TlsTransport {
    async fn connect(&self, host: &str, port: u16) -> std::io::Result<BoxedStream> {
        let sni_str: String = self
            .options
            .sni
            .clone()
            .unwrap_or_else(|| host.to_string());
        let dns: ServerName<'static> = ServerName::try_from(sni_str.clone()).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("非法 SNI: {sni_str} ({e})"),
            )
        })?;
        let tcp = TcpStream::connect((host, port)).await?;
        let _ = tcp.set_nodelay(true);
        let connector = TlsConnector::from(self.config.clone());
        let stream = connector.connect(dns, tcp).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("TLS handshake: {e}"))
        })?;
        Ok(Box::pin(stream))
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
