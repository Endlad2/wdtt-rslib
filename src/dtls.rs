// SPDX-License-Identifier: LGPL-2.1
//
//! DTLS client over the obfuscated TURN transport.
//!
//! The WDTT server terminates DTLS and treats the decrypted stream as a plain
//! TCP-like byte stream (it reads a `GETCONF:...` line, then proxies raw
//! WireGuard datagrams). To stay compatible the client must negotiate exactly
//! the same parameters as the reference implementation:
//!
//! * cipher suite `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`;
//! * extended master secret **required**;
//! * a self-signed certificate, server verification disabled;
//! * a connection ID so the peer can follow address changes.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use webrtc_dtls::cipher_suite::CipherSuiteId;
use webrtc_dtls::config::{Config, ExtendedMasterSecretType};
use webrtc_dtls::conn::DTLSConn;
use webrtc_dtls::crypto::Certificate;

use crate::turn::TurnObfsConn;

/// Handshake timeout, matching the reference client (20 s).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Wraps a DTLS connection so it can be used as a byte stream.
pub struct DtlsSession {
    conn: Arc<DTLSConn>,
}

impl DtlsSession {
    /// Performs the DTLS handshake over `transport`.
    ///
    /// The transport must already be pointed at the server through the TURN
    /// relay; `server_name` is only used for SNI and is not verified.
    pub async fn connect(transport: TurnObfsConn, server_name: &str) -> Result<Self> {
        let cert = Certificate::generate_self_signed(vec![server_name.to_string()])
            .context("generating the DTLS client certificate")?;

        let config = Config {
            certificates: vec![cert],
            insecure_skip_verify: true,
            extended_master_secret: ExtendedMasterSecretType::Require,
            cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
            server_name: server_name.to_string(),
            ..Default::default()
        };

        // `DTLSConn::new` performs the handshake itself, so the timeout has to
        // wrap the constructor.
        let conn = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            DTLSConn::new(Arc::new(transport), config, true, None),
        )
        .await
        .map_err(|_| anyhow!("DTLS handshake timed out after {HANDSHAKE_TIMEOUT:?}"))?
        .map_err(|e| anyhow!("DTLS handshake failed: {e}"))?;

        Ok(DtlsSession {
            conn: Arc::new(conn),
        })
    }

    /// Sends application data.
    pub async fn write(&self, data: &[u8]) -> Result<usize> {
        self.conn
            .write(data, None)
            .await
            .map_err(|e| anyhow!("DTLS write: {e}"))
    }

    /// Receives application data, blocking until something arrives.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        self.conn
            .read(buf, None)
            .await
            .map_err(|e| anyhow!("DTLS read: {e}"))
    }

    /// Sends a `GETCONF` request and returns the server's answer.
    ///
    /// The server replies with a WireGuard config, `NOCONF` (no config yet) or
    /// `DENIED:<reason>`.
    pub async fn request_config(
        &self,
        local_port: u16,
        device_id: &str,
        password: &str,
    ) -> Result<ConfigResponse> {
        let request = format!("GETCONF:{local_port}|{device_id}|{password}");
        self.write(request.as_bytes()).await?;

        let mut buf = vec![0u8; 8192];
        let read = tokio::time::timeout(Duration::from_secs(15), self.read(&mut buf))
            .await
            .map_err(|_| anyhow!("timed out waiting for the WireGuard config"))??;
        let response = String::from_utf8_lossy(&buf[..read]).to_string();

        if response == "NOCONF" {
            return Ok(ConfigResponse::NotReady);
        }
        if let Some(reason) = response.strip_prefix("DENIED:") {
            return Ok(ConfigResponse::Denied(reason.trim().to_string()));
        }
        if response.trim().is_empty() {
            return Ok(ConfigResponse::NotReady);
        }
        Ok(ConfigResponse::Config(response))
    }

    /// Signals readiness, as the reference client does before proxying.
    pub async fn say_ready(&self) -> Result<()> {
        self.write(b"READY").await?;
        let mut buf = vec![0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(10), self.read(&mut buf))
            .await
            .map_err(|_| anyhow!("timed out waiting for READY_OK"))??;
        let response = String::from_utf8_lossy(&buf[..read]).to_string();
        if !response.starts_with("READY_OK") {
            return Err(anyhow!("server did not acknowledge READY: {response:?}"));
        }
        Ok(())
    }

    /// Sends the 1-byte keepalive understood by the server.
    pub async fn keepalive(&self) -> Result<()> {
        self.write(&[KEEPALIVE_BYTE]).await.map(|_| ())
    }

    pub async fn close(&self) {
        use webrtc_util::conn::Conn;
        let _ = Conn::close(&*self.conn).await;
    }
}

/// Keepalive byte used by the reference client and server.
pub const KEEPALIVE_BYTE: u8 = 0xFF;

/// What the server answered to `GETCONF`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigResponse {
    /// A WireGuard configuration.
    Config(String),
    /// The server has no config for this device yet; retry later.
    NotReady,
    /// The password was rejected; `reason` is one of the server's codes.
    Denied(String),
}

impl ConfigResponse {
    /// Human readable explanation for `DENIED:<reason>`.
    pub fn denial_message(reason: &str) -> String {
        match reason {
            "wrong_password" => "неверный пароль подключения".to_string(),
            "expired" => "срок действия пароля истёк".to_string(),
            "device_mismatch" => "пароль привязан к другому устройству".to_string(),
            "deactivated" => "пароль деактивирован".to_string(),
            other => format!("доступ запрещён ({other})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_server_responses() {
        assert_eq!(
            ConfigResponse::denial_message("wrong_password"),
            "неверный пароль подключения"
        );
        assert_eq!(
            ConfigResponse::denial_message("expired"),
            "срок действия пароля истёк"
        );
        assert_eq!(
            ConfigResponse::denial_message("device_mismatch"),
            "пароль привязан к другому устройству"
        );
        assert!(ConfigResponse::denial_message("deactivated").contains("деактивирован"));
        assert!(ConfigResponse::denial_message("weird").contains("weird"));
    }

    #[test]
    fn keepalive_byte_matches_reference() {
        assert_eq!(KEEPALIVE_BYTE, 0xFF);
    }
}
