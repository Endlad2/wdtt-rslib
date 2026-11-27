// SPDX-License-Identifier: LGPL-2.1
//
//! TURN client and the obfuscated transport that rides on it.
//!
//! The WDTT transport is: UDP → TURN allocation → relayed UDP to the VPS →
//! DTLS. Every packet that travels over the relay is wrapped in the RTP-shaped
//! AEAD envelope from [`crate::obfs`], so what the TURN server sees looks like
//! a WebRTC call.
//!
//! This module provides [`TurnAllocation`], which allocates the relay, and
//! [`TurnObfsConn`], a `webrtc_util::Conn` that DTLS can drive directly:
//! `send_to` wraps and relays, `recv_from` relays and unwraps.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use tokio::net::UdpSocket;
use turn::client::{Client, ClientConfig};
use webrtc_util::conn::Conn as DtlsConn;
use webrtc_util::Error as UtilError;
use webrtc_util_17::conn::Conn as TurnConn;

use crate::obfs::{self, ObfsMode, ObfsState};

/// Socket buffer size, matching the reference client (625 KiB).
const SOCKET_BUF_SIZE: usize = 625 * 1024;
/// How often a STUN binding request is sent to keep the allocation alive.
pub const BINDING_INTERVAL: Duration = Duration::from_secs(10);

/// Thin adapter so `tokio::net::UdpSocket` can be handed to the TURN client,
/// which expects the `webrtc-util` `Conn` trait.
struct UdpAdapter {
    socket: UdpSocket,
}

#[async_trait]
impl TurnConn for UdpAdapter {
    async fn connect(&self, addr: SocketAddr) -> webrtc_util_17::Result<()> {
        self.socket
            .connect(addr)
            .await
            .map_err(webrtc_util_17::Error::from_std)
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util_17::Result<usize> {
        self.socket
            .recv(buf)
            .await
            .map_err(webrtc_util_17::Error::from_std)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util_17::Result<(usize, SocketAddr)> {
        self.socket
            .recv_from(buf)
            .await
            .map_err(webrtc_util_17::Error::from_std)
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util_17::Result<usize> {
        self.socket
            .send(buf)
            .await
            .map_err(webrtc_util_17::Error::from_std)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util_17::Result<usize> {
        self.socket
            .send_to(buf, target)
            .await
            .map_err(webrtc_util_17::Error::from_std)
    }

    fn local_addr(&self) -> webrtc_util_17::Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(webrtc_util_17::Error::from_std)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.socket.peer_addr().ok()
    }

    async fn close(&self) -> webrtc_util_17::Result<()> {
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// A live TURN allocation towards the WDTT server.
pub struct TurnAllocation {
    client: Client,
    relay: Arc<dyn TurnConn + Send + Sync>,
    relay_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl TurnAllocation {
    /// Allocates a relay on `turn_addr` with the given credentials.
    ///
    /// `realm` is left empty: the server sends it in its 401 challenge and the
    /// client picks it up, exactly like the reference implementation.
    pub async fn allocate(
        turn_addr: &str,
        username: &str,
        password: &str,
        ipv4: bool,
    ) -> Result<Self> {
        let resolved: SocketAddr = tokio::net::lookup_host(turn_addr)
            .await
            .with_context(|| format!("resolving TURN address {turn_addr}"))?
            .find(|addr| (ipv4 && addr.is_ipv4()) || (!ipv4 && addr.is_ipv6()))
            .ok_or_else(|| anyhow!("no suitable address for TURN server {turn_addr}"))?;

        let socket = UdpSocket::bind(if resolved.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await
        .context("binding UDP socket for TURN")?;
        socket.connect(resolved).await.ok();
        set_socket_buffers(&socket);

        let local_addr = socket
            .local_addr()
            .context("local address of TURN socket")?;
        let conn = Arc::new(UdpAdapter { socket });

        let client = Client::new(ClientConfig {
            stun_serv_addr: turn_addr.to_string(),
            turn_serv_addr: turn_addr.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            realm: String::new(),
            software: String::new(),
            rto_in_ms: 0,
            conn,
            // The zero-value Net avoids enumerating interfaces, which some
            // Android ROMs deny (the reference client does the same).
            vnet: None,
        })
        .await
        .map_err(|e| anyhow!("TURN client init: {e}"))?;

        client
            .listen()
            .await
            .map_err(|e| anyhow!("TURN listen: {e}"))?;

        let relay = client
            .allocate()
            .await
            .map_err(|e| anyhow!("TURN allocate: {e}"))?;

        let relay_addr = relay
            .local_addr()
            .map_err(|e| anyhow!("TURN relay address: {e}"))?;

        Ok(TurnAllocation {
            client,
            relay: Arc::new(relay),
            relay_addr,
            local_addr,
        })
    }

    /// Relayed address as seen by the TURN server.
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    /// Local address of the UDP socket talking to the TURN server.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Cloneable handle for background STUN refreshes.
    pub fn client_handle(&self) -> TurnBindingClient {
        TurnBindingClient {
            client: self.client.clone(),
        }
    }

    /// Sends a STUN binding request to refresh permissions.
    pub async fn send_binding_request(&self) -> Result<()> {
        self.client
            .send_binding_request()
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("STUN binding request: {e}"))
    }

    pub async fn close(&self) {
        let _ = self.client.close().await;
    }
}

/// Minimal handle used by the keepalive task.
#[derive(Clone)]
pub struct TurnBindingClient {
    client: Client,
}

impl TurnBindingClient {
    pub async fn send_binding_request(&self) -> Result<()> {
        self.client
            .send_binding_request()
            .await
            .map(|_| ())
            .map_err(|e| anyhow!("STUN binding request: {e}"))
    }
}

fn set_socket_buffers(socket: &UdpSocket) {
    // Best effort: the kernel may clamp these, which is fine.
    let sock = socket2::SockRef::from(socket);
    let _ = sock.set_send_buffer_size(SOCKET_BUF_SIZE);
    let _ = sock.set_recv_buffer_size(SOCKET_BUF_SIZE);
}

/// The DTLS-facing connection: relays through TURN and obfuscates every packet.
pub struct TurnObfsConn {
    relay: Arc<dyn TurnConn + Send + Sync>,
    peer: SocketAddr,
    local: SocketAddr,
    wrap_key: Vec<u8>,
    tx: tokio::sync::Mutex<ObfsState>,
    closed: std::sync::atomic::AtomicBool,
}

impl TurnObfsConn {
    pub fn new(
        allocation: &TurnAllocation,
        peer: SocketAddr,
        wrap_key: Vec<u8>,
        mode: ObfsMode,
    ) -> Self {
        TurnObfsConn {
            relay: Arc::clone(&allocation.relay),
            peer,
            local: allocation.local_addr,
            wrap_key,
            tx: tokio::sync::Mutex::new(ObfsState::new(mode)),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

fn util_err(context: &str, err: impl std::fmt::Display) -> UtilError {
    UtilError::Other(format!("{context}: {err}"))
}

#[async_trait]
impl DtlsConn for TurnObfsConn {
    async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
        // The relay is already pinned to the peer.
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
        // Read a wire packet, then unwrap. The relay may also deliver stray
        // non-RTP traffic (e.g. a STUN response), so keep reading until we get
        // something we can decrypt.
        let mut wire = vec![0u8; buf.len() + 128];
        loop {
            let (n, addr) = TurnConn::recv_from(&*self.relay, &mut wire)
                .await
                .map_err(|e| util_err("relay recv", e))?;
            if n == 0 {
                return Err(util_err("relay recv", "empty datagram"));
            }
            let packet = &wire[..n];
            if !obfs::is_rtp_packet(packet) {
                log::trace!("dropping non-RTP packet from relay ({n} bytes)");
                continue;
            }
            let plain =
                obfs::unwrap(&self.wrap_key, packet).map_err(|e| util_err("obfs unwrap", e))?;
            if plain.len() > buf.len() {
                return Err(util_err("obfs unwrap", "payload larger than buffer"));
            }
            buf[..plain.len()].copy_from_slice(&plain);
            return Ok((plain.len(), addr));
        }
    }

    async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
        self.send_to(buf, self.peer).await
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> webrtc_util::Result<usize> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(util_err("send", "connection closed"));
        }
        let wrapped = {
            let mut state = self.tx.lock().await;
            obfs::wrap(&self.wrap_key, buf, &mut state).map_err(|e| util_err("obfs wrap", e))?
        };
        TurnConn::send_to(&*self.relay, &wrapped, self.peer)
            .await
            .map_err(|e| util_err("relay send", e))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }

    async fn close(&self) -> webrtc_util::Result<()> {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Classifies TURN allocation errors the way the reference client does, so the
/// session loop can decide between refreshing credentials and giving up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocErrorKind {
    /// The credentials are stale or rejected: refresh and retry.
    CredentialsRejected,
    /// The server reports quota exhaustion: back off.
    Quota,
    /// Anything else.
    Other,
}

impl AllocErrorKind {
    pub fn classify(message: &str) -> Self {
        let lower = message.to_ascii_lowercase();
        if lower.contains("quota") || lower.contains("486") || lower.contains("508") {
            return AllocErrorKind::Quota;
        }
        if lower.contains("auth")
            || lower.contains("invalid credential")
            || lower.contains("stale nonce")
            || lower.contains("allocation mismatch")
            || lower.contains("attribute not found")
            || lower.contains("401")
            || lower.contains("438")
        {
            return AllocErrorKind::CredentialsRejected;
        }
        AllocErrorKind::Other
    }
}

/// Parses `turn:host:port?transport=udp` style URLs into `host:port`.
pub fn normalize_turn_url(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("empty TURN URL");
    }
    let without_scheme = trimmed
        .strip_prefix("turn:")
        .or_else(|| trimmed.strip_prefix("turns:"))
        .unwrap_or(trimmed);
    let without_query = without_scheme.split('?').next().unwrap_or(without_scheme);
    let addr = without_query.trim();
    if addr.is_empty() {
        bail!("empty TURN address in {raw:?}");
    }
    Ok(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_turn_urls() {
        assert_eq!(
            normalize_turn_url("turn:82.40.38.237:56005?transport=udp").unwrap(),
            "82.40.38.237:56005"
        );
        assert_eq!(
            normalize_turn_url("turns:82.40.38.237:56005").unwrap(),
            "82.40.38.237:56005"
        );
        assert_eq!(
            normalize_turn_url("82.40.38.237:56005").unwrap(),
            "82.40.38.237:56005"
        );
        assert!(normalize_turn_url("").is_err());
        assert!(normalize_turn_url("turn:").is_err());
    }

    #[test]
    fn classifies_allocation_errors() {
        assert_eq!(
            AllocErrorKind::classify("TURN allocate: Quota reached (486)"),
            AllocErrorKind::Quota
        );
        assert_eq!(
            AllocErrorKind::classify("invalid credential"),
            AllocErrorKind::CredentialsRejected
        );
        assert_eq!(
            AllocErrorKind::classify("stale nonce"),
            AllocErrorKind::CredentialsRejected
        );
        assert_eq!(
            AllocErrorKind::classify("attribute not found"),
            AllocErrorKind::CredentialsRejected
        );
        assert_eq!(
            AllocErrorKind::classify("i/o timeout"),
            AllocErrorKind::Other
        );
    }
}
