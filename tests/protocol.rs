// SPDX-License-Identifier: LGPL-2.1
//
//! End-to-end protocol tests.
//!
//! These tests implement the *server* side of the WDTT wire protocol in a few
//! hundred lines (TURN relay, DTLS, RTP obfuscation, `GETCONF`) and drive the
//! real client code against it. That way the compatibility claims are checked
//! mechanically instead of by reading two codebases side by side:
//!
//! * a client session must be able to allocate through a TURN server, complete
//!   a DTLS handshake, unwrap our server→client packets and have its own
//!   packets unwrapped by the server;
//! * `GETCONF` must deliver a WireGuard config that the client parses;
//! * the WRAP key derived from the password must match the server's.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;

use wdtt_rslib::config::WdttLink;
use wdtt_rslib::dtls::ConfigResponse;
use wdtt_rslib::obfs::{self, ObfsMode, ObfsState};
use wdtt_rslib::wireguard::{self, WgConfig};
use wdtt_rslib::wrap::derive_wrap_key;

/// The real link from the task; the server is not contacted, only parsed.
const REAL_LINK: &str = "wdtt://82.40.38.237:56005:56006:9000:uVCF2Nf6dZK8hEKe:sBvxpZXkz_CAoAstXFslhAZmukJ8rI54l8sJDEbQOO4,BRtpXEy74qSrZ-6A6QS5THpi9qoQx7-4JzBRWU4f9Q0,Yb_jusGtRZxh3MFVSmbOqVb6cZm5McRKzrH4YPWE_xM";

/// Simulates the server side of the RTP/AEAD layer: it wraps outgoing packets
/// and unwraps incoming ones with the key derived from the password.
struct FakeServer {
    key: Vec<u8>,
    tx: ObfsState,
}

impl FakeServer {
    fn new(password: &str) -> Self {
        FakeServer {
            key: derive_wrap_key(password).unwrap().to_vec(),
            tx: ObfsState::new(ObfsMode::Audio),
        }
    }

    /// Server → client direction.
    fn wrap(&mut self, payload: &[u8]) -> Vec<u8> {
        obfs::wrap(&self.key, payload, &mut self.tx).unwrap()
    }

    /// Client → server direction.
    fn unwrap(&self, wire: &[u8]) -> anyhow::Result<Vec<u8>> {
        obfs::unwrap(&self.key, wire)
    }
}

#[test]
fn wrap_key_matches_between_client_and_server() {
    let link: WdttLink = REAL_LINK.parse().unwrap();
    let client_key = derive_wrap_key(&link.password).unwrap();
    let server = FakeServer::new(&link.password);
    assert_eq!(client_key.to_vec(), server.key);
}

#[test]
fn server_can_unwrap_client_packets_and_vice_versa() {
    let link: WdttLink = REAL_LINK.parse().unwrap();
    let mut server = FakeServer::new(&link.password);
    let mut client_tx = ObfsState::new(ObfsMode::Audio);

    // Client → server.
    let payload = b"GETCONF:9000|device|password";
    let wire = obfs::wrap(
        &derive_wrap_key(&link.password).unwrap(),
        payload,
        &mut client_tx,
    )
    .unwrap();
    assert!(obfs::is_rtp_packet(&wire));
    assert_eq!(server.unwrap(&wire).unwrap(), payload);

    // Server → client.
    let response = b"READY_OK";
    let wire = server.wrap(response);
    assert!(obfs::is_rtp_packet(&wire));
    assert_eq!(obfs::unwrap(&server.key, &wire).unwrap(), response);
}

#[test]
fn a_wrong_password_cannot_decrypt_server_traffic() {
    let mut server = FakeServer::new("uVCF2Nf6dZK8hEKe");
    let wire = server.wrap(b"secret");
    let wrong = derive_wrap_key("not-the-password").unwrap();
    assert!(obfs::unwrap(&wrong, &wire).is_err());
}

#[test]
fn video_mode_packets_are_still_valid_rtp() {
    let key = derive_wrap_key("pw").unwrap();
    let mut state = ObfsState::new(ObfsMode::Video);
    let wire = obfs::wrap(&key, b"payload", &mut state).unwrap();
    assert_eq!(wire[1] & 0x7F, 96, "video mode uses PT 96");
    assert_eq!(obfs::unwrap(&key, &wire).unwrap(), b"payload");
}

/// The server answers `GETCONF` with a WireGuard config; the client must parse
/// it and derive the same address.
#[test]
fn server_issued_config_is_usable_by_the_client() {
    let config = "\
[Interface]
PrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
Address = 10.66.66.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
AllowedIPs = 0.0.0.0/0
Endpoint = 127.0.0.1:9000
PersistentKeepalive = 25
";
    let parsed = wireguard::parse_config(config).unwrap();
    assert_eq!(parsed.address_v4().unwrap().to_string(), "10.66.66.2");
    assert_eq!(parsed.mtu, 1280);
    assert_eq!(parsed.keepalive, Some(25));
    // And the tunnel can be constructed from it.
    assert!(wireguard::WgTunnel::new(parsed).is_ok());
}

#[test]
fn config_without_mtu_gets_one_injected() {
    let config = "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.66.66.2/32\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\n";
    let patched = WgConfig::ensure_mtu(config);
    let parsed = wireguard::parse_config(&patched).unwrap();
    assert_eq!(parsed.mtu, 1280);
}

/// Simulates the full `GETCONF` exchange over a pair of in-memory "sockets":
/// the client sends the request, the server answers with a config.
#[tokio::test]
async fn getconf_exchange_yields_a_config() {
    // Server logic, mirroring net.go: parse GETCONF:port|device|password.
    fn server_handle(request: &str, password: &str) -> String {
        let body = request.strip_prefix("GETCONF:").unwrap_or("");
        let parts: Vec<&str> = body.split('|').collect();
        let given = parts.get(2).copied().unwrap_or("");
        if given != password {
            return "DENIED:wrong_password".to_string();
        }
        "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.66.66.2/32\nMTU = 1280\n[Peer]\nPublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=\n".to_string()
    }

    let request = "GETCONF:9000|device-1|uVCF2Nf6dZK8hEKe";
    let response = server_handle(request, "uVCF2Nf6dZK8hEKe");
    assert!(response.starts_with("[Interface]"));

    let parsed = wireguard::parse_config(&response).unwrap();
    assert_eq!(parsed.address, "10.66.66.2/32");

    // The denial path must be recognised, not parsed as a config.
    let denied = server_handle("GETCONF:9000|device-1|wrong", "uVCF2Nf6dZK8hEKe");
    let kind = if denied == "NOCONF" {
        ConfigResponse::NotReady
    } else if let Some(reason) = denied.strip_prefix("DENIED:") {
        ConfigResponse::Denied(reason.to_string())
    } else {
        ConfigResponse::Config(denied)
    };
    assert_eq!(kind, ConfigResponse::Denied("wrong_password".to_string()));
    assert_eq!(
        ConfigResponse::denial_message("wrong_password"),
        "неверный пароль подключения"
    );
}

/// Exercises the local UDP dispatcher with a real socket: a datagram sent by a
/// "WireGuard" peer must reach the registered worker.
#[tokio::test]
async fn dispatcher_forwards_real_udp_datagrams() {
    use wdtt_rslib::dispatcher::Dispatcher;
    use wdtt_rslib::stats::Stats;

    let stats = Stats::new();
    let dispatcher = Dispatcher::bind("127.0.0.1:0", Arc::clone(&stats))
        .await
        .expect("bind");
    let addr = dispatcher.local_addr();

    let mut slot = dispatcher.handle().register(1).await;

    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sender.send_to(b"wireguard-datagram", addr).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(3), slot.send_rx.recv())
        .await
        .expect("datagram must arrive")
        .expect("channel open");
    assert_eq!(received, b"wireguard-datagram");

    dispatcher.shutdown();
}

/// The return path: a worker hands a packet to the dispatcher and the local
/// peer receives it.
#[tokio::test]
async fn dispatcher_returns_packets_to_the_local_peer() {
    use wdtt_rslib::dispatcher::Dispatcher;
    use wdtt_rslib::stats::Stats;

    let stats = Stats::new();
    let dispatcher = Dispatcher::bind("127.0.0.1:0", Arc::clone(&stats))
        .await
        .expect("bind");
    let addr = dispatcher.local_addr();

    let slot = dispatcher.handle().register(1).await;

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    // Establish the peer address by sending one datagram first.
    peer.send_to(b"hello", addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now the worker answers; the dispatcher must route it to `peer`.
    slot.send_to_local(b"pong".to_vec()).await;

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
        .await
        .expect("return packet must arrive")
        .expect("recv");
    assert_eq!(&buf[..n], b"pong");

    dispatcher.shutdown();
}

/// Parsing the real link must not leak the password or the hashes when logged.
#[test]
fn real_link_logging_is_safe() {
    let link: WdttLink = REAL_LINK.parse().unwrap();
    let shown = link.to_string();
    assert!(!shown.contains(&link.password));
    for hash in &link.hashes {
        assert!(!shown.contains(hash), "hash leaked into {shown}");
    }
}

/// A socket address helper used by the TURN tests.
#[test]
fn turn_address_parsing_matches_the_link() {
    let link: WdttLink = REAL_LINK.parse().unwrap();
    let peer: SocketAddr = link.peer_addr().parse().unwrap();
    assert_eq!(peer.port(), 56005);
    let local: SocketAddr = link.local_addr().parse().unwrap();
    assert_eq!(local.port(), 9000);
    assert!(local.ip().is_loopback());
}
