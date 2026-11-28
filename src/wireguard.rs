// SPDX-License-Identifier: LGPL-2.1
//
//! WireGuard config parsing and the boringtun tunnel.
//!
//! The WDTT server hands out a stock WireGuard config over the DTLS channel:
//!
//! ```text
//! [Interface]
//! PrivateKey = <base64>
//! Address = 10.66.66.2/32
//! DNS = 1.1.1.1
//! MTU = 1280
//!
//! [Peer]
//! PublicKey = <base64>
//! AllowedIPs = 0.0.0.0/0
//! Endpoint = 127.0.0.1:9000
//! PersistentKeepalive = 25
//! ```
//!
//! The endpoint is always the local UDP port the client exposes, so the
//! WireGuard handshake packets travel through the DTLS tunnel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519;

/// MTU the server always uses; injected when the config omits it.
pub const DEFAULT_MTU: u16 = 1280;
/// Largest datagram we ever read from the tunnel.
pub const MAX_PACKET: usize = 1500 + 64;

/// A parsed WireGuard configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgConfig {
    /// Client private key (base64, as handed out by the server).
    pub private_key: String,
    /// Address assigned to this client, e.g. `10.66.66.2/32`.
    pub address: String,
    /// DNS server, if present.
    pub dns: Option<String>,
    /// MTU, defaults to 1280.
    pub mtu: u16,
    /// Server public key (base64).
    pub peer_public_key: String,
    /// Allowed IPs of the peer.
    pub allowed_ips: Vec<String>,
    /// Endpoint, normally the local UDP port.
    pub endpoint: Option<String>,
    /// Persistent keepalive in seconds.
    pub keepalive: Option<u16>,
}

impl WgConfig {
    /// The IPv4 address without the prefix length.
    pub fn address_v4(&self) -> Result<Ipv4Addr> {
        let addr = self
            .address
            .split('/')
            .next()
            .unwrap_or(&self.address)
            .trim();
        addr.parse()
            .with_context(|| format!("некорректный Address в конфиге WireGuard: {addr}"))
    }

    /// Prefix length of `Address`, defaulting to /32.
    pub fn prefix_len(&self) -> u8 {
        self.address
            .split('/')
            .nth(1)
            .and_then(|p| p.trim().parse().ok())
            .unwrap_or(32)
    }

    /// Adds `MTU = 1280` when the server omitted it, like the reference client.
    pub fn ensure_mtu(text: &str) -> String {
        if text.contains("MTU =") || text.contains("MTU=") {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len() + 16);
        for line in text.lines() {
            out.push_str(line);
            out.push('\n');
            if line.trim().eq_ignore_ascii_case("[Interface]") {
                out.push_str(&format!("MTU = {DEFAULT_MTU}\n"));
            }
        }
        out
    }
}

fn base64_to_32(value: &str, what: &str) -> Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .with_context(|| format!("{what}: некорректный base64"))?;
    if decoded.len() != 32 {
        bail!("{what}: ожидается 32 байта, получено {}", decoded.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

/// Parses an INI-style WireGuard config.
pub fn parse_config(text: &str) -> Result<WgConfig> {
    let mut private_key = None;
    let mut address = None;
    let mut dns = None;
    let mut mtu = None;
    let mut peer_public_key = None;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut endpoint = None;
    let mut keepalive = None;
    let mut section = String::new();

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .to_ascii_lowercase();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if value.is_empty() {
            continue;
        }
        match (section.as_str(), key.as_str()) {
            ("interface", "privatekey") => private_key = Some(value),
            ("interface", "address") => address = Some(value),
            ("interface", "dns") => dns = Some(value),
            ("interface", "mtu") => mtu = value.parse::<u16>().ok(),
            ("peer", "publickey") => peer_public_key = Some(value),
            ("peer", "allowedips") => {
                allowed_ips.extend(
                    value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
            ("peer", "endpoint") => endpoint = Some(value),
            ("peer", "persistentkeepalive") => keepalive = value.parse::<u16>().ok(),
            _ => {}
        }
    }

    let private_key = private_key.ok_or_else(|| anyhow!("в конфиге нет PrivateKey"))?;
    let peer_public_key = peer_public_key.ok_or_else(|| anyhow!("в конфиге нет PublicKey"))?;
    let address = address.ok_or_else(|| anyhow!("в конфиге нет Address"))?;

    // Validate the keys early: a bad key would otherwise fail inside boringtun.
    base64_to_32(&private_key, "PrivateKey")?;
    base64_to_32(&peer_public_key, "PublicKey")?;
    if address.parse::<Ipv4Addr>().is_err() {
        address
            .split('/')
            .next()
            .unwrap_or(&address)
            .parse::<Ipv4Addr>()
            .with_context(|| format!("некорректный Address: {address}"))?;
    }

    Ok(WgConfig {
        private_key,
        address,
        dns,
        mtu: mtu.unwrap_or(DEFAULT_MTU),
        peer_public_key,
        allowed_ips,
        endpoint,
        keepalive,
    })
}

/// A boringtun tunnel plus the metadata needed to pump packets.
pub struct WgTunnel {
    tunn: Tunn,
    pub config: WgConfig,
    /// Local address assigned by the server (for logging and the TUN device).
    pub local_v4: Ipv4Addr,
}

impl WgTunnel {
    /// Builds the tunnel from a parsed config.
    pub fn new(config: WgConfig) -> Result<Self> {
        let private_bytes = base64_to_32(&config.private_key, "PrivateKey")?;
        let peer_bytes = base64_to_32(&config.peer_public_key, "PublicKey")?;

        let private = x25519::StaticSecret::from(private_bytes);
        let peer = x25519::PublicKey::from(peer_bytes);

        let tunn = Tunn::new(private, peer, None, config.keepalive, 0, None);

        let local_v4 = config.address_v4()?;
        Ok(WgTunnel {
            tunn,
            config,
            local_v4,
        })
    }

    /// Encapsulates a plaintext IP packet from the TUN device.
    ///
    /// Returns `None` when the packet was queued (no session yet) or dropped.
    pub fn encapsulate(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; MAX_PACKET];
        match self.tunn.encapsulate(packet, &mut out) {
            TunnResult::WriteToNetwork(data) => Some(data.to_vec()),
            TunnResult::Done => None,
            TunnResult::Err(err) => {
                log::debug!("[WG] encapsulate error: {err:?}");
                None
            }
            other => {
                log::trace!("[WG] unexpected encapsulate result: {other:?}");
                None
            }
        }
    }

    /// Decapsulates a datagram received from the network.
    ///
    /// Returns the plaintext IP packet (if any) and any datagrams that must be
    /// sent back to the peer (e.g. handshake responses).
    pub fn decapsulate(&mut self, datagram: &[u8]) -> (Option<Vec<u8>>, Vec<Vec<u8>>) {
        let mut out = vec![0u8; MAX_PACKET];
        let mut plaintext = None;
        let mut to_network = Vec::new();

        match self.tunn.decapsulate(None, datagram, &mut out) {
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                plaintext = Some(data.to_vec());
            }
            TunnResult::WriteToNetwork(data) => {
                to_network.push(data.to_vec());
            }
            TunnResult::Err(err) => {
                log::debug!("[WG] decapsulate error: {err:?}");
            }
            TunnResult::Done => {}
        }

        // boringtun may have queued packets or pending handshake messages.
        loop {
            let mut buf = vec![0u8; MAX_PACKET];
            match self.tunn.decapsulate(None, &[], &mut buf) {
                TunnResult::WriteToNetwork(data) => to_network.push(data.to_vec()),
                TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                    if plaintext.is_none() {
                        plaintext = Some(data.to_vec());
                    }
                }
                _ => break,
            }
        }

        (plaintext, to_network)
    }

    /// True once the peer has answered the handshake.
    ///
    /// boringtun reports `None` until a handshake completed, so this is the
    /// only reliable "the tunnel really works" signal available without
    /// injecting traffic.
    pub fn handshake_complete(&self) -> bool {
        self.tunn.time_since_last_handshake().is_some()
    }

    /// `TUNCONF:<address>:<dns>` — the same line the reference clients print
    /// so a host application can configure its own interface (Android/iOS
    /// VpnService, Desktop).
    pub fn tunconf_line(&self) -> String {
        let addr = self.local_v4.to_string();
        let dns = self
            .config
            .dns
            .as_deref()
            .map(|d| d.replace(' ', ""))
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "1.1.1.1".to_string());
        format!("TUNCONF:{addr}:{dns}")
    }

    /// Drives the WireGuard timers; returns datagrams to send.
    pub fn update_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = vec![0u8; MAX_PACKET];
        let mut datagrams = Vec::new();
        match self.tunn.update_timers(&mut out) {
            TunnResult::WriteToNetwork(data) => datagrams.push(data.to_vec()),
            TunnResult::Err(err) => log::debug!("[WG] timer error: {err:?}"),
            _ => {}
        }
        datagrams
    }
}

/// Formats a config for logging with the private key masked.
pub fn redact_config(text: &str) -> String {
    text.lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("privatekey") {
                match line.split_once('=') {
                    Some((key, _)) => format!("{} = <скрыто>", key.trim()),
                    None => line.to_string(),
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Returns true when `addr` is a private/local address that should not be
/// routed into the tunnel.
pub fn is_local_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Parses `10.0.0.1/8` style CIDR into an address and prefix length.
pub fn parse_cidr(value: &str) -> Result<(IpAddr, u8)> {
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, prefix.parse::<u8>()?),
        None => (value, 32),
    };
    Ok((
        addr.trim()
            .parse()
            .map_err(|_| anyhow!("некорректный CIDR: {value}"))?,
        prefix,
    ))
}

/// Unused helper kept for symmetry with the reference implementation.
pub fn _assert_ipv6_parse(value: &str) -> Option<Ipv6Addr> {
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config shaped exactly like the one the WDTT server returns.
    const SAMPLE: &str = "\
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

    #[test]
    fn parses_a_server_style_config() {
        let cfg = parse_config(SAMPLE).unwrap();
        assert_eq!(cfg.address, "10.66.66.2/32");
        assert_eq!(cfg.dns.as_deref(), Some("1.1.1.1"));
        assert_eq!(cfg.mtu, 1280);
        assert_eq!(cfg.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(cfg.endpoint.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(cfg.keepalive, Some(25));
        assert_eq!(cfg.address_v4().unwrap().to_string(), "10.66.66.2");
        assert_eq!(cfg.prefix_len(), 32);
    }

    #[test]
    fn injects_mtu_when_missing() {
        let without = "[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n";
        let patched = WgConfig::ensure_mtu(without);
        assert!(patched.contains("MTU = 1280"));
        // Existing MTU is preserved.
        let kept = WgConfig::ensure_mtu(SAMPLE);
        assert_eq!(kept, SAMPLE);
    }

    #[test]
    fn rejects_configs_without_required_keys() {
        assert!(parse_config("").is_err());
        assert!(parse_config("[Interface]\nAddress = 10.0.0.2/32\n").is_err());
        assert!(parse_config(
            "[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
        )
        .is_err());
        // Wrong key length.
        assert!(parse_config(
            "[Interface]\nPrivateKey = c2hvcnQ=\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = c2hvcnQ=\n"
        )
        .is_err());
    }

    #[test]
    fn redacts_the_private_key() {
        let redacted = redact_config(SAMPLE);
        assert!(!redacted.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="));
        assert!(redacted.contains("PrivateKey = <скрыто>"));
        assert!(redacted.contains("PublicKey = ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="));
    }

    #[test]
    fn detects_local_addresses() {
        assert!(is_local_address("127.0.0.1".parse().unwrap()));
        assert!(is_local_address("10.0.0.1".parse().unwrap()));
        assert!(is_local_address("192.168.1.1".parse().unwrap()));
        assert!(is_local_address("169.254.1.1".parse().unwrap()));
        assert!(!is_local_address("1.1.1.1".parse().unwrap()));
        assert!(!is_local_address("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn parses_cidrs() {
        let (addr, prefix) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(addr.to_string(), "10.0.0.0");
        assert_eq!(prefix, 8);
        let (addr, prefix) = parse_cidr("1.2.3.4").unwrap();
        assert_eq!(addr.to_string(), "1.2.3.4");
        assert_eq!(prefix, 32);
        assert!(parse_cidr("nope").is_err());
    }

    /// End-to-end check of the boringtun wiring: two peers must complete a
    /// handshake and exchange a transport packet.
    #[test]
    fn boringtun_peers_complete_a_handshake() {
        fn keypair() -> (x25519::StaticSecret, [u8; 32]) {
            let secret = x25519::StaticSecret::random_from_rng(rand::thread_rng());
            let public = x25519::PublicKey::from(&secret);
            (secret, public.to_bytes())
        }

        let (client_secret, client_public) = keypair();
        let (server_secret, server_public) = keypair();

        let mut client = Tunn::new(
            client_secret,
            x25519::PublicKey::from(server_public),
            None,
            None,
            0,
            None,
        );
        let mut server = Tunn::new(
            server_secret,
            x25519::PublicKey::from(client_public),
            None,
            None,
            1,
            None,
        );

        let mut buf = [0u8; MAX_PACKET];

        // The client starts the handshake.
        let init = match client.encapsulate(b"", &mut buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected handshake initiation, got {other:?}"),
        };

        // The server answers.
        let mut out = [0u8; MAX_PACKET];
        let response = match server.decapsulate(None, &init, &mut out) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected handshake response, got {other:?}"),
        };

        // The client completes it; it may then have a packet to send.
        let mut out2 = [0u8; MAX_PACKET];
        let mut keepalive = None;
        match client.decapsulate(None, &response, &mut out2) {
            TunnResult::WriteToNetwork(data) => keepalive = Some(data.to_vec()),
            TunnResult::Done => {}
            other => panic!("unexpected client result {other:?}"),
        }
        if let Some(keepalive) = keepalive {
            let mut out3 = [0u8; MAX_PACKET];
            let _ = server.decapsulate(None, &keepalive, &mut out3);
        }

        // Now a real IPv4 packet must travel from client to server.
        let mut packet = vec![0u8; 20 + 8 + 4];
        packet[0] = 0x45; // IPv4, IHL 5
        packet[2..4].copy_from_slice(&(32u16).to_be_bytes());
        packet[8] = 64; // TTL
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[10, 66, 66, 2]);
        packet[16..20].copy_from_slice(&[10, 66, 66, 1]);

        let mut out4 = [0u8; MAX_PACKET];
        let wire = match client.encapsulate(&packet, &mut out4) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected transport packet, got {other:?}"),
        };
        let mut out5 = [0u8; MAX_PACKET];
        match server.decapsulate(None, &wire, &mut out5) {
            TunnResult::WriteToTunnelV4(data, _) => assert_eq!(data, &packet[..]),
            other => panic!("expected tunnel packet, got {other:?}"),
        }
    }
}
