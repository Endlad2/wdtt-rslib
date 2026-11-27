// SPDX-License-Identifier: LGPL-2.1
//
//! Parsing of `wdtt://` links and runtime configuration.
//!
//! Link format (identical to the WDTT server's `db.go`):
//!
//! ```text
//! wdtt://<server-ip>:<dtls-port>:<wg-port>:<local-port>:<password>:<hash>[,<hash>...]
//! ```
//!
//! * `server-ip` — VPS running the WDTT server.
//! * `dtls-port` — TURN/DTLS port the server listens on (the client's `-peer`).
//! * `wg-port` — WireGuard port on the server; informational for the client,
//!   the real endpoint comes from the WireGuard config handed out by the server.
//! * `local-port` — UDP port the client exposes for the WireGuard endpoint.
//! * `password` — connection password; also the WRAP key material.
//! * `hash` — one or more VK call join hashes used to obtain TURN credentials.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::{bail, Context, Result};

/// Default TURN/DTLS port when a link omits it.
pub const DEFAULT_DTLS_PORT: u16 = 56000;
/// Default WireGuard port (server side).
pub const DEFAULT_WG_PORT: u16 = 56001;
/// Default local WireGuard endpoint port.
pub const DEFAULT_LOCAL_PORT: u16 = 9000;

/// A parsed `wdtt://` link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WdttLink {
    /// Server address (IP literal or hostname).
    pub host: String,
    /// TURN/DTLS port.
    pub dtls_port: u16,
    /// WireGuard port on the server.
    pub wg_port: u16,
    /// Local UDP port for the WireGuard endpoint.
    pub local_port: u16,
    /// Connection password (WRAP key material).
    pub password: String,
    /// VK call join hashes.
    pub hashes: Vec<String>,
}

impl WdttLink {
    /// `host:dtls_port`, the address the DTLS peer lives at.
    pub fn peer_addr(&self) -> String {
        format!("{}:{}", self.host, self.dtls_port)
    }

    /// Address of the local WireGuard endpoint.
    pub fn local_addr(&self) -> String {
        format!("127.0.0.1:{}", self.local_port)
    }
}

impl fmt::Display for WdttLink {
    /// Renders the link back to `wdtt://` form, masking the password and
    /// hashes so it can be logged.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wdtt://{}:{}:{}:{}:***:{} hash(es)",
            self.host,
            self.dtls_port,
            self.wg_port,
            self.local_port,
            self.hashes.len()
        )
    }
}

/// Normalizes a VK call hash: accepts a bare hash, a `/call/join/<hash>` URL or
/// a full `https://vk.com/call/join/<hash>` link, and strips query/fragment.
pub fn normalize_vk_hash(input: &str) -> Option<String> {
    let mut s = input
        .trim()
        .trim_matches(|c| c == '<' || c == '>' || c == '"' || c == '\'');
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    if let Some(idx) = lower.find("/call/join/") {
        s = &s[idx + "/call/join/".len()..];
    } else if lower.starts_with("http://") || lower.starts_with("https://") {
        return None;
    }
    if let Some(idx) = s.find(['?', '#', '/']) {
        s = &s[..idx];
    }
    let trimmed = s.trim().trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parses a comma/semicolon/whitespace separated list of hashes, removing
/// duplicates while preserving order.
pub fn parse_hashes(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in
        raw.split(|c: char| c == ',' || c == ';' || c == '\n' || c == '\r' || c == '\t' || c == ' ')
    {
        if let Some(hash) = normalize_vk_hash(part) {
            if !out.iter().any(|existing| existing == &hash) {
                out.push(hash);
            }
        }
    }
    out
}

/// Splits the link body into at most six fields.
///
/// The password may contain `:`, but hashes may contain commas. Splitting with
/// a limit keeps the hash list intact; a `:` inside the password is not
/// supported by the reference server either.
fn split_fields(body: &str) -> Vec<&str> {
    body.splitn(6, ':').collect()
}

impl FromStr for WdttLink {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let body = trimmed
            .strip_prefix("wdtt://")
            .or_else(|| trimmed.strip_prefix("WDTToR://"))
            .or_else(|| trimmed.strip_prefix("wdtto://"))
            .ok_or_else(|| {
                anyhow::anyhow!("ссылка должна начинаться с wdtt://, получено: {trimmed:.32}")
            })?;

        let fields = split_fields(body);
        if fields.len() < 5 {
            bail!(
                "некорректная ссылка wdtt://: ожидается \
                 wdtt://host:dtls:wg:local:password:hashes, получено {} поле(й)",
                fields.len()
            );
        }

        let host = fields[0].trim();
        if host.is_empty() {
            bail!("в ссылке wdtt:// не указан адрес сервера");
        }
        // Validate the host: an IP literal or a DNS name.
        if IpAddr::from_str(host).is_err() && !host.contains('.') {
            bail!("некорректный адрес сервера в wdtt://: {host}");
        }

        let dtls_port = parse_port(fields[1], "порт DTLS", DEFAULT_DTLS_PORT)?;
        let wg_port = parse_port(fields[2], "порт WireGuard", DEFAULT_WG_PORT)?;
        let local_port = parse_port(fields[3], "локальный порт", DEFAULT_LOCAL_PORT)?;

        let password = fields[4].trim().to_string();
        if password.is_empty() {
            bail!("в ссылке wdtt:// не указан пароль подключения");
        }

        let hashes = fields
            .get(5)
            .map(|raw| parse_hashes(raw))
            .unwrap_or_default();

        Ok(WdttLink {
            host: host.to_string(),
            dtls_port,
            wg_port,
            local_port,
            password,
            hashes,
        })
    }
}

fn parse_port(raw: &str, what: &str, default: u16) -> Result<u16> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(default);
    }
    let value: u16 = raw
        .parse()
        .with_context(|| format!("некорректный {what} в wdtt://: {raw}"))?;
    if value == 0 {
        bail!("{what} не может быть 0");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact link from the task description.
    const REAL_LINK: &str = "wdtt://82.40.38.237:56005:56006:9000:uVCF2Nf6dZK8hEKe:sBvxpZXkz_CAoAstXFslhAZmukJ8rI54l8sJDEbQOO4,BRtpXEy74qSrZ-6A6QS5THpi9qoQx7-4JzBRWU4f9Q0,Yb_jusGtRZxh3MFVSmbOqVb6cZm5McRKzrH4YPWE_xM";

    #[test]
    fn parses_the_real_link() {
        let link: WdttLink = REAL_LINK.parse().unwrap();
        assert_eq!(link.host, "82.40.38.237");
        assert_eq!(link.dtls_port, 56005);
        assert_eq!(link.wg_port, 56006);
        assert_eq!(link.local_port, 9000);
        assert_eq!(link.password, "uVCF2Nf6dZK8hEKe");
        assert_eq!(link.hashes.len(), 3);
        assert_eq!(
            link.hashes[0],
            "sBvxpZXkz_CAoAstXFslhAZmukJ8rI54l8sJDEbQOO4"
        );
        assert_eq!(
            link.hashes[1],
            "BRtpXEy74qSrZ-6A6QS5THpi9qoQx7-4JzBRWU4f9Q0"
        );
        assert_eq!(
            link.hashes[2],
            "Yb_jusGtRZxh3MFVSmbOqVb6cZm5McRKzrH4YPWE_xM"
        );
        assert_eq!(link.peer_addr(), "82.40.38.237:56005");
        assert_eq!(link.local_addr(), "127.0.0.1:9000");
    }

    #[test]
    fn display_masks_secrets() {
        let link: WdttLink = REAL_LINK.parse().unwrap();
        let shown = link.to_string();
        assert!(
            !shown.contains("uVCF2Nf6dZK8hEKe"),
            "password must not leak: {shown}"
        );
        assert!(
            !shown.contains("sBvxpZXkz"),
            "hashes must not leak: {shown}"
        );
        assert!(shown.contains("82.40.38.237:56005"));
    }

    #[test]
    fn applies_defaults_for_empty_ports() {
        let link: WdttLink = "wdtt://1.2.3.4::::pass:hash".parse().unwrap();
        assert_eq!(link.dtls_port, DEFAULT_DTLS_PORT);
        assert_eq!(link.wg_port, DEFAULT_WG_PORT);
        assert_eq!(link.local_port, DEFAULT_LOCAL_PORT);
    }

    #[test]
    fn rejects_malformed_links() {
        for bad in [
            "",
            "csqtt://1.2.3.4",
            "wdtt://",
            "wdtt://1.2.3.4",
            "wdtt://1.2.3.4:1:2:3",
            "wdtt://1.2.3.4:1:2:3:",
            "wdtt://notahost:1:2:3:pass",
            "wdtt://1.2.3.4:0:2:3:pass",
            "wdtt://1.2.3.4:99999:2:3:pass",
        ] {
            assert!(bad.parse::<WdttLink>().is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn accepts_hostnames() {
        let link: WdttLink = "wdtt://vpn.example.com:56000:56001:9000:p:h"
            .parse()
            .unwrap();
        assert_eq!(link.host, "vpn.example.com");
    }

    #[test]
    fn normalizes_hash_inputs() {
        assert_eq!(normalize_vk_hash("abc123").as_deref(), Some("abc123"));
        assert_eq!(
            normalize_vk_hash("https://vk.com/call/join/abc123?x=1").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            normalize_vk_hash("/call/join/abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(normalize_vk_hash("  <abc123>  ").as_deref(), Some("abc123"));
        assert_eq!(normalize_vk_hash(""), None);
        assert_eq!(normalize_vk_hash("https://example.com/x"), None);
    }

    #[test]
    fn parse_hashes_deduplicates() {
        let hashes = parse_hashes("a, b;a  b\nc,");
        assert_eq!(hashes, vec!["a", "b", "c"]);
    }
}
