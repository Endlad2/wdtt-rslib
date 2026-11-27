// SPDX-License-Identifier: LGPL-2.1
//
//! RTP-shaped obfuscation layer ("WRAP").
//!
//! Every packet between the WDTT client and server is a syntactically valid
//! RTP v2 packet whose payload is ChaCha20-Poly1305 ciphertext. The header
//! (12 bytes) is used as AEAD associated data, so the sequence number,
//! timestamp and SSRC are authenticated too.
//!
//! Wire layout (all integers big-endian):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P=1|X=0|CC=0|M=0|   PT      |          sequence             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                           timestamp                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                             SSRC                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            ciphertext (payload + 16-byte tag) ...             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |      padding (random)         |  pad count (1..=PaddingMax)   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! The AEAD nonce is `SSRC || seq || 0x0000 || timestamp`, matching the server
//! exactly. The 12-byte RTP header is the associated data.

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use crate::wrap::WRAP_KEY_LEN;

/// Size of the RTP header used as AEAD associated data.
pub const RTP_HEADER_LEN: usize = 12;
/// Poly1305 tag length.
pub const AEAD_TAG_LEN: usize = 16;
/// Smallest possible wire packet: header + tag + one padding byte.
pub const MIN_WIRE_LEN: usize = RTP_HEADER_LEN + AEAD_TAG_LEN + 1;

/// Payload type for audio-shaped traffic.
pub const PAYLOAD_TYPE_AUDIO: u8 = 111;
/// Payload type for video-shaped traffic.
pub const PAYLOAD_TYPE_VIDEO: u8 = 96;

/// How packets are shaped on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObfsMode {
    /// PT 111, up to 24 padding bytes.
    Audio,
    /// PT 96, up to 60 padding bytes.
    Video,
}

impl ObfsMode {
    /// Parses the CLI/settings value. Unknown values fall back to `audio`,
    /// mirroring the reference client.
    pub fn parse(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "video" => ObfsMode::Video,
            _ => ObfsMode::Audio,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ObfsMode::Audio => "audio",
            ObfsMode::Video => "video",
        }
    }

    fn payload_type(self) -> u8 {
        match self {
            ObfsMode::Audio => PAYLOAD_TYPE_AUDIO,
            ObfsMode::Video => PAYLOAD_TYPE_VIDEO,
        }
    }

    fn padding_max(self) -> u8 {
        match self {
            ObfsMode::Audio => 24,
            ObfsMode::Video => 60,
        }
    }
}

/// Per-direction RTP state: a random SSRC plus the sequence/timestamp bases.
#[derive(Debug, Clone)]
pub struct ObfsState {
    ssrc: u32,
    init_seq: u16,
    init_ts: u32,
    count: u64,
    mode: ObfsMode,
}

impl ObfsState {
    /// Creates a fresh state with random SSRC, sequence and timestamp, exactly
    /// like the reference implementation.
    pub fn new(mode: ObfsMode) -> Self {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 6];
        rng.fill_bytes(&mut buf);
        ObfsState {
            ssrc: rng.next_u32(),
            init_seq: u16::from_be_bytes([buf[0], buf[1]]),
            init_ts: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            count: 0,
            mode,
        }
    }

    /// Creates a state pinned to a known SSRC (used by tests and by the server
    /// side of the protocol, which echoes the client's payload type).
    pub fn with_ssrc(mode: ObfsMode, ssrc: u32) -> Self {
        let mut state = Self::new(mode);
        state.ssrc = ssrc;
        state
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn mode(&self) -> ObfsMode {
        self.mode
    }

    /// Sequence number and timestamp for the next packet, following the
    /// reference `seq = init + c`, `ts = init + c*960 + (c>>16)` rule that
    /// mimics a 48 kHz RTP clock.
    fn next_header(&mut self) -> (u16, u32) {
        let c = self.count;
        self.count = self.count.wrapping_add(1);
        let seq = self.init_seq.wrapping_add(c as u16);
        let ts = self
            .init_ts
            .wrapping_add((c as u32).wrapping_mul(960))
            .wrapping_add((c >> 16) as u32);
        (seq, ts)
    }
}

fn build_nonce(ssrc: u32, seq: u16, ts: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..4].copy_from_slice(&ssrc.to_be_bytes());
    nonce[4..6].copy_from_slice(&seq.to_be_bytes());
    // nonce[6..8] stays zero, exactly like the server.
    nonce[8..12].copy_from_slice(&ts.to_be_bytes());
    nonce
}

fn cipher(key: &[u8]) -> Result<ChaCha20Poly1305> {
    if key.len() != WRAP_KEY_LEN {
        bail!("obfs: key must be {WRAP_KEY_LEN} bytes (got {})", key.len());
    }
    ChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("obfs: cipher init: {e}"))
}

/// Wraps a payload into an RTP-shaped AEAD packet.
pub fn wrap(key: &[u8], payload: &[u8], state: &mut ObfsState) -> Result<Vec<u8>> {
    if payload.is_empty() {
        bail!("obfs: refusing to wrap an empty payload");
    }
    let aead = cipher(key)?;
    let (seq, ts) = state.next_header();
    let mode = state.mode;

    let pad_rand = {
        let max = mode.padding_max();
        // 1..=max bytes of padding in total; pad_rand is the random part.
        let mut b = [0u8; 1];
        rand::thread_rng().fill_bytes(&mut b);
        (b[0] as usize) % (max as usize)
    };
    let pad_total = pad_rand + 1;

    let mut out = Vec::with_capacity(RTP_HEADER_LEN + payload.len() + AEAD_TAG_LEN + pad_total);
    out.push(0x80 | 0x20); // V=2, P=1
    out.push(mode.payload_type() & 0x7F);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&ts.to_be_bytes());
    out.extend_from_slice(&state.ssrc.to_be_bytes());

    let header: [u8; RTP_HEADER_LEN] = out[..RTP_HEADER_LEN].try_into().expect("header");
    let nonce = build_nonce(state.ssrc, seq, ts);
    let sealed = aead
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("obfs: encrypt failed"))?;
    out.extend_from_slice(&sealed);

    if pad_rand > 0 {
        let start = out.len();
        out.resize(start + pad_rand, 0);
        rand::thread_rng().fill_bytes(&mut out[start..]);
    }
    out.push(pad_total as u8);
    Ok(out)
}

/// Unwraps an RTP-shaped AEAD packet, returning the plaintext payload.
pub fn unwrap(key: &[u8], wire: &[u8]) -> Result<Vec<u8>> {
    if wire.len() < MIN_WIRE_LEN {
        bail!("obfs: packet too short ({} bytes)", wire.len());
    }
    if (wire[0] >> 6) != 2 {
        bail!("obfs: not an RTP v2 packet");
    }
    let seq = u16::from_be_bytes([wire[2], wire[3]]);
    let ts = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]);
    let ssrc = u32::from_be_bytes([wire[8], wire[9], wire[10], wire[11]]);

    let mut payload_end = wire.len();
    if wire[0] & 0x20 != 0 {
        let pad_len = wire[wire.len() - 1] as usize;
        if pad_len == 0 || pad_len > payload_end - RTP_HEADER_LEN {
            bail!("obfs: invalid padding length {pad_len}");
        }
        payload_end -= pad_len;
    }
    let ciphertext_len = payload_end.saturating_sub(RTP_HEADER_LEN);
    if ciphertext_len <= AEAD_TAG_LEN {
        bail!("obfs: no payload after stripping header/padding");
    }

    let aead = cipher(key)?;
    let nonce = build_nonce(ssrc, seq, ts);
    let header = &wire[..RTP_HEADER_LEN];
    let plain = aead
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &wire[RTP_HEADER_LEN..payload_end],
                aad: header,
            },
        )
        .map_err(|_| anyhow!("obfs: authentication failed (wrong password?)"))?;
    Ok(plain)
}

/// Cheap check used before attempting to unwrap: does this look like a packet
/// we produce?
pub fn is_rtp_packet(wire: &[u8]) -> bool {
    if wire.len() < MIN_WIRE_LEN {
        return false;
    }
    if (wire[0] >> 6) != 2 {
        return false;
    }
    let pt = wire[1] & 0x7F;
    pt == PAYLOAD_TYPE_AUDIO || pt == PAYLOAD_TYPE_VIDEO
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wrap::derive_wrap_key;

    fn key() -> [u8; WRAP_KEY_LEN] {
        derive_wrap_key("uVCF2Nf6dZK8hEKe").unwrap()
    }

    #[test]
    fn round_trips_audio_and_video() {
        let k = key();
        for mode in [ObfsMode::Audio, ObfsMode::Video] {
            let mut tx = ObfsState::new(mode);
            let mut rx = ObfsState::with_ssrc(mode, tx.ssrc());
            for size in [1usize, 17, 64, 1400] {
                let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
                let wire = wrap(&k, &payload, &mut tx).unwrap();
                assert!(is_rtp_packet(&wire), "wire packet must look like RTP");
                assert_eq!(wire[1] & 0x7F, mode.payload_type());
                let plain = unwrap(&k, &wire).unwrap();
                assert_eq!(plain, payload, "payload must survive a round trip");
                // rx state is only used for its SSRC here.
                let _ = &mut rx;
            }
        }
    }

    #[test]
    fn wire_header_matches_reference_layout() {
        let k = key();
        let mut state = ObfsState::with_ssrc(ObfsMode::Audio, 0xDEADBEEF);
        let wire = wrap(&k, b"hello", &mut state).unwrap();
        assert_eq!(wire[0], 0xA0, "V=2 + padding bit");
        assert_eq!(wire[1] & 0x7F, 111);
        assert_eq!(&wire[8..12], &0xDEADBEEFu32.to_be_bytes());
        // Padding is always present: at least one trailing length byte.
        assert!(wire[0] & 0x20 != 0);
        let pad = wire[wire.len() - 1] as usize;
        assert!((1..=24).contains(&pad));
    }

    #[test]
    fn rejects_wrong_key() {
        let mut state = ObfsState::new(ObfsMode::Audio);
        let wire = wrap(&key(), b"secret payload", &mut state).unwrap();
        let other = derive_wrap_key("wrong password").unwrap();
        assert!(unwrap(&other, &wire).is_err());
    }

    #[test]
    fn rejects_truncated_and_garbage_packets() {
        let k = key();
        assert!(unwrap(&k, &[]).is_err());
        assert!(unwrap(&k, &[0u8; 8]).is_err());
        let mut garbage = vec![0u8; 40];
        garbage[0] = 0x40; // not RTP v2
        assert!(unwrap(&k, &garbage).is_err());
        assert!(!is_rtp_packet(&garbage));
    }

    #[test]
    fn rejects_empty_payload_on_wrap() {
        let mut state = ObfsState::new(ObfsMode::Audio);
        assert!(wrap(&key(), b"", &mut state).is_err());
    }

    #[test]
    fn sequence_and_timestamp_follow_the_reference_formula() {
        let k = key();
        let mut state = ObfsState::new(ObfsMode::Audio);
        let first = wrap(&k, b"a", &mut state).unwrap();
        let second = wrap(&k, b"b", &mut state).unwrap();
        let seq1 = u16::from_be_bytes([first[2], first[3]]);
        let seq2 = u16::from_be_bytes([second[2], second[3]]);
        let ts1 = u32::from_be_bytes([first[4], first[5], first[6], first[7]]);
        let ts2 = u32::from_be_bytes([second[4], second[5], second[6], second[7]]);
        assert_eq!(seq2, seq1.wrapping_add(1));
        assert_eq!(ts2, ts1.wrapping_add(960));
    }

    #[test]
    fn mode_parsing_defaults_to_audio() {
        assert_eq!(ObfsMode::parse("video"), ObfsMode::Video);
        assert_eq!(ObfsMode::parse("AUDIO"), ObfsMode::Audio);
        assert_eq!(ObfsMode::parse("nonsense"), ObfsMode::Audio);
        assert_eq!(ObfsMode::parse(""), ObfsMode::Audio);
    }
}
