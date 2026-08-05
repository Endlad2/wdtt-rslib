use anyhow::{bail, Result};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, KeyInit, Nonce};
use rand::Rng;
use std::sync::Mutex;
use crate::wrap::wrapKeyLen;

pub fn getAEAD(key: &[u8]) -> Result<ChaCha20Poly1305> {
    if key.len() != wrapKeyLen { bail!("obfs: key must be {wrapKeyLen} bytes"); }
    ChaCha20Poly1305::new_from_slice(key).map_err(Into::into)
}
pub struct ObfsConfig { pub SSRC: u32, pub PayloadType: u8, pub PaddingMax: usize }
pub fn NewObfsConfig(mode: &str) -> ObfsConfig {
    let (PayloadType, PaddingMax) = if mode == "video" {(96, 60)} else {(111, 24)};
    ObfsConfig { SSRC: rand::thread_rng().gen(), PayloadType, PaddingMax }
}
pub struct ObfsState { initSeq: u16, initTs: u32, count: Mutex<u64> }
pub fn NewObfsState() -> ObfsState { ObfsState { initSeq: rand::thread_rng().gen(), initTs: rand::thread_rng().gen(), count: Mutex::new(0) } }
pub fn obfsBuildNonce(ssrc: u32, seq: u16, ts: u32) -> [u8; 12] {
    let mut n = [0; 12]; n[..4].copy_from_slice(&ssrc.to_be_bytes()); n[4..6].copy_from_slice(&seq.to_be_bytes()); n[8..].copy_from_slice(&ts.to_be_bytes()); n
}
pub fn obfsWrapPacket(key: &[u8], payload: &[u8], cfg: &ObfsConfig, state: &ObfsState) -> Result<Vec<u8>> {
    if payload.is_empty() { bail!("obfs: empty payload"); }
    let c = { let mut count = state.count.lock().unwrap(); let c = *count; *count += 1; c };
    let seq = state.initSeq.wrapping_add(c as u16); let ts = state.initTs.wrapping_add((c as u32).wrapping_mul(960)).wrapping_add((c >> 16) as u32);
    let mut header = [0u8; 12]; header[0] = 0xa0; header[1] = cfg.PayloadType & 0x7f; header[2..4].copy_from_slice(&seq.to_be_bytes()); header[4..8].copy_from_slice(&ts.to_be_bytes()); header[8..].copy_from_slice(&cfg.SSRC.to_be_bytes());
    let sealed = getAEAD(key)?.encrypt(Nonce::from_slice(&obfsBuildNonce(cfg.SSRC, seq, ts)), Payload { msg: payload, aad: &header }).map_err(|_| anyhow::anyhow!("obfs: auth"))?;
    let pad = if cfg.PaddingMax == 0 { 1 } else { rand::thread_rng().gen_range(0..cfg.PaddingMax) + 1 };
    let mut out = Vec::with_capacity(12 + sealed.len() + pad); out.extend_from_slice(&header); out.extend_from_slice(&sealed); out.extend((0..pad - 1).map(|_| rand::thread_rng().gen::<u8>())); out.push(pad as u8); Ok(out)
}
pub fn obfsUnwrapPacket(key: &[u8], wire: &[u8], dst: &mut [u8]) -> Result<usize> {
    if !obfsIsRTPPacket(wire) { bail!("obfs: not RTP v2"); } let pad = wire[wire.len()-1] as usize; if pad == 0 || pad > wire.len()-12 { bail!("obfs: invalid padding"); }
    let end = wire.len() - pad; let seq = u16::from_be_bytes(wire[2..4].try_into().unwrap()); let ts = u32::from_be_bytes(wire[4..8].try_into().unwrap()); let ssrc = u32::from_be_bytes(wire[8..12].try_into().unwrap());
    let plain = getAEAD(key)?.decrypt(Nonce::from_slice(&obfsBuildNonce(ssrc, seq, ts)), Payload { msg: &wire[12..end], aad: &wire[..12] }).map_err(|_| anyhow::anyhow!("obfs: auth"))?;
    if plain.len() > dst.len() { bail!("obfs: dst buffer too small"); } dst[..plain.len()].copy_from_slice(&plain); Ok(plain.len())
}
pub fn obfsIsRTPPacket(wire: &[u8]) -> bool { wire.len() >= 13 && wire[0] >> 6 == 2 && matches!(wire[1] & 0x7f, 111 | 96) }
