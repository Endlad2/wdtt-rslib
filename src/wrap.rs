use anyhow::{bail, Result};
use hkdf::Hkdf;
use sha2::Sha256;

pub const wrapKeyLen: usize = 32;

pub fn deriveWrapKey(password: &str) -> Result<Vec<u8>> {
    if password.is_empty() { bail!("empty password"); }
    let hk = Hkdf::<Sha256>::new(Some(b"WDTT-WRAP-v1"), password.as_bytes());
    let mut key = vec![0; wrapKeyLen];
    hk.expand(b"rtp-obfs/chacha20poly1305", &mut key)
        .map_err(|_| anyhow::anyhow!("derive wrap key"))?;
    Ok(key)
}
