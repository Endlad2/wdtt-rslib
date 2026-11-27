// SPDX-License-Identifier: LGPL-2.1
//
//! WRAP key derivation.
//!
//! The WDTT server derives a 32-byte ChaCha20-Poly1305 key from the connection
//! password with HKDF-SHA256 and uses it to authenticate/encrypt every RTP
//! packet it exchanges with the client. The parameters below are part of the
//! wire contract with the server: changing any of them breaks compatibility.

use hkdf::Hkdf;
use sha2::Sha256;

/// Length of the derived WRAP key (ChaCha20-Poly1305 key size).
pub const WRAP_KEY_LEN: usize = 32;

/// HKDF salt, byte-for-byte identical to the server (`wrap.go`).
const WRAP_SALT: &[u8] = b"WDTT-WRAP-v1";
/// HKDF info string, identical to the server.
const WRAP_INFO: &[u8] = b"rtp-obfs/chacha20poly1305";

/// Derives the WRAP key from the connection password.
///
/// An empty password is an error: the server always wraps, so a client without
/// a key can never authenticate.
pub fn derive_wrap_key(password: &str) -> anyhow::Result<[u8; WRAP_KEY_LEN]> {
    if password.is_empty() {
        anyhow::bail!("connection password is empty: WRAP key cannot be derived");
    }
    let hk = Hkdf::<Sha256>::new(Some(WRAP_SALT), password.as_bytes());
    let mut key = [0u8; WRAP_KEY_LEN];
    hk.expand(WRAP_INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_password() {
        assert!(derive_wrap_key("").is_err());
    }

    #[test]
    fn derives_a_deterministic_32_byte_key() {
        let a = derive_wrap_key("secret").unwrap();
        let b = derive_wrap_key("secret").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), WRAP_KEY_LEN);
        // A different password must produce a different key.
        assert_ne!(a, derive_wrap_key("secret2").unwrap());
    }

    /// Known-answer test computed with the reference Go implementation
    /// (`deriveWrapKey` in the WDTT client). If this changes, the client stops
    /// being able to talk to a WDTT server.
    #[test]
    fn matches_reference_implementation() {
        let key = derive_wrap_key("uVCF2Nf6dZK8hEKe").unwrap();
        assert_eq!(
            hex::encode(key),
            "0dcffa215cce8383d5b738e7b7d593866a004ccd19ec83d7e7c3c7948736745c",
            "WRAP key derivation diverged from the server"
        );
    }
}
