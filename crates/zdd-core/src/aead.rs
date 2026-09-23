use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::error::{Error, Result};
use crate::secret::{Key32, SecretBytes};

pub const NONCE_LEN: usize = 24;

pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Sealed {
    #[serde(with = "crate::codec::base64_bytes")]
    bytes: Vec<u8>,
}

impl Sealed {
    pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() < Self::OVERHEAD {
            return Err(Error::length("sealed value", Self::OVERHEAD, bytes.len()));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn plaintext_len(&self) -> usize {
        self.bytes.len() - Self::OVERHEAD
    }
}

pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(key.expose().into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(Sealed { bytes: out })
}

pub fn unseal(key: &Key32, sealed: &Sealed, aad: &[u8]) -> Result<SecretBytes> {
    let bytes = sealed.as_bytes();
    if bytes.len() < Sealed::OVERHEAD {
        return Err(Error::Authentication);
    }

    let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.expose().into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Authentication)?;

    Ok(SecretBytes::new(plaintext))
}

pub fn wrap_key(kek: &Key32, key: &Key32, aad: &[u8]) -> Result<Sealed> {
    seal(kek, key.expose(), aad)
}

pub fn unwrap_key(kek: &Key32, sealed: &Sealed, aad: &[u8]) -> Result<Key32> {
    let plain = unseal(kek, sealed, aad)?;
    Key32::from_slice(plain.expose())
}

pub fn aad(components: &[&[u8]]) -> Vec<u8> {
    let total: usize = components.iter().map(|c| c.len() + 4).sum();
    let mut out = Vec::with_capacity(total);
    for c in components {
        out.extend_from_slice(&(c.len() as u32).to_be_bytes());
        out.extend_from_slice(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = Key32::random();
        let msg = b"the launch codes are in the second drawer";
        let sealed = seal(&key, msg, b"ctx").unwrap();
        let opened = unseal(&key, &sealed, b"ctx").unwrap();
        assert_eq!(opened.expose(), msg);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let key = Key32::random();
        let sealed = seal(&key, b"", b"").unwrap();
        assert_eq!(sealed.plaintext_len(), 0);
        assert_eq!(unseal(&key, &sealed, b"").unwrap().len(), 0);
    }

    #[test]
    fn wrong_key_fails() {
        let key = Key32::random();
        let other = Key32::random();
        let sealed = seal(&key, b"secret", b"ctx").unwrap();
        assert!(unseal(&other, &sealed, b"ctx").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = Key32::random();
        let sealed = seal(&key, b"secret", b"capsule-1").unwrap();
        assert!(unseal(&key, &sealed, b"capsule-2").is_err());
        assert!(unseal(&key, &sealed, b"").is_err());
    }

    #[test]
    fn every_bit_flip_is_caught() {
        let key = Key32::random();
        let sealed = seal(&key, b"0123456789abcdef", b"ctx").unwrap();

        for byte_idx in 0..sealed.as_bytes().len() {
            for bit in 0..8u32 {
                let mut corrupted = sealed.as_bytes().to_vec();
                corrupted[byte_idx] ^= 1 << bit;
                let corrupted = Sealed::from_bytes(corrupted).unwrap();
                assert!(
                    unseal(&key, &corrupted, b"ctx").is_err(),
                    "flipping bit {bit} of byte {byte_idx} went undetected"
                );
            }
        }
    }

    #[test]
    fn truncation_is_caught() {
        let key = Key32::random();
        let sealed = seal(&key, b"0123456789abcdef", b"ctx").unwrap();
        for cut in Sealed::OVERHEAD..sealed.as_bytes().len() {
            let truncated = Sealed::from_bytes(sealed.as_bytes()[..cut].to_vec()).unwrap();
            assert!(
                unseal(&key, &truncated, b"ctx").is_err(),
                "truncation to {cut} undetected"
            );
        }
    }

    #[test]
    fn nonces_do_not_repeat() {
        let key = Key32::random();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let sealed = seal(&key, b"same plaintext every time", b"same aad").unwrap();
            let nonce = sealed.as_bytes()[..NONCE_LEN].to_vec();
            assert!(seen.insert(nonce), "nonce reuse under a single key");
        }
    }

    #[test]
    fn ciphertexts_are_not_deterministic() {
        let key = Key32::random();
        let a = seal(&key, b"same", b"same").unwrap();
        let b = seal(&key, b"same", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn key_wrapping_round_trips() {
        let kek = Key32::random();
        let dek = Key32::random();
        let wrapped = wrap_key(&kek, &dek, b"ctx").unwrap();
        assert_eq!(unwrap_key(&kek, &wrapped, b"ctx").unwrap(), dek);
        assert!(unwrap_key(&Key32::random(), &wrapped, b"ctx").is_err());
    }

    #[test]
    fn aad_components_are_unambiguous() {
        assert_ne!(aad(&[b"ab", b"c"]), aad(&[b"a", b"bc"]));
        assert_ne!(aad(&[b"", b"abc"]), aad(&[b"abc", b""]));
        assert_eq!(aad(&[b"x", b"y"]), aad(&[b"x", b"y"]));
    }

    #[test]
    fn rejects_undersized_sealed_value() {
        assert!(Sealed::from_bytes(vec![0; Sealed::OVERHEAD - 1]).is_err());
        assert!(Sealed::from_bytes(vec![0; Sealed::OVERHEAD]).is_ok());
    }
}
