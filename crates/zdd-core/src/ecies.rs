use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};

use crate::aead::{self, Sealed};
use crate::error::{Error, Result};
use crate::identity::{RecipientIdentity, RecipientPublicKey, PUBLIC_KEY_LEN};
use crate::secret::{Key32, SecretBytes};

const ECIES_DOMAIN: &[u8] = b"zdd/v1/ecies-x25519-hkdf-sha256";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SealedToRecipient {
    #[serde(with = "crate::codec::base64_array")]
    pub ephemeral_public: [u8; PUBLIC_KEY_LEN],

    pub sealed: Sealed,
}

fn wrap_key_from_dh(
    shared: &[u8; 32],
    ephemeral_public: &[u8; PUBLIC_KEY_LEN],
    recipient_public: &[u8; PUBLIC_KEY_LEN],
) -> Key32 {
    let mut info = Vec::with_capacity(ECIES_DOMAIN.len() + 2 * PUBLIC_KEY_LEN);
    info.extend_from_slice(ECIES_DOMAIN);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);

    let shared_key = Key32::new(*shared);
    crate::kdf::derive_subkey_ctx(&shared_key, ECIES_DOMAIN, &info)
}

pub fn seal_to(
    recipient: &RecipientPublicKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedToRecipient> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral_secret);

    let shared = ephemeral_secret.diffie_hellman(&recipient.to_dalek());
    if !shared.was_contributory() {
        return Err(Error::format(
            "recipient public key",
            "key lies in a small subgroup and cannot be used",
        ));
    }

    let eph_bytes = ephemeral_public.to_bytes();
    let key = wrap_key_from_dh(shared.as_bytes(), &eph_bytes, &recipient.0);
    let sealed = aead::seal(&key, plaintext, aad)?;

    Ok(SealedToRecipient {
        ephemeral_public: eph_bytes,
        sealed,
    })
}

pub fn open_as(
    recipient: &RecipientIdentity,
    wrapped: &SealedToRecipient,
    aad: &[u8],
) -> Result<SecretBytes> {
    let ephemeral_public = X25519Public::from(wrapped.ephemeral_public);
    let shared = recipient.secret().diffie_hellman(&ephemeral_public);
    if !shared.was_contributory() {
        return Err(Error::Authentication);
    }

    let recipient_public = recipient.public().0;
    let key = wrap_key_from_dh(
        shared.as_bytes(),
        &wrapped.ephemeral_public,
        &recipient_public,
    );
    aead::unseal(&key, &wrapped.sealed, aad)
}

pub fn wrap_key_to(
    recipient: &RecipientPublicKey,
    key: &Key32,
    aad: &[u8],
) -> Result<SealedToRecipient> {
    seal_to(recipient, key.expose(), aad)
}

pub fn unwrap_key_as(
    recipient: &RecipientIdentity,
    wrapped: &SealedToRecipient,
    aad: &[u8],
) -> Result<Key32> {
    let plain = open_as(recipient, wrapped, aad)?;
    Key32::from_slice(plain.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let alex = RecipientIdentity::generate();
        let msg = b"the capsule data key goes here!!";
        let wrapped = seal_to(&alex.public(), msg, b"capsule-1/slot-0").unwrap();
        let opened = open_as(&alex, &wrapped, b"capsule-1/slot-0").unwrap();
        assert_eq!(opened.expose(), msg);
    }

    #[test]
    fn a_different_recipient_cannot_open_it() {
        let alex = RecipientIdentity::generate();
        let sam = RecipientIdentity::generate();
        let wrapped = seal_to(&alex.public(), b"for alex only", b"ctx").unwrap();
        assert!(open_as(&sam, &wrapped, b"ctx").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let alex = RecipientIdentity::generate();
        let wrapped = seal_to(&alex.public(), b"secret", b"capsule-1/slot-0").unwrap();
        assert!(open_as(&alex, &wrapped, b"capsule-2/slot-0").is_err());
        assert!(open_as(&alex, &wrapped, b"capsule-1/slot-1").is_err());
        assert!(open_as(&alex, &wrapped, b"").is_err());
    }

    #[test]
    fn each_wrap_uses_a_fresh_ephemeral_key() {
        let alex = RecipientIdentity::generate();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let w = seal_to(&alex.public(), b"same plaintext", b"same aad").unwrap();
            assert!(seen.insert(w.ephemeral_public), "ephemeral key reuse");
        }
    }

    #[test]
    fn identical_plaintexts_produce_different_ciphertexts() {
        let alex = RecipientIdentity::generate();
        let a = seal_to(&alex.public(), b"same", b"same").unwrap();
        let b = seal_to(&alex.public(), b"same", b"same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tampering_with_the_ephemeral_key_fails() {
        let alex = RecipientIdentity::generate();
        let mut wrapped = seal_to(&alex.public(), b"secret", b"ctx").unwrap();
        wrapped.ephemeral_public[0] ^= 1;
        assert!(open_as(&alex, &wrapped, b"ctx").is_err());
    }

    #[test]
    fn tampering_with_the_ciphertext_fails() {
        let alex = RecipientIdentity::generate();
        let wrapped = seal_to(&alex.public(), b"secret value here", b"ctx").unwrap();

        for i in 0..wrapped.sealed.as_bytes().len() {
            let mut bytes = wrapped.sealed.as_bytes().to_vec();
            bytes[i] ^= 0x80;
            let tampered = SealedToRecipient {
                ephemeral_public: wrapped.ephemeral_public,
                sealed: Sealed::from_bytes(bytes).unwrap(),
            };
            assert!(
                open_as(&alex, &tampered, b"ctx").is_err(),
                "byte {i} tamper undetected"
            );
        }
    }

    #[test]
    fn low_order_recipient_keys_are_refused() {
        let low_order: [[u8; 32]; 4] = [
            [0u8; 32],
            {
                let mut p = [0u8; 32];
                p[0] = 1;
                p
            },
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            [
                0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
                0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
                0xd0, 0x9f, 0x11, 0x57,
            ],
        ];

        for point in low_order {
            let bad = RecipientPublicKey(point);
            assert!(
                seal_to(&bad, b"secret", b"ctx").is_err(),
                "small-subgroup key {} was accepted",
                crate::codec::to_hex(&point)
            );
        }
    }

    #[test]
    fn key_wrapping_helpers_round_trip() {
        let alex = RecipientIdentity::generate();
        let cdk = Key32::random();
        let wrapped = wrap_key_to(&alex.public(), &cdk, b"capsule-1").unwrap();
        assert_eq!(unwrap_key_as(&alex, &wrapped, b"capsule-1").unwrap(), cdk);
    }

    #[test]
    fn owner_can_seal_to_themselves() {
        use crate::identity::VaultIdentity;
        let root = Key32::random();
        let owner = VaultIdentity::derive(&root);
        let own_pub = RecipientPublicKey(owner.public().agreement_public);

        let cdk = Key32::random();
        let wrapped = wrap_key_to(&own_pub, &cdk, b"capsule-1").unwrap();

        assert_eq!(
            unwrap_key_as(&owner.as_recipient(), &wrapped, b"capsule-1").unwrap(),
            cdk
        );
        assert_eq!(owner.as_recipient_public(), own_pub);
    }

    #[test]
    fn survives_json_transport() {
        let alex = RecipientIdentity::generate();
        let cdk = Key32::random();
        let wrapped = wrap_key_to(&alex.public(), &cdk, b"ctx").unwrap();
        let json = serde_json::to_string(&wrapped).unwrap();
        let back: SealedToRecipient = serde_json::from_str(&json).unwrap();
        assert_eq!(unwrap_key_as(&alex, &back, b"ctx").unwrap(), cdk);
    }

    #[test]
    fn a_recovered_recipient_can_still_open_old_capsules() {
        let seed = Key32::random();
        let alex = RecipientIdentity::from_recovery_seed(&seed);
        let cdk = Key32::random();
        let wrapped = wrap_key_to(&alex.public(), &cdk, b"capsule-1").unwrap();

        drop(alex);

        let restored = RecipientIdentity::from_recovery_seed(&seed);
        assert_eq!(
            unwrap_key_as(&restored, &wrapped, b"capsule-1").unwrap(),
            cdk
        );
    }
}
