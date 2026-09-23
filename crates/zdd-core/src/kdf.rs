use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};
use crate::secret::{Key32, SecretBytes};

pub mod label {

    pub const VIGIL_SIGNING: &[u8] = b"zdd/v1/vigil-signing-ed25519";

    pub const VAULT_AGREEMENT: &[u8] = b"zdd/v1/vault-agreement-x25519";

    pub const DURESS_SIGNING: &[u8] = b"zdd/v1/duress-signing-ed25519";

    pub const STORE_METADATA: &[u8] = b"zdd/v1/store-metadata-aead";

    pub const STORE_BLOB: &[u8] = b"zdd/v1/store-blob-aead";

    pub const STORE_LOG_CHAIN: &[u8] = b"zdd/v1/store-log-chain-mac";

    pub const CAPSULE_MANIFEST: &[u8] = b"zdd/v1/capsule-manifest-aead";

    pub const CAPSULE_PAYLOAD: &[u8] = b"zdd/v1/capsule-payload-stream";

    pub const RELEASE_GATE: &[u8] = b"zdd/v1/release-gate";

    pub const DURESS_CHANNEL: &[u8] = b"zdd/v1/duress-channel-aead";

    pub const TRUSTEE_POSSESSION: &[u8] = b"zdd/v1/trustee-possession-challenge";

    pub const UNLOCK_PASSPHRASE: &[u8] = b"zdd/v1/unlock-passphrase-kek";

    pub const UNLOCK_RECOVERY: &[u8] = b"zdd/v1/unlock-recovery-kek";

    pub const UNLOCK_HARDWARE: &[u8] = b"zdd/v1/unlock-hardware-kek";

    pub const UNLOCK_SOCIAL: &[u8] = b"zdd/v1/unlock-social-kek";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub m_cost: u32,

    pub t_cost: u32,

    pub p_cost: u32,
}

impl Argon2Params {
    pub const INTERACTIVE: Self = Self {
        m_cost: 64 * 1024,
        t_cost: 2,
        p_cost: 4,
    };

    pub const MODERATE: Self = Self {
        m_cost: 256 * 1024,
        t_cost: 3,
        p_cost: 4,
    };

    pub const PARANOID: Self = Self {
        m_cost: 1024 * 1024,
        t_cost: 4,
        p_cost: 4,
    };

    pub const MINIMUM: Self = Self {
        m_cost: 32 * 1024,
        t_cost: 2,
        p_cost: 1,
    };

    pub fn validate(&self) -> Result<()> {
        if self.m_cost < Self::MINIMUM.m_cost {
            return Err(Error::Kdf(format!(
                "memory cost {} KiB is below the {} KiB floor",
                self.m_cost,
                Self::MINIMUM.m_cost
            )));
        }
        if self.t_cost < Self::MINIMUM.t_cost {
            return Err(Error::Kdf(format!(
                "time cost {} is below the floor of {}",
                self.t_cost,
                Self::MINIMUM.t_cost
            )));
        }
        if self.p_cost == 0 || self.p_cost > 64 {
            return Err(Error::Kdf(format!(
                "parallelism {} out of range 1..=64",
                self.p_cost
            )));
        }

        if self.m_cost > 4 * 1024 * 1024 {
            return Err(Error::Kdf(format!(
                "memory cost {} KiB exceeds the 4 GiB ceiling",
                self.m_cost
            )));
        }
        Ok(())
    }

    fn to_argon(self) -> Result<Params> {
        Params::new(self.m_cost, self.t_cost, self.p_cost, Some(32))
            .map_err(|e| Error::Kdf(e.to_string()))
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::MODERATE
    }
}

const _: () = assert!(Argon2Params::MINIMUM.m_cost <= Argon2Params::INTERACTIVE.m_cost);
const _: () = assert!(Argon2Params::INTERACTIVE.m_cost < Argon2Params::MODERATE.m_cost);
const _: () = assert!(Argon2Params::MODERATE.m_cost < Argon2Params::PARANOID.m_cost);

pub const SALT_LEN: usize = 16;

pub fn derive_from_passphrase(
    passphrase: &SecretBytes,
    salt: &[u8],
    params: Argon2Params,
    label: &[u8],
) -> Result<Key32> {
    if salt.len() != SALT_LEN {
        return Err(Error::length("kdf salt", SALT_LEN, salt.len()));
    }
    params.validate()?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.to_argon()?);

    let mut salted = Vec::with_capacity(SALT_LEN + 1 + label.len());
    salted.extend_from_slice(salt);
    salted.push(0x1F);
    salted.extend_from_slice(label);

    let mut out = Key32::zeroed();
    argon
        .hash_password_into(passphrase.expose(), &salted, out.expose_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

pub fn random_salt() -> [u8; SALT_LEN] {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn calibrate(target_ms: u64) -> Argon2Params {
    use std::time::Instant;

    let probe = SecretBytes::from_slice(b"zdd-calibration-probe");
    let salt = [0x5Au8; SALT_LEN];

    let candidates = [
        Argon2Params::PARANOID,
        Argon2Params::MODERATE,
        Argon2Params::INTERACTIVE,
        Argon2Params::MINIMUM,
    ];

    for params in candidates {
        let start = Instant::now();
        let ok = derive_from_passphrase(&probe, &salt, params, b"calibrate").is_ok();
        let elapsed = start.elapsed().as_millis() as u64;
        if ok && elapsed <= target_ms {
            return params;
        }
    }

    Argon2Params::MINIMUM
}

pub fn derive_subkey(parent: &Key32, label: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(None, parent.expose());
    let mut out = Key32::zeroed();
    hk.expand(label, out.expose_mut())
        .expect("32 bytes is well within HKDF-SHA256's output limit");
    out
}

pub fn derive_subkey_ctx(parent: &Key32, label: &[u8], context: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(None, parent.expose());
    let mut info = Vec::with_capacity(label.len() + 1 + context.len());
    info.extend_from_slice(label);
    info.push(0x1F);
    info.extend_from_slice(context);

    let mut out = Key32::zeroed();
    hk.expand(&info, out.expose_mut())
        .expect("32 bytes is well within HKDF-SHA256's output limit");
    out
}

pub fn derive_combined(salt_secret: &Key32, ikm_secret: &Key32, label: &[u8]) -> Key32 {
    let hk = Hkdf::<Sha256>::new(Some(salt_secret.expose()), ikm_secret.expose());
    let mut out = Key32::zeroed();
    hk.expand(label, out.expose_mut())
        .expect("32 bytes is well within HKDF-SHA256's output limit");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretBytes {
        SecretBytes::from_slice(s.as_bytes())
    }

    #[test]
    fn passphrase_derivation_is_deterministic() {
        let salt = [1u8; SALT_LEN];
        let p = Argon2Params::MINIMUM;
        let a = derive_from_passphrase(&pw("hunter2"), &salt, p, label::UNLOCK_PASSPHRASE).unwrap();
        let b = derive_from_passphrase(&pw("hunter2"), &salt, p, label::UNLOCK_PASSPHRASE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_passphrase_different_key() {
        let salt = [1u8; SALT_LEN];
        let p = Argon2Params::MINIMUM;
        let a = derive_from_passphrase(&pw("hunter2"), &salt, p, label::UNLOCK_PASSPHRASE).unwrap();
        let b = derive_from_passphrase(&pw("hunter3"), &salt, p, label::UNLOCK_PASSPHRASE).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_different_key() {
        let p = Argon2Params::MINIMUM;
        let a = derive_from_passphrase(&pw("same"), &[1u8; SALT_LEN], p, label::UNLOCK_PASSPHRASE)
            .unwrap();
        let b = derive_from_passphrase(&pw("same"), &[2u8; SALT_LEN], p, label::UNLOCK_PASSPHRASE)
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_label_different_key() {
        let salt = [1u8; SALT_LEN];
        let p = Argon2Params::MINIMUM;
        let real = derive_from_passphrase(&pw("same"), &salt, p, label::UNLOCK_PASSPHRASE).unwrap();
        let duress = derive_from_passphrase(&pw("same"), &salt, p, label::UNLOCK_RECOVERY).unwrap();
        assert_ne!(real, duress);
    }

    #[test]
    fn rejects_wrong_salt_length() {
        let p = Argon2Params::MINIMUM;
        assert!(derive_from_passphrase(&pw("x"), &[0; 8], p, b"l").is_err());
        assert!(derive_from_passphrase(&pw("x"), &[0; 32], p, b"l").is_err());
    }

    #[test]
    fn rejects_downgraded_parameters() {
        let weak = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(weak.validate().is_err());
        assert!(derive_from_passphrase(&pw("x"), &[0; SALT_LEN], weak, b"l").is_err());

        let no_parallelism = Argon2Params {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 0,
        };
        assert!(no_parallelism.validate().is_err());

        let absurd = Argon2Params {
            m_cost: 64 * 1024 * 1024,
            t_cost: 3,
            p_cost: 1,
        };
        assert!(
            absurd.validate().is_err(),
            "must not honour a memory bomb in the header"
        );
    }

    #[test]
    fn presets_are_valid_and_ordered() {
        for p in [
            Argon2Params::MINIMUM,
            Argon2Params::INTERACTIVE,
            Argon2Params::MODERATE,
            Argon2Params::PARANOID,
        ] {
            p.validate().unwrap();
        }
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let root = Key32::new([9u8; 32]);
        let a = derive_subkey(&root, label::VIGIL_SIGNING);
        let b = derive_subkey(&root, label::VAULT_AGREEMENT);
        let c = derive_subkey(&root, label::DURESS_SIGNING);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);

        assert_eq!(a, derive_subkey(&root, label::VIGIL_SIGNING));
    }

    #[test]
    fn context_changes_the_subkey() {
        let root = Key32::new([9u8; 32]);
        let a = derive_subkey_ctx(&root, label::CAPSULE_MANIFEST, b"capsule-1");
        let b = derive_subkey_ctx(&root, label::CAPSULE_MANIFEST, b"capsule-2");
        assert_ne!(a, b);
        assert_eq!(
            a,
            derive_subkey_ctx(&root, label::CAPSULE_MANIFEST, b"capsule-1")
        );
    }

    #[test]
    fn context_separator_prevents_ambiguity() {
        let root = Key32::new([9u8; 32]);
        let a = derive_subkey_ctx(&root, b"ab", b"c");
        let b = derive_subkey_ctx(&root, b"a", b"bc");
        assert_ne!(a, b, "label/context boundary is ambiguous");
    }

    #[test]
    fn combined_derivation_needs_both_halves() {
        let relay = Key32::new([1u8; 32]);
        let quorum = Key32::new([2u8; 32]);
        let wrong_relay = Key32::new([3u8; 32]);
        let wrong_quorum = Key32::new([4u8; 32]);

        let real = derive_combined(&relay, &quorum, label::RELEASE_GATE);

        assert_ne!(
            real,
            derive_combined(&wrong_relay, &quorum, label::RELEASE_GATE)
        );
        assert_ne!(
            real,
            derive_combined(&relay, &wrong_quorum, label::RELEASE_GATE)
        );
        assert_eq!(real, derive_combined(&relay, &quorum, label::RELEASE_GATE));
    }

    #[test]
    fn combined_derivation_is_not_symmetric() {
        let a = Key32::new([1u8; 32]);
        let b = Key32::new([2u8; 32]);
        assert_ne!(
            derive_combined(&a, &b, label::RELEASE_GATE),
            derive_combined(&b, &a, label::RELEASE_GATE)
        );
    }

    #[test]
    fn all_labels_are_distinct() {
        let all = [
            label::VIGIL_SIGNING,
            label::VAULT_AGREEMENT,
            label::DURESS_SIGNING,
            label::STORE_METADATA,
            label::STORE_BLOB,
            label::STORE_LOG_CHAIN,
            label::CAPSULE_MANIFEST,
            label::CAPSULE_PAYLOAD,
            label::RELEASE_GATE,
            label::TRUSTEE_POSSESSION,
            label::UNLOCK_PASSPHRASE,
            label::UNLOCK_RECOVERY,
            label::DURESS_CHANNEL,
            label::UNLOCK_HARDWARE,
            label::UNLOCK_SOCIAL,
        ];
        let mut seen = std::collections::HashSet::new();
        for l in all {
            assert!(
                seen.insert(l),
                "duplicate domain-separation label: {:?}",
                std::str::from_utf8(l)
            );
        }
    }
}
