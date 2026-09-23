use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::codec;
use crate::error::{Error, Result};
use crate::kdf::{self, label};
use crate::secret::Key32;

pub const PUBLIC_KEY_LEN: usize = 32;

pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Fingerprint(#[serde(with = "crate::codec::base64_array")] pub [u8; 32]);

impl Fingerprint {
    pub fn derive(domain: &[u8], data: &[u8]) -> Self {
        Self::of(domain, data)
    }

    fn of(domain: &[u8], key_bytes: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zdd/v1/fingerprint");
        hasher.update(&(domain.len() as u32).to_be_bytes());
        hasher.update(domain);
        hasher.update(key_bytes);
        Self(*hasher.finalize().as_bytes())
    }

    pub fn hex(&self) -> String {
        codec::to_hex(&self.0)
    }

    pub fn short(&self) -> String {
        codec::fingerprint_string(&self.0, 4)
    }

    pub fn seal_seed(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct VaultIdentity {
    vigil: SigningKey,
    duress: SigningKey,
    agreement: X25519Secret,
}

impl core::fmt::Debug for VaultIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultIdentity")
            .field("vigil", &self.public().vigil_fingerprint().short())
            .field("private_keys", &"redacted")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultPublicIdentity {
    #[serde(with = "crate::codec::base64_array")]
    pub vigil_verifying: [u8; PUBLIC_KEY_LEN],
    #[serde(with = "crate::codec::base64_array")]
    pub agreement_public: [u8; PUBLIC_KEY_LEN],
}

impl VaultIdentity {
    pub fn derive(root: &Key32) -> Self {
        let vigil_seed = kdf::derive_subkey(root, label::VIGIL_SIGNING);
        let duress_seed = kdf::derive_subkey(root, label::DURESS_SIGNING);
        let agreement_seed = kdf::derive_subkey(root, label::VAULT_AGREEMENT);

        Self {
            vigil: SigningKey::from_bytes(vigil_seed.expose()),
            duress: SigningKey::from_bytes(duress_seed.expose()),
            agreement: X25519Secret::from(*agreement_seed.expose()),
        }
    }

    pub fn public(&self) -> VaultPublicIdentity {
        VaultPublicIdentity {
            vigil_verifying: self.vigil.verifying_key().to_bytes(),
            agreement_public: X25519Public::from(&self.agreement).to_bytes(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.vigil.sign(message).to_bytes()
    }

    pub fn sign_duress(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.duress.sign(message).to_bytes()
    }

    pub fn duress_verifying(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.duress.verifying_key().to_bytes()
    }

    pub fn as_recipient(&self) -> RecipientIdentity {
        RecipientIdentity::from_x25519(self.agreement.clone())
    }

    pub fn as_recipient_public(&self) -> RecipientPublicKey {
        RecipientPublicKey(X25519Public::from(&self.agreement).to_bytes())
    }
}

impl VaultPublicIdentity {
    pub fn vigil_fingerprint(&self) -> Fingerprint {
        Fingerprint::of(b"vigil-ed25519", &self.vigil_verifying)
    }

    pub fn agreement_fingerprint(&self) -> Fingerprint {
        Fingerprint::of(b"agreement-x25519", &self.agreement_public)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.vigil_verifying).map_err(|_| Error::Signature)?;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        vk.verify(message, &sig).map_err(|_| Error::Signature)
    }
}

pub fn verify_with(
    verifying_key: &[u8; PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let vk = VerifyingKey::from_bytes(verifying_key).map_err(|_| Error::Signature)?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    vk.verify(message, &sig).map_err(|_| Error::Signature)
}

pub struct RecipientIdentity {
    secret: X25519Secret,
}

impl core::fmt::Debug for RecipientIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientIdentity")
            .field("public", &self.public().fingerprint().short())
            .field("secret", &"redacted")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientPublicKey(
    #[serde(with = "crate::codec::base64_array")] pub [u8; PUBLIC_KEY_LEN],
);

impl RecipientIdentity {
    pub fn generate() -> Self {
        Self {
            secret: X25519Secret::random_from_rng(rand::rngs::OsRng),
        }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let key = Key32::from_slice(bytes)?;
        Ok(Self {
            secret: X25519Secret::from(*key.expose()),
        })
    }

    pub fn from_recovery_seed(seed: &Key32) -> Self {
        let derived = kdf::derive_subkey(seed, b"zdd/v1/recipient-x25519");
        Self {
            secret: X25519Secret::from(*derived.expose()),
        }
    }

    pub fn public(&self) -> RecipientPublicKey {
        RecipientPublicKey(X25519Public::from(&self.secret).to_bytes())
    }

    pub fn export_secret(&self) -> Key32 {
        Key32::new(self.secret.to_bytes())
    }

    pub(crate) fn secret(&self) -> &X25519Secret {
        &self.secret
    }

    pub(crate) fn from_x25519(secret: X25519Secret) -> Self {
        Self { secret }
    }
}

impl RecipientPublicKey {
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(b"recipient-x25519", &self.0)
    }

    pub(crate) fn to_dalek(self) -> X25519Public {
        X25519Public::from(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_derivation_is_deterministic() {
        let root = Key32::new([42u8; 32]);
        let a = VaultIdentity::derive(&root);
        let b = VaultIdentity::derive(&root);
        assert_eq!(a.public(), b.public());
        assert_eq!(a.duress_verifying(), b.duress_verifying());
    }

    #[test]
    fn recovered_root_yields_the_same_signing_identity() {
        let root = Key32::random();
        let original = VaultIdentity::derive(&root);
        let message = b"check-in #17";
        let sig = original.sign(message);

        let restored = VaultIdentity::derive(&root.duplicate());
        assert_eq!(restored.public(), original.public());
        restored.public().verify(message, &sig).unwrap();
    }

    #[test]
    fn different_roots_yield_different_identities() {
        let a = VaultIdentity::derive(&Key32::new([1u8; 32]));
        let b = VaultIdentity::derive(&Key32::new([2u8; 32]));
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn derived_keys_are_independent() {
        let id = VaultIdentity::derive(&Key32::random());
        let pubkeys = id.public();
        assert_ne!(pubkeys.vigil_verifying, pubkeys.agreement_public);
        assert_ne!(pubkeys.vigil_verifying, id.duress_verifying());
        assert_ne!(pubkeys.agreement_public, id.duress_verifying());
    }

    #[test]
    fn signatures_verify() {
        let id = VaultIdentity::derive(&Key32::random());
        let msg = b"I am still here";
        let sig = id.sign(msg);
        id.public().verify(msg, &sig).unwrap();
    }

    #[test]
    fn signatures_reject_tampering() {
        let id = VaultIdentity::derive(&Key32::random());
        let msg = b"I am still here";
        let sig = id.sign(msg);

        assert!(id.public().verify(b"I am not here", &sig).is_err());

        let mut bad = sig;
        bad[0] ^= 1;
        assert!(id.public().verify(msg, &bad).is_err());
    }

    #[test]
    fn a_different_identity_cannot_forge_a_checkin() {
        let real = VaultIdentity::derive(&Key32::random());
        let impostor = VaultIdentity::derive(&Key32::random());
        let msg = b"check-in";
        let forged = impostor.sign(msg);
        assert!(real.public().verify(msg, &forged).is_err());
    }

    #[test]
    fn duress_signature_is_opaque_to_the_relay() {
        let id = VaultIdentity::derive(&Key32::random());
        let msg = b"check-in under duress";
        let duress_sig = id.sign_duress(msg);
        let normal_sig = id.sign(msg);

        assert_eq!(duress_sig.len(), normal_sig.len());

        assert!(id.public().verify(msg, &duress_sig).is_err());

        verify_with(&id.duress_verifying(), msg, &duress_sig).unwrap();
    }

    #[test]
    fn duress_key_is_not_in_the_published_identity() {
        let id = VaultIdentity::derive(&Key32::random());
        let published = serde_json::to_string(&id.public()).unwrap();
        let duress_b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(id.duress_verifying())
        };
        assert!(
            !published.contains(&duress_b64),
            "publishing the duress key announces that a duress path exists"
        );
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let id = VaultIdentity::derive(&Key32::new([7u8; 32]));
        let p = id.public();
        assert_eq!(p.vigil_fingerprint(), p.vigil_fingerprint());
        assert_ne!(p.vigil_fingerprint(), p.agreement_fingerprint());
    }

    #[test]
    fn fingerprints_are_domain_separated() {
        let bytes = [3u8; 32];
        assert_ne!(
            Fingerprint::of(b"vigil-ed25519", &bytes),
            Fingerprint::of(b"agreement-x25519", &bytes)
        );
    }

    #[test]
    fn short_fingerprint_is_readable() {
        let fp = Fingerprint(
            [0x9f, 0x2a, 0xc4, 0x1d, 0x88, 0xbe, 0x01, 0x73]
                .iter()
                .copied()
                .chain(std::iter::repeat(0))
                .take(32)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        assert_eq!(fp.short(), "9f2a-c41d-88be-0173");
        assert_eq!(fp.short().len(), 19);
    }

    #[test]
    fn recipient_keys_are_unique() {
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();
        assert_ne!(a.public(), b.public());
    }

    #[test]
    fn recipient_survives_export_and_reimport() {
        let original = RecipientIdentity::generate();
        let exported = original.export_secret();
        let restored = RecipientIdentity::from_secret_bytes(exported.expose()).unwrap();
        assert_eq!(original.public(), restored.public());
    }

    #[test]
    fn recipient_recovery_seed_is_deterministic() {
        let seed = Key32::new([11u8; 32]);
        let a = RecipientIdentity::from_recovery_seed(&seed);
        let b = RecipientIdentity::from_recovery_seed(&seed);
        assert_eq!(a.public(), b.public());

        let other = RecipientIdentity::from_recovery_seed(&Key32::new([12u8; 32]));
        assert_ne!(a.public(), other.public());
    }

    #[test]
    fn debug_never_reveals_private_keys() {
        let id = VaultIdentity::derive(&Key32::random());
        assert!(format!("{id:?}").contains("redacted"));
        let r = RecipientIdentity::generate();
        assert!(format!("{r:?}").contains("redacted"));
    }

    #[test]
    fn public_identity_survives_json() {
        let id = VaultIdentity::derive(&Key32::random());
        let json = serde_json::to_string(&id.public()).unwrap();
        let back: VaultPublicIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id.public());
    }
}
