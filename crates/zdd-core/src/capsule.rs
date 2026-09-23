use std::collections::BTreeMap;

use crate::aead::{self, Sealed};
use crate::clock::Timestamp;
use crate::error::{Error, Result};
use crate::identity::{Fingerprint, RecipientIdentity, RecipientPublicKey, VaultIdentity};
use crate::kdf::{self, label};
use crate::release::{self, ReleaseGate};
use crate::secret::{Key32, SecretBytes};
use crate::stream::StreamPrefix;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct CapsuleId(#[serde(with = "crate::codec::base64_array")] pub [u8; 16]);

impl CapsuleId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Self(id)
    }

    pub fn short(&self) -> String {
        crate::codec::fingerprint_string(&self.0, 3)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    File,
    Directory,
    Note,
    Credential,
    TotpSeed,
    SshKey,
    GpgKey,
    SeedPhrase,
    RecoveryCodes,
    Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub kind: EntryKind,

    #[serde(with = "crate::codec::base64_array")]
    pub content_hash: [u8; 32],

    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub name: String,

    pub note: Option<String>,
    pub entries: Vec<ManifestEntry>,

    pub recipient_labels: BTreeMap<u8, String>,
    pub total_bytes: u64,
}

impl Manifest {
    fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Encoding(e.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| Error::Encoding(e.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecipientSlot {
    pub id: u8,
    pub public_key: RecipientPublicKey,

    pub tier: u8,

    pub claim_window: u64,

    pub key_verified_at: Option<Timestamp>,

    pub key_rotated_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GatedKeySlot {
    pub recipient_id: u8,

    pub gated: Sealed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PayloadRef {
    pub prefix: StreamPrefix,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,

    #[serde(with = "crate::codec::base64_array")]
    pub blob_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Capsule {
    #[serde(with = "crate::codec::base64_array")]
    pub magic: [u8; 8],
    pub version: u16,
    pub id: CapsuleId,
    pub created_at: Timestamp,

    pub gate: ReleaseGate,
    pub recipients: Vec<RecipientSlot>,
    pub key_slots: Vec<GatedKeySlot>,

    pub owner_slot: crate::ecies::SealedToRecipient,

    pub manifest: Sealed,

    pub payload: Option<PayloadRef>,

    pub is_rehearsal: bool,
}

fn manifest_aad(id: &CapsuleId) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/capsule-manifest", &id.0])
}

fn recipient_aad(id: &CapsuleId, recipient_id: u8) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/capsule-recipient", &id.0, &[recipient_id]])
}

fn gate_aad(id: &CapsuleId, recipient_id: u8) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/capsule-gate", &id.0, &[recipient_id]])
}

fn owner_aad(id: &CapsuleId) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/capsule-owner", &id.0])
}

pub struct CapsuleDraft {
    pub capsule: Capsule,

    pub cdk: Key32,

    pub gate_material: release::GateMaterial,
}

impl core::fmt::Debug for CapsuleDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CapsuleDraft")
            .field("id", &self.capsule.id.short())
            .field("cdk", &"redacted")
            .field("gate_material", &self.gate_material)
            .finish()
    }
}

impl Capsule {
    pub fn payload_key(cdk: &Key32) -> Key32 {
        kdf::derive_subkey(cdk, label::CAPSULE_PAYLOAD)
    }

    fn manifest_key(cdk: &Key32) -> Key32 {
        kdf::derive_subkey(cdk, label::CAPSULE_MANIFEST)
    }

    pub fn seal(&self) -> Fingerprint {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id.0);
        data.extend_from_slice(&self.gate.gate_id.0);

        let mut keys: Vec<[u8; 32]> = self.recipients.iter().map(|r| r.public_key.0).collect();
        keys.sort_unstable();
        for k in keys {
            data.extend_from_slice(&k);
        }
        Fingerprint::derive(b"capsule-seal", &data)
    }

    pub fn create(
        owner: &VaultIdentity,
        recipients: Vec<RecipientSlot>,
        gate_policy: crate::release::GatePolicy,
        manifest: &Manifest,
        created_at: Timestamp,
    ) -> Result<CapsuleDraft> {
        if recipients.is_empty() {
            return Err(Error::format(
                "capsule",
                "a capsule needs at least one recipient",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for r in &recipients {
            if !seen.insert(r.id) {
                return Err(Error::format(
                    "capsule",
                    format!("duplicate recipient slot id {}", r.id),
                ));
            }
        }

        let id = CapsuleId::random();
        let cdk = Key32::random();
        let (gate, gate_material) = release::create(gate_policy)?;

        let mut key_slots = Vec::with_capacity(recipients.len());
        for r in &recipients {
            let inner = crate::ecies::wrap_key_to(&r.public_key, &cdk, &recipient_aad(&id, r.id))?;
            let encoded = serde_json::to_vec(&inner).map_err(|e| Error::Encoding(e.to_string()))?;
            let gated = aead::seal(&gate_material.release_key, &encoded, &gate_aad(&id, r.id))?;
            key_slots.push(GatedKeySlot {
                recipient_id: r.id,
                gated,
            });
        }

        let owner_slot =
            crate::ecies::wrap_key_to(&owner.as_recipient_public(), &cdk, &owner_aad(&id))?;

        let manifest_sealed = aead::seal(
            &Self::manifest_key(&cdk),
            &manifest.encode()?,
            &manifest_aad(&id),
        )?;

        Ok(CapsuleDraft {
            capsule: Capsule {
                magic: *crate::CAPSULE_MAGIC,
                version: crate::FORMAT_VERSION,
                id,
                created_at,
                gate,
                recipients,
                key_slots,
                owner_slot,
                manifest: manifest_sealed,
                payload: None,
                is_rehearsal: false,
            },
            cdk,
            gate_material,
        })
    }

    pub fn attach_payload(&mut self, payload: PayloadRef) {
        self.payload = Some(payload);
    }

    pub fn open_as_owner(&self, owner: &VaultIdentity) -> Result<Key32> {
        crate::ecies::unwrap_key_as(
            &owner.as_recipient(),
            &self.owner_slot,
            &owner_aad(&self.id),
        )
    }

    pub fn open_as_recipient(
        &self,
        recipient: &RecipientIdentity,
        recipient_id: u8,
        release_key: &Key32,
    ) -> Result<Key32> {
        let slot = self
            .key_slots
            .iter()
            .find(|s| s.recipient_id == recipient_id)
            .ok_or_else(|| {
                Error::format("capsule", format!("no slot for recipient {recipient_id}"))
            })?;

        let encoded = aead::unseal(release_key, &slot.gated, &gate_aad(&self.id, recipient_id))?;
        let inner: crate::ecies::SealedToRecipient =
            serde_json::from_slice(encoded.expose()).map_err(|e| Error::Encoding(e.to_string()))?;

        crate::ecies::unwrap_key_as(recipient, &inner, &recipient_aad(&self.id, recipient_id))
    }

    pub fn read_manifest(&self, cdk: &Key32) -> Result<Manifest> {
        let bytes = aead::unseal(
            &Self::manifest_key(cdk),
            &self.manifest,
            &manifest_aad(&self.id),
        )?;
        Manifest::decode(bytes.expose())
    }

    pub fn write_manifest(&mut self, cdk: &Key32, manifest: &Manifest) -> Result<()> {
        self.manifest = aead::seal(
            &Self::manifest_key(cdk),
            &manifest.encode()?,
            &manifest_aad(&self.id),
        )?;
        Ok(())
    }

    pub fn rotate_recipient_key(
        &mut self,
        cdk: &Key32,
        release_key: &Key32,
        recipient_id: u8,
        new_public_key: RecipientPublicKey,
        now: Timestamp,
    ) -> Result<()> {
        let slot = self
            .recipients
            .iter_mut()
            .find(|r| r.id == recipient_id)
            .ok_or_else(|| Error::format("capsule", format!("no recipient {recipient_id}")))?;
        slot.public_key = new_public_key;

        slot.key_verified_at = None;
        slot.key_rotated_at = Some(now);

        let inner = crate::ecies::wrap_key_to(
            &new_public_key,
            cdk,
            &recipient_aad(&self.id, recipient_id),
        )?;
        let encoded = serde_json::to_vec(&inner).map_err(|e| Error::Encoding(e.to_string()))?;
        let gated = aead::seal(release_key, &encoded, &gate_aad(&self.id, recipient_id))?;

        match self
            .key_slots
            .iter_mut()
            .find(|s| s.recipient_id == recipient_id)
        {
            Some(existing) => existing.gated = gated,
            None => self.key_slots.push(GatedKeySlot {
                recipient_id,
                gated,
            }),
        }
        Ok(())
    }

    pub fn revoke_recipient(&mut self, recipient_id: u8) -> Result<()> {
        if !self.recipients.iter().any(|r| r.id == recipient_id) {
            return Err(Error::format(
                "capsule",
                format!("no recipient {recipient_id}"),
            ));
        }
        if self.recipients.len() == 1 {
            return Err(Error::format(
                "capsule",
                "cannot revoke the only recipient; delete the capsule instead",
            ));
        }
        self.recipients.retain(|r| r.id != recipient_id);
        self.key_slots.retain(|s| s.recipient_id != recipient_id);
        Ok(())
    }

    pub fn rotate_gate(
        &mut self,
        cdk: &Key32,
        policy: crate::release::GatePolicy,
    ) -> Result<release::GateMaterial> {
        let (gate, material) = release::create(policy)?;

        let mut slots = Vec::with_capacity(self.recipients.len());
        for r in &self.recipients {
            let inner =
                crate::ecies::wrap_key_to(&r.public_key, cdk, &recipient_aad(&self.id, r.id))?;
            let encoded = serde_json::to_vec(&inner).map_err(|e| Error::Encoding(e.to_string()))?;
            let gated = aead::seal(&material.release_key, &encoded, &gate_aad(&self.id, r.id))?;
            slots.push(GatedKeySlot {
                recipient_id: r.id,
                gated,
            });
        }

        self.gate = gate;
        self.key_slots = slots;
        Ok(material)
    }

    pub fn eligible_recipients(
        &self,
        released_at: Timestamp,
        now: Timestamp,
        claimed: &[u8],
    ) -> Vec<u8> {
        let mut tiers: Vec<u8> = self.recipients.iter().map(|r| r.tier).collect();
        tiers.sort_unstable();
        tiers.dedup();

        let mut eligible = Vec::new();
        let mut opens_at = released_at;

        for tier in tiers {
            let in_tier: Vec<&RecipientSlot> =
                self.recipients.iter().filter(|r| r.tier == tier).collect();

            if now >= opens_at {
                for r in &in_tier {
                    eligible.push(r.id);
                }
            }

            if in_tier.iter().any(|r| claimed.contains(&r.id)) {
                break;
            }
            let window = in_tier.iter().map(|r| r.claim_window).max().unwrap_or(0);
            opens_at = opens_at.plus_secs(window);
        }

        eligible
    }

    pub fn validate(&self) -> Result<()> {
        if &self.magic != crate::CAPSULE_MAGIC {
            return Err(Error::format("capsule", "wrong magic bytes"));
        }
        if self.version > crate::FORMAT_VERSION {
            return Err(Error::format(
                "capsule",
                format!(
                    "written by a newer version ({} > {})",
                    self.version,
                    crate::FORMAT_VERSION
                ),
            ));
        }
        if self.recipients.is_empty() {
            return Err(Error::format("capsule", "no recipients"));
        }

        for r in &self.recipients {
            if !self.key_slots.iter().any(|s| s.recipient_id == r.id) {
                return Err(Error::format(
                    "capsule",
                    format!("recipient {} has no wrapped key", r.id),
                ));
            }
        }

        for s in &self.key_slots {
            if !self.recipients.iter().any(|r| r.id == s.recipient_id) {
                return Err(Error::format(
                    "capsule",
                    format!("key slot for unknown recipient {}", s.recipient_id),
                ));
            }
        }
        Ok(())
    }
}

pub fn simple_recipient(id: u8, public_key: RecipientPublicKey) -> RecipientSlot {
    RecipientSlot {
        id,
        public_key,
        tier: 0,
        claim_window: 0,
        key_verified_at: None,
        key_rotated_at: None,
    }
}

pub fn wrap_for_recipient_passphrase(
    cdk: &Key32,
    passphrase: &SecretBytes,
    capsule_id: &CapsuleId,
    argon: kdf::Argon2Params,
) -> Result<(Sealed, [u8; kdf::SALT_LEN])> {
    let salt = kdf::random_salt();
    let kek =
        kdf::derive_from_passphrase(passphrase, &salt, argon, b"zdd/v1/recipient-passphrase")?;
    let sealed = aead::seal(
        &kek,
        cdk.expose(),
        &aead::aad(&[b"zdd/v1/recipient-passphrase", &capsule_id.0]),
    )?;
    Ok((sealed, salt))
}

pub fn unwrap_with_recipient_passphrase(
    sealed: &Sealed,
    passphrase: &SecretBytes,
    salt: &[u8; kdf::SALT_LEN],
    capsule_id: &CapsuleId,
    argon: kdf::Argon2Params,
) -> Result<Key32> {
    let kek = kdf::derive_from_passphrase(passphrase, salt, argon, b"zdd/v1/recipient-passphrase")?;
    let plain = aead::unseal(
        &kek,
        sealed,
        &aead::aad(&[b"zdd/v1/recipient-passphrase", &capsule_id.0]),
    )?;
    Key32::from_slice(plain.expose())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::release::GatePolicy;

    const T0: Timestamp = Timestamp(1_800_000_000);

    fn policy() -> GatePolicy {
        GatePolicy::RelayAndQuorum {
            threshold: 3,
            total: 5,
        }
    }

    fn manifest() -> Manifest {
        let mut labels = BTreeMap::new();
        labels.insert(0u8, "Alex".to_string());
        Manifest {
            name: "For Alex, about the house".to_string(),
            note: Some("Read the letter first.".to_string()),
            entries: vec![ManifestEntry {
                path: "letter.md".to_string(),
                size: 2048,
                kind: EntryKind::Note,
                content_hash: [1u8; 32],
                offset: 0,
            }],
            recipient_labels: labels,
            total_bytes: 2048,
        }
    }

    struct Scene {
        owner: VaultIdentity,
        alex: RecipientIdentity,
        draft: CapsuleDraft,
    }

    fn scene() -> Scene {
        let owner = VaultIdentity::derive(&Key32::random());
        let alex = RecipientIdentity::generate();
        let draft = Capsule::create(
            &owner,
            vec![simple_recipient(0, alex.public())],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();
        Scene { owner, alex, draft }
    }

    #[test]
    fn a_recipient_needs_both_the_release_key_and_their_own() {
        let s = scene();
        let capsule = &s.draft.capsule;
        let release_key = &s.draft.gate_material.release_key;

        let cdk = capsule.open_as_recipient(&s.alex, 0, release_key).unwrap();
        assert_eq!(cdk, s.draft.cdk);

        let stranger = RecipientIdentity::generate();
        assert!(capsule
            .open_as_recipient(&stranger, 0, release_key)
            .is_err());

        assert!(capsule
            .open_as_recipient(&s.alex, 0, &Key32::random())
            .is_err());
    }

    #[test]
    fn the_relay_learns_nothing_even_with_the_release_key() {
        let s = scene();
        let relay_view = serde_json::to_string(&s.draft.capsule).unwrap();
        let capsule: Capsule = serde_json::from_str(&relay_view).unwrap();

        let not_alex = RecipientIdentity::generate();
        assert!(capsule
            .open_as_recipient(&not_alex, 0, &s.draft.gate_material.release_key)
            .is_err());
        assert!(capsule.read_manifest(&Key32::random()).is_err());
    }

    #[test]
    fn a_full_quorum_release_opens_the_capsule() {
        let s = scene();
        let gate = &s.draft.capsule.gate;
        let relay_share = s.draft.gate_material.relay_share.as_ref().unwrap();

        let release_key = release::assemble(
            gate,
            Some(relay_share),
            &s.draft.gate_material.trustee_shares[..3],
        )
        .unwrap();

        let cdk = s
            .draft
            .capsule
            .open_as_recipient(&s.alex, 0, &release_key)
            .unwrap();
        let read = s.draft.capsule.read_manifest(&cdk).unwrap();
        assert_eq!(read.name, "For Alex, about the house");
        assert_eq!(read.recipient_labels.get(&0).unwrap(), "Alex");
    }

    #[test]
    fn a_short_quorum_cannot_open_the_capsule() {
        let s = scene();
        let gate = &s.draft.capsule.gate;
        let relay_share = s.draft.gate_material.relay_share.as_ref().unwrap();
        assert!(release::assemble(
            gate,
            Some(relay_share),
            &s.draft.gate_material.trustee_shares[..2]
        )
        .is_err());
    }

    #[test]
    fn the_owner_can_always_reopen_their_own_capsule() {
        let s = scene();
        let cdk = s.draft.capsule.open_as_owner(&s.owner).unwrap();
        assert_eq!(cdk, s.draft.cdk);
        let read = s.draft.capsule.read_manifest(&cdk).unwrap();
        assert_eq!(read.name, "For Alex, about the house");
    }

    #[test]
    fn another_owner_cannot_open_it() {
        let s = scene();
        let other = VaultIdentity::derive(&Key32::random());
        assert!(s.draft.capsule.open_as_owner(&other).is_err());
    }

    #[test]
    fn descriptive_metadata_never_leaves_the_manifest() {
        let s = scene();
        let wire = serde_json::to_string(&s.draft.capsule).unwrap();

        for secret in [
            "For Alex, about the house",
            "Read the letter first.",
            "letter.md",
            "Alex",
        ] {
            assert!(
                !wire.contains(secret),
                "{secret:?} leaked into the capsule the relay stores"
            );
        }
    }

    #[test]
    fn keys_never_appear_in_the_serialised_capsule() {
        let s = scene();
        let wire = serde_json::to_string(&s.draft.capsule).unwrap();
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;

        assert!(!wire.contains(&engine.encode(s.draft.cdk.expose())));
        assert!(!wire.contains(&engine.encode(s.draft.gate_material.release_key.expose())));
        assert!(!wire.contains(
            &engine.encode(s.draft.gate_material.relay_share.as_ref().unwrap().expose())
        ));
    }

    #[test]
    fn the_seal_is_stable() {
        let s = scene();
        assert_eq!(s.draft.capsule.seal(), s.draft.capsule.seal());
    }

    #[test]
    fn substituting_a_recipient_key_changes_the_seal() {
        let s = scene();
        let original = s.draft.capsule.seal();

        let mut tampered = s.draft.capsule.clone();
        tampered.recipients[0].public_key = RecipientIdentity::generate().public();
        assert_ne!(
            tampered.seal(),
            original,
            "a swapped recipient key must change the seal a person can see"
        );
        assert_ne!(tampered.seal().short(), original.short());
    }

    #[test]
    fn rotating_the_gate_changes_the_seal() {
        let mut s = scene();
        let original = s.draft.capsule.seal();
        s.draft.capsule.rotate_gate(&s.draft.cdk, policy()).unwrap();
        assert_ne!(s.draft.capsule.seal(), original);
    }

    #[test]
    fn the_seal_ignores_recipient_order() {
        let owner = VaultIdentity::derive(&Key32::random());
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();

        let one = Capsule::create(
            &owner,
            vec![
                simple_recipient(0, a.public()),
                simple_recipient(1, b.public()),
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();

        let mut two = one.capsule.clone();
        two.recipients.reverse();
        assert_eq!(two.seal(), one.capsule.seal());
    }

    #[test]
    fn different_capsules_have_different_seals() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            assert!(seen.insert(scene().draft.capsule.seal()));
        }
    }

    #[test]
    fn rotating_a_recipient_key_preserves_access_for_the_new_key() {
        let mut s = scene();
        let release_key = s.draft.gate_material.release_key.duplicate();
        let new_alex = RecipientIdentity::generate();

        s.draft
            .capsule
            .rotate_recipient_key(&s.draft.cdk, &release_key, 0, new_alex.public(), T0)
            .unwrap();

        assert_eq!(
            s.draft
                .capsule
                .open_as_recipient(&new_alex, 0, &release_key)
                .unwrap(),
            s.draft.cdk
        );

        assert!(s
            .draft
            .capsule
            .open_as_recipient(&s.alex, 0, &release_key)
            .is_err());

        assert!(s.draft.capsule.recipients[0].key_verified_at.is_none());
        assert_eq!(s.draft.capsule.recipients[0].key_rotated_at, Some(T0));
        s.draft.capsule.validate().unwrap();
    }

    #[test]
    fn rotation_leaves_the_payload_untouched() {
        let mut s = scene();
        s.draft.capsule.attach_payload(PayloadRef {
            prefix: StreamPrefix::random(),
            plaintext_len: 40_000_000_000,
            ciphertext_len: 40_000_610_352,
            blob_id: [9u8; 32],
        });
        let before = s.draft.capsule.payload.clone();

        s.draft.capsule.rotate_gate(&s.draft.cdk, policy()).unwrap();
        s.draft
            .capsule
            .rotate_recipient_key(
                &s.draft.cdk,
                &s.draft.gate_material.release_key,
                0,
                RecipientIdentity::generate().public(),
                T0,
            )
            .unwrap();

        assert_eq!(
            s.draft.capsule.payload, before,
            "a 40 GB payload must not be rewritten"
        );
    }

    #[test]
    fn rotating_the_gate_invalidates_the_old_shares() {
        let mut s = scene();
        let old_relay = s
            .draft
            .gate_material
            .relay_share
            .as_ref()
            .unwrap()
            .duplicate();
        let old_shares = std::mem::take(&mut s.draft.gate_material.trustee_shares);

        let new_material = s.draft.capsule.rotate_gate(&s.draft.cdk, policy()).unwrap();

        assert!(
            release::assemble(&s.draft.capsule.gate, Some(&old_relay), &old_shares[..3]).is_err(),
            "shares from the old gate must not open the rotated capsule"
        );

        let fresh = release::assemble(
            &s.draft.capsule.gate,
            new_material.relay_share.as_ref(),
            &new_material.trustee_shares[..3],
        )
        .unwrap();
        assert_eq!(
            s.draft
                .capsule
                .open_as_recipient(&s.alex, 0, &fresh)
                .unwrap(),
            s.draft.cdk
        );
    }

    #[test]
    fn revoking_a_recipient_removes_their_slot() {
        let owner = VaultIdentity::derive(&Key32::random());
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();
        let mut draft = Capsule::create(
            &owner,
            vec![
                simple_recipient(0, a.public()),
                simple_recipient(1, b.public()),
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();

        draft.capsule.revoke_recipient(1).unwrap();
        assert_eq!(draft.capsule.recipients.len(), 1);
        assert!(draft
            .capsule
            .open_as_recipient(&b, 1, &draft.gate_material.release_key)
            .is_err());
        draft.capsule.validate().unwrap();
    }

    #[test]
    fn the_last_recipient_cannot_be_revoked() {
        let s = scene();
        let mut capsule = s.draft.capsule.clone();
        assert!(
            capsule.revoke_recipient(0).is_err(),
            "a capsule with no recipients would release to nobody"
        );
    }

    #[test]
    fn a_capsule_falls_through_to_the_next_tier() {
        let owner = VaultIdentity::derive(&Key32::random());
        let alex = RecipientIdentity::generate();
        let sam = RecipientIdentity::generate();

        let draft = Capsule::create(
            &owner,
            vec![
                RecipientSlot {
                    id: 0,
                    public_key: alex.public(),
                    tier: 0,
                    claim_window: 60 * crate::clock::SECONDS_PER_DAY,
                    key_verified_at: None,
                    key_rotated_at: None,
                },
                RecipientSlot {
                    id: 1,
                    public_key: sam.public(),
                    tier: 1,
                    claim_window: 0,
                    key_verified_at: None,
                    key_rotated_at: None,
                },
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();
        let c = &draft.capsule;

        assert_eq!(c.eligible_recipients(T0, T0, &[]), vec![0]);
        assert_eq!(c.eligible_recipients(T0, T0.plus_days(59), &[]), vec![0]);

        assert_eq!(c.eligible_recipients(T0, T0.plus_days(60), &[]), vec![0, 1]);
    }

    #[test]
    fn claiming_stops_the_fallthrough() {
        let owner = VaultIdentity::derive(&Key32::random());
        let alex = RecipientIdentity::generate();
        let sam = RecipientIdentity::generate();

        let draft = Capsule::create(
            &owner,
            vec![
                RecipientSlot {
                    id: 0,
                    public_key: alex.public(),
                    tier: 0,
                    claim_window: 60 * crate::clock::SECONDS_PER_DAY,
                    key_verified_at: None,
                    key_rotated_at: None,
                },
                RecipientSlot {
                    id: 1,
                    public_key: sam.public(),
                    tier: 1,
                    claim_window: 0,
                    key_verified_at: None,
                    key_rotated_at: None,
                },
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();

        let far_future = T0.plus_days(9999);
        assert_eq!(
            draft.capsule.eligible_recipients(T0, far_future, &[0]),
            vec![0]
        );
    }

    #[test]
    fn multiple_recipients_in_one_tier_are_all_eligible() {
        let owner = VaultIdentity::derive(&Key32::random());
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();
        let draft = Capsule::create(
            &owner,
            vec![
                simple_recipient(0, a.public()),
                simple_recipient(1, b.public()),
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();
        assert_eq!(draft.capsule.eligible_recipients(T0, T0, &[]), vec![0, 1]);
    }

    #[test]
    fn a_recipient_passphrase_fallback_round_trips() {
        let s = scene();
        let argon = kdf::Argon2Params::MINIMUM;
        let phrase = SecretBytes::from_slice(b"the name of our first dog");

        let (sealed, salt) =
            wrap_for_recipient_passphrase(&s.draft.cdk, &phrase, &s.draft.capsule.id, argon)
                .unwrap();

        assert_eq!(
            unwrap_with_recipient_passphrase(&sealed, &phrase, &salt, &s.draft.capsule.id, argon)
                .unwrap(),
            s.draft.cdk
        );

        let wrong = SecretBytes::from_slice(b"not the dog");
        assert!(unwrap_with_recipient_passphrase(
            &sealed,
            &wrong,
            &salt,
            &s.draft.capsule.id,
            argon
        )
        .is_err());
        assert!(unwrap_with_recipient_passphrase(
            &sealed,
            &phrase,
            &salt,
            &CapsuleId::random(),
            argon
        )
        .is_err());
    }

    #[test]
    fn rejects_duplicate_recipient_ids() {
        let owner = VaultIdentity::derive(&Key32::random());
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();
        assert!(Capsule::create(
            &owner,
            vec![
                simple_recipient(0, a.public()),
                simple_recipient(0, b.public())
            ],
            policy(),
            &manifest(),
            T0
        )
        .is_err());
    }

    #[test]
    fn rejects_a_capsule_with_no_recipients() {
        let owner = VaultIdentity::derive(&Key32::random());
        assert!(Capsule::create(&owner, vec![], policy(), &manifest(), T0).is_err());
    }

    #[test]
    fn validation_catches_a_recipient_without_a_key_slot() {
        let mut s = scene();
        s.draft.capsule.key_slots.clear();
        assert!(
            s.draft.capsule.validate().is_err(),
            "a recipient with no wrapped key would silently receive nothing"
        );
    }

    #[test]
    fn validation_catches_an_orphan_key_slot() {
        let mut s = scene();
        s.draft.capsule.key_slots.push(GatedKeySlot {
            recipient_id: 99,
            gated: s.draft.capsule.key_slots[0].gated.clone(),
        });
        assert!(s.draft.capsule.validate().is_err());
    }

    #[test]
    fn validation_catches_bad_magic_and_future_versions() {
        let s = scene();
        s.draft.capsule.validate().unwrap();

        let mut c = s.draft.capsule.clone();
        c.magic = *b"NOTACAPS";
        assert!(c.validate().is_err());

        let mut c = s.draft.capsule.clone();
        c.version = crate::FORMAT_VERSION + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn manifest_cannot_be_moved_between_capsules() {
        let a = scene();
        let mut b = scene();
        b.draft.capsule.manifest = a.draft.capsule.manifest.clone();

        assert!(b.draft.capsule.read_manifest(&a.draft.cdk).is_err());
    }

    #[test]
    fn a_key_slot_cannot_be_moved_between_recipients() {
        let owner = VaultIdentity::derive(&Key32::random());
        let a = RecipientIdentity::generate();
        let b = RecipientIdentity::generate();
        let mut draft = Capsule::create(
            &owner,
            vec![
                simple_recipient(0, a.public()),
                simple_recipient(1, b.public()),
            ],
            policy(),
            &manifest(),
            T0,
        )
        .unwrap();

        let slot_zero = draft.capsule.key_slots[0].gated.clone();
        draft.capsule.key_slots[1].gated = slot_zero;

        assert!(
            draft
                .capsule
                .open_as_recipient(&b, 1, &draft.gate_material.release_key)
                .is_err(),
            "the recipient slot id is bound into the AAD"
        );
    }

    #[test]
    fn manifest_can_be_rewritten_without_rewrapping_keys() {
        let mut s = scene();
        let slots_before = s.draft.capsule.key_slots.clone();

        let mut m = s.draft.capsule.read_manifest(&s.draft.cdk).unwrap();
        m.note = Some("Actually, read the deed first.".to_string());
        s.draft.capsule.write_manifest(&s.draft.cdk, &m).unwrap();

        assert_eq!(s.draft.capsule.key_slots, slots_before);
        assert_eq!(
            s.draft
                .capsule
                .read_manifest(&s.draft.cdk)
                .unwrap()
                .note
                .unwrap(),
            "Actually, read the deed first."
        );
    }

    #[test]
    fn capsule_survives_json() {
        let s = scene();
        let json = serde_json::to_string(&s.draft.capsule).unwrap();
        let back: Capsule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s.draft.capsule);
        back.validate().unwrap();
        assert_eq!(back.open_as_owner(&s.owner).unwrap(), s.draft.cdk);
    }

    #[test]
    fn payload_key_is_distinct_from_manifest_key() {
        let cdk = Key32::random();
        assert_ne!(Capsule::payload_key(&cdk), Capsule::manifest_key(&cdk));
    }
}
