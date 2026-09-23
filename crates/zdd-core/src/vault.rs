use zeroize::Zeroize;

use crate::aead::{self, Sealed};
use crate::codec;
use crate::error::{Error, Result};
use crate::identity::VaultPublicIdentity;
use crate::kdf::{self, label, Argon2Params, SALT_LEN};
use crate::secret::{Key32, SecretBytes};

pub const SLOT_COUNT: usize = 8;

const SLOT_PLAINTEXT_LEN: usize = 1 + 32;

const SLOT_SEALED_LEN: usize = Sealed::OVERHEAD + SLOT_PLAINTEXT_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotRole {
    Primary = 1,

    Duress = 2,

    RecoverySheet = 3,

    SocialRecovery = 4,

    HardwareKey = 5,
}

impl SlotRole {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => SlotRole::Primary,
            2 => SlotRole::Duress,
            3 => SlotRole::RecoverySheet,
            4 => SlotRole::SocialRecovery,
            5 => SlotRole::HardwareKey,
            _ => return None,
        })
    }

    fn kdf_label(&self) -> &'static [u8] {
        match self {
            SlotRole::Primary | SlotRole::Duress => label::UNLOCK_PASSPHRASE,
            SlotRole::RecoverySheet => label::UNLOCK_RECOVERY,
            SlotRole::SocialRecovery => label::UNLOCK_SOCIAL,
            SlotRole::HardwareKey => label::UNLOCK_HARDWARE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Passphrase,

    RecoverySheet,

    SocialRecovery,

    HardwareKey,
}

impl CredentialKind {
    fn candidate_roles(&self) -> &'static [SlotRole] {
        match self {
            CredentialKind::Passphrase => &[SlotRole::Primary, SlotRole::Duress],
            CredentialKind::RecoverySheet => &[SlotRole::RecoverySheet],
            CredentialKind::SocialRecovery => &[SlotRole::SocialRecovery],
            CredentialKind::HardwareKey => &[SlotRole::HardwareKey],
        }
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrapSlot {
    #[serde(with = "crate::codec::base64_array")]
    salt: [u8; SALT_LEN],
    #[serde(with = "crate::codec::base64_bytes")]
    blob: Vec<u8>,
}

impl core::fmt::Debug for WrapSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "WrapSlot(opaque, {} bytes)", self.blob.len())
    }
}

impl WrapSlot {
    fn chaff() -> Self {
        use rand::RngCore;
        let mut salt = [0u8; SALT_LEN];
        let mut blob = vec![0u8; SLOT_SEALED_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut blob);
        Self { salt, blob }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HardwareEnrollment {
    #[serde(with = "crate::codec::base64_bytes")]
    pub credential_id: Vec<u8>,

    pub slot: u8,

    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicy {
    Standard,

    Unrecoverable,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultHeader {
    #[serde(with = "crate::codec::base64_array")]
    pub magic: [u8; 8],
    pub version: u16,

    #[serde(with = "crate::codec::base64_array")]
    pub vault_id: [u8; 16],

    pub argon: Argon2Params,

    pub slots: Vec<WrapSlot>,

    pub hardware: Vec<HardwareEnrollment>,
    pub recovery_policy: RecoveryPolicy,

    pub public_identity: VaultPublicIdentity,
}

pub struct UnlockedVault {
    pub root: Key32,

    pub role: SlotRole,

    pub slot: u8,
}

impl core::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("role", &self.role)
            .field("slot", &self.slot)
            .field("root", &"redacted")
            .finish()
    }
}

fn slot_aad(vault_id: &[u8; 16], slot_index: u8, role: SlotRole) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/wrap-slot", vault_id, &[slot_index], &[role as u8]])
}

fn encode_slot_plaintext(role: SlotRole, root: &Key32) -> [u8; SLOT_PLAINTEXT_LEN] {
    let mut out = [0u8; SLOT_PLAINTEXT_LEN];
    out[0] = role as u8;
    out[1..].copy_from_slice(root.expose());
    out
}

impl VaultHeader {
    pub fn create(
        passphrase: &SecretBytes,
        argon: Argon2Params,
        recovery_policy: RecoveryPolicy,
    ) -> Result<(Self, Key32, u8)> {
        use rand::{Rng, RngCore};
        argon.validate()?;

        let mut vault_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut vault_id);

        let root = Key32::random();
        let public_identity = crate::identity::VaultIdentity::derive(&root).public();

        let mut header = Self {
            magic: *crate::VAULT_MAGIC,
            version: crate::FORMAT_VERSION,
            vault_id,
            argon,
            slots: (0..SLOT_COUNT).map(|_| WrapSlot::chaff()).collect(),
            hardware: Vec::new(),
            recovery_policy,
            public_identity,
        };

        let slot: u8 = rand::rngs::OsRng.gen_range(0..SLOT_COUNT as u8);
        header.write_slot(slot, SlotRole::Primary, &root, passphrase)?;

        Ok((header, root, slot))
    }

    fn write_slot(
        &mut self,
        slot: u8,
        role: SlotRole,
        root: &Key32,
        credential: &SecretBytes,
    ) -> Result<()> {
        let index = slot as usize;
        if index >= SLOT_COUNT {
            return Err(Error::format(
                "wrap slot",
                format!("slot {slot} is out of range"),
            ));
        }

        let mut salt = [0u8; SALT_LEN];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let kek = kdf::derive_from_passphrase(credential, &salt, self.argon, role.kdf_label())?;
        let mut plaintext = encode_slot_plaintext(role, root);
        let sealed = aead::seal(&kek, &plaintext, &slot_aad(&self.vault_id, slot, role))?;
        plaintext.zeroize();

        debug_assert_eq!(
            sealed.as_bytes().len(),
            SLOT_SEALED_LEN,
            "a real slot must be exactly the size of chaff, or chaff is pointless"
        );

        self.slots[index] = WrapSlot {
            salt,
            blob: sealed.into_bytes(),
        };
        Ok(())
    }

    pub fn add_slot(
        &mut self,
        role: SlotRole,
        root: &Key32,
        credential: &SecretBytes,
        occupied: &[u8],
    ) -> Result<u8> {
        if self.recovery_policy == RecoveryPolicy::Unrecoverable && role != SlotRole::Primary {
            return Err(Error::format(
                "recovery policy",
                "this vault was created as unrecoverable; adding another unlock path \
                 requires re-keying it from scratch",
            ));
        }
        let slot = self.pick_free_slot(occupied)?;
        self.write_slot(slot, role, root, credential)?;
        Ok(slot)
    }

    pub fn add_duress_slot(
        &mut self,
        decoy_root: &Key32,
        duress_passphrase: &SecretBytes,
        occupied: &[u8],
    ) -> Result<u8> {
        let slot = self.pick_free_slot(occupied)?;
        self.write_slot(slot, SlotRole::Duress, decoy_root, duress_passphrase)?;
        Ok(slot)
    }

    fn pick_free_slot(&self, occupied: &[u8]) -> Result<u8> {
        use rand::seq::SliceRandom;
        let free: Vec<u8> = (0..SLOT_COUNT as u8)
            .filter(|s| !occupied.contains(s))
            .collect();
        free.choose(&mut rand::rngs::OsRng)
            .copied()
            .ok_or_else(|| Error::format("wrap slot", format!("all {SLOT_COUNT} slots are in use")))
    }

    pub fn erase_slot(&mut self, slot: u8) -> Result<()> {
        let index = slot as usize;
        if index >= SLOT_COUNT {
            return Err(Error::format(
                "wrap slot",
                format!("slot {slot} is out of range"),
            ));
        }
        self.slots[index].salt.zeroize();
        self.slots[index].blob.zeroize();
        self.slots[index] = WrapSlot::chaff();
        self.hardware.retain(|h| h.slot != slot);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if &self.magic != crate::VAULT_MAGIC {
            return Err(Error::format("vault header", "wrong magic bytes"));
        }
        if self.version > crate::FORMAT_VERSION {
            return Err(Error::format(
                "vault header",
                format!(
                    "written by a newer version ({} > {})",
                    self.version,
                    crate::FORMAT_VERSION
                ),
            ));
        }

        if self.slots.len() != SLOT_COUNT {
            return Err(Error::format(
                "vault header",
                format!("expected {} slots, found {}", SLOT_COUNT, self.slots.len()),
            ));
        }
        for (i, slot) in self.slots.iter().enumerate() {
            if slot.blob.len() != SLOT_SEALED_LEN {
                return Err(Error::format(
                    "vault header",
                    format!(
                        "slot {i} is {} bytes, expected {SLOT_SEALED_LEN}",
                        slot.blob.len()
                    ),
                ));
            }
        }

        self.argon.validate()?;
        Ok(())
    }

    pub fn short_id(&self) -> String {
        codec::fingerprint_string(&self.vault_id, 3)
    }
}

pub fn unlock(
    header: &VaultHeader,
    kind: CredentialKind,
    credential: &SecretBytes,
) -> Result<UnlockedVault> {
    header.validate()?;

    let roles = kind.candidate_roles();

    let mut labels: Vec<&'static [u8]> = Vec::new();
    for role in roles {
        if !labels.contains(&role.kdf_label()) {
            labels.push(role.kdf_label());
        }
    }

    let per_derivation = (header.argon.m_cost as u64).saturating_mul(1024).max(1);
    let by_memory = (UNLOCK_MEMORY_BUDGET / per_derivation).max(1) as usize;
    let by_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let workers = by_memory.min(by_cores).clamp(1, SLOT_COUNT);

    let next = std::sync::atomic::AtomicUsize::new(0);
    let results: std::sync::Mutex<Vec<(usize, UnlockedVault)>> = std::sync::Mutex::new(Vec::new());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(slot) = header.slots.get(index) else {
                    break;
                };
                for label in &labels {
                    let Ok(kek) =
                        kdf::derive_from_passphrase(credential, &slot.salt, header.argon, label)
                    else {
                        continue;
                    };
                    for role in roles.iter().filter(|r| r.kdf_label() == *label) {
                        if let Some(opened) = try_slot(header, index, slot, &kek, *role) {
                            results
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push((roles.iter().position(|r| r == role).unwrap_or(0), opened));
                        }
                    }
                }
            });
        }
    });

    let mut found = results.into_inner().unwrap_or_else(|e| e.into_inner());
    found.sort_by_key(|(rank, v)| (*rank, v.slot));
    found
        .into_iter()
        .next()
        .map(|(_, v)| v)
        .ok_or(Error::UnlockRejected)
}

const UNLOCK_MEMORY_BUDGET: u64 = 2 * 1024 * 1024 * 1024;

fn try_slot(
    header: &VaultHeader,
    index: usize,
    slot: &WrapSlot,
    kek: &Key32,
    role: SlotRole,
) -> Option<UnlockedVault> {
    let sealed = Sealed::from_bytes(slot.blob.clone()).ok()?;
    let aad = slot_aad(&header.vault_id, index as u8, role);
    let plaintext = aead::unseal(kek, &sealed, &aad).ok()?;
    if plaintext.len() != SLOT_PLAINTEXT_LEN {
        return None;
    }

    if SlotRole::from_byte(plaintext.expose()[0])? != role {
        return None;
    }
    let root = Key32::from_slice(&plaintext.expose()[1..]).ok()?;
    Some(UnlockedVault {
        root,
        role,
        slot: index as u8,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::VaultIdentity;

    fn pw(s: &str) -> SecretBytes {
        SecretBytes::from_slice(s.as_bytes())
    }

    fn fast() -> Argon2Params {
        Argon2Params::MINIMUM
    }

    const PASS: &str = "correct horse battery staple";

    fn make() -> (VaultHeader, Key32, Vec<u8>) {
        let (header, root, primary) =
            VaultHeader::create(&pw(PASS), fast(), RecoveryPolicy::Standard).unwrap();
        (header, root, vec![primary])
    }

    #[test]
    fn a_new_vault_unlocks_with_its_passphrase() {
        let (header, root, _occ) = make();
        let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
        assert_eq!(opened.root, root);
        assert_eq!(opened.role, SlotRole::Primary);
    }

    #[test]
    fn the_wrong_passphrase_is_rejected() {
        let (header, _root, _occ) = make();
        let err = unlock(&header, CredentialKind::Passphrase, &pw("wrong")).unwrap_err();
        assert!(matches!(err, Error::UnlockRejected));
    }

    #[test]
    fn the_root_key_is_not_in_the_header() {
        let (header, root, _occ) = make();
        let json = serde_json::to_string(&header).unwrap();
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(root.expose());
        assert!(
            !json.contains(&encoded),
            "the root key leaked into the header"
        );
        assert!(!json.contains(&codec::to_hex(root.expose())));
    }

    #[test]
    fn every_header_has_exactly_the_same_slot_count() {
        let (plain, _proot, _pocc) = make();
        assert_eq!(plain.slots.len(), SLOT_COUNT);

        let (mut loaded, root, mut occ) = make();
        loaded
            .add_slot(SlotRole::RecoverySheet, &root, &pw("sheet words"), &occ)
            .unwrap();
        occ.push(
            loaded
                .add_slot(SlotRole::SocialRecovery, &root, &pw("social"), &occ)
                .unwrap(),
        );
        loaded
            .add_duress_slot(&Key32::random(), &pw("decoy pass"), &occ)
            .unwrap();

        assert_eq!(
            loaded.slots.len(),
            SLOT_COUNT,
            "slot count must not vary with enrolment"
        );
    }

    #[test]
    fn a_duress_vault_is_indistinguishable_from_a_plain_one() {
        let (plain, _proot, _pocc) = make();
        let (mut with_duress, _wroot, wocc) = make();
        let duress_slot = with_duress
            .add_duress_slot(&Key32::random(), &pw("decoy pass"), &wocc)
            .unwrap();

        assert_eq!(plain.slots.len(), with_duress.slots.len());

        let sizes_plain: Vec<usize> = plain.slots.iter().map(|s| s.blob.len()).collect();
        let sizes_duress: Vec<usize> = with_duress.slots.iter().map(|s| s.blob.len()).collect();
        assert_eq!(sizes_plain, sizes_duress);
        assert!(sizes_plain.iter().all(|&n| n == SLOT_SEALED_LEN));

        let a = serde_json::to_string(&plain).unwrap();
        let b = serde_json::to_string(&with_duress).unwrap();
        assert_eq!(
            a.len(),
            b.len(),
            "header size must not reveal a duress path"
        );

        let rendered = format!("{:?}", with_duress.slots[duress_slot as usize]);
        assert!(rendered.contains("opaque"));
        assert!(!rendered.to_lowercase().contains("duress"));
    }

    #[test]
    fn a_duress_passphrase_opens_a_different_vault() {
        let (mut header, real_root, occ) = make();
        let decoy_root = Key32::random();
        header
            .add_duress_slot(&decoy_root, &pw("decoy pass"), &occ)
            .unwrap();

        let real = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
        assert_eq!(real.root, real_root);
        assert_eq!(real.role, SlotRole::Primary);

        let decoy = unlock(&header, CredentialKind::Passphrase, &pw("decoy pass")).unwrap();
        assert_eq!(decoy.root, decoy_root);
        assert_eq!(decoy.role, SlotRole::Duress);

        assert_ne!(
            real.root, decoy.root,
            "the decoy must not open the real vault"
        );
    }

    #[test]
    fn erasing_a_slot_leaves_only_chaff() {
        let (mut header, _root, occ) = make();
        let slot = header
            .add_duress_slot(&Key32::random(), &pw("decoy"), &occ)
            .unwrap();
        assert!(unlock(&header, CredentialKind::Passphrase, &pw("decoy")).is_ok());

        header.erase_slot(slot).unwrap();
        assert!(unlock(&header, CredentialKind::Passphrase, &pw("decoy")).is_err());
        assert_eq!(header.slots.len(), SLOT_COUNT);
        assert_eq!(header.slots[slot as usize].blob.len(), SLOT_SEALED_LEN);
    }

    #[test]
    fn the_primary_slot_position_varies() {
        let mut positions = std::collections::HashSet::new();
        for _ in 0..30 {
            let (header, _root, _occ) = make();
            let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
            positions.insert(opened.slot);
        }
        assert!(
            positions.len() > 1,
            "the primary slot is always in the same place, so an attacker knows where to look"
        );
    }

    #[test]
    fn a_recovery_sheet_opens_the_same_root() {
        let (mut header, root, occ) = make();
        header
            .add_slot(
                SlotRole::RecoverySheet,
                &root,
                &pw("abandon abandon ability"),
                &occ,
            )
            .unwrap();

        let opened = unlock(
            &header,
            CredentialKind::RecoverySheet,
            &pw("abandon abandon ability"),
        )
        .unwrap();
        assert_eq!(opened.root, root, "recovery must yield the real root key");
        assert_eq!(opened.role, SlotRole::RecoverySheet);
    }

    #[test]
    fn social_recovery_opens_the_same_root() {
        let (mut header, root, occ) = make();
        let reconstructed = SecretBytes::from_slice(Key32::random().expose());
        header
            .add_slot(SlotRole::SocialRecovery, &root, &reconstructed, &occ)
            .unwrap();
        let opened = unlock(&header, CredentialKind::SocialRecovery, &reconstructed).unwrap();
        assert_eq!(opened.root, root);
    }

    #[test]
    fn credentials_do_not_cross_roles() {
        let (mut header, root, occ) = make();
        let shared = pw("the very same bytes");
        header
            .add_slot(SlotRole::RecoverySheet, &root, &shared, &occ)
            .unwrap();

        assert!(unlock(&header, CredentialKind::RecoverySheet, &shared).is_ok());

        assert!(unlock(&header, CredentialKind::Passphrase, &shared).is_err());
    }

    #[test]
    fn the_published_identity_belongs_to_the_wrapped_root() {
        let (header, root, _) = make();
        assert_eq!(
            header.public_identity,
            VaultIdentity::derive(&root).public()
        );
        let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
        let signer = VaultIdentity::derive(&opened.root);
        let sig = signer.sign(b"still here");
        assert!(header.public_identity.verify(b"still here", &sig).is_ok());
    }

    #[test]
    fn an_unrecoverable_vault_refuses_extra_paths() {
        let (mut header, root, primary) =
            VaultHeader::create(&pw("only way in"), fast(), RecoveryPolicy::Unrecoverable).unwrap();
        let occ = vec![primary];

        for role in [
            SlotRole::RecoverySheet,
            SlotRole::SocialRecovery,
            SlotRole::HardwareKey,
        ] {
            let err = header
                .add_slot(role, &root, &pw("backup"), &occ)
                .unwrap_err();
            assert!(
                matches!(err, Error::Format { .. }),
                "an unrecoverable vault must refuse {role:?}"
            );
        }

        assert!(unlock(&header, CredentialKind::Passphrase, &pw("only way in")).is_ok());
    }

    #[test]
    fn an_unrecoverable_vault_still_allows_duress() {
        let (mut header, _root, primary) =
            VaultHeader::create(&pw("only way in"), fast(), RecoveryPolicy::Unrecoverable).unwrap();
        let occ = vec![primary];
        let decoy = Key32::random();
        header.add_duress_slot(&decoy, &pw("decoy"), &occ).unwrap();
        assert_eq!(
            unlock(&header, CredentialKind::Passphrase, &pw("decoy"))
                .unwrap()
                .root,
            decoy
        );
    }

    #[test]
    fn slots_cannot_be_moved_between_vaults() {
        let (header_a, root_a, _aocc) = make();
        let (mut header_b, root_b, _bocc) = make();
        assert_ne!(root_a, root_b);

        let a_slot = unlock(&header_a, CredentialKind::Passphrase, &pw(PASS))
            .unwrap()
            .slot;
        header_b.slots[a_slot as usize] = header_a.slots[a_slot as usize].clone();

        match unlock(&header_b, CredentialKind::Passphrase, &pw(PASS)) {
            Ok(opened) => {
                assert_ne!(
                    opened.root, root_a,
                    "a grafted slot leaked the other vault's root key"
                );
                assert_eq!(opened.root, root_b, "unlock returned neither vault's root");
            }

            Err(Error::UnlockRejected) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn slots_cannot_be_moved_within_a_vault() {
        let (mut header, _root, _occ) = make();
        let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();

        let other = (opened.slot + 1) % SLOT_COUNT as u8;
        header.slots.swap(opened.slot as usize, other as usize);

        assert!(
            unlock(&header, CredentialKind::Passphrase, &pw(PASS)).is_err(),
            "the slot index is bound into the AAD, so moving a slot must break it"
        );
    }

    #[test]
    fn tampering_with_a_slot_is_caught() {
        let (mut header, _root, _occ) = make();
        let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
        header.slots[opened.slot as usize].blob[30] ^= 0x01;
        assert!(unlock(&header, CredentialKind::Passphrase, &pw(PASS)).is_err());
    }

    #[test]
    fn a_downgraded_argon_cost_is_refused() {
        let (mut header, _root, _occ) = make();
        header.argon = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(header.validate().is_err());
        assert!(unlock(&header, CredentialKind::Passphrase, &pw(PASS)).is_err());
    }

    #[test]
    fn a_short_slot_array_is_refused() {
        let (mut header, _root, _occ) = make();
        header.slots.truncate(SLOT_COUNT - 1);
        assert!(
            header.validate().is_err(),
            "stripping chaff would let an attacker count real slots by elimination"
        );
    }

    #[test]
    fn a_future_format_version_is_refused() {
        let (mut header, _root, _occ) = make();
        header.version = crate::FORMAT_VERSION + 1;
        assert!(header.validate().is_err());
    }

    #[test]
    fn wrong_magic_is_refused() {
        let (mut header, _root, _occ) = make();
        header.magic = *b"NOTAVALT";
        assert!(header.validate().is_err());
    }

    #[test]
    fn slots_run_out_rather_than_overwriting() {
        let (mut header, root, _occ) = make();
        let mut used = vec![
            unlock(&header, CredentialKind::Passphrase, &pw(PASS))
                .unwrap()
                .slot,
        ];

        for i in 0..(SLOT_COUNT - 1) {
            let slot = header
                .add_slot(
                    SlotRole::SocialRecovery,
                    &root,
                    &pw(&format!("cred{i}")),
                    &used,
                )
                .unwrap();
            used.push(slot);
        }
        assert_eq!(used.len(), SLOT_COUNT);

        let err = header
            .add_slot(SlotRole::SocialRecovery, &root, &pw("one too many"), &used)
            .unwrap_err();
        assert!(
            matches!(err, Error::Format { .. }),
            "overwriting an occupied slot could destroy the owner's only way in"
        );
    }

    #[test]
    fn header_survives_json() {
        let (header, root, _occ) = make();
        let json = serde_json::to_string(&header).unwrap();
        let back: VaultHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(back, header);
        back.validate().unwrap();
        assert_eq!(
            unlock(&back, CredentialKind::Passphrase, &pw(PASS))
                .unwrap()
                .root,
            root
        );
    }

    #[test]
    fn debug_never_reveals_the_root() {
        let (header, root, _occ) = make();
        let opened = unlock(&header, CredentialKind::Passphrase, &pw(PASS)).unwrap();
        let rendered = format!("{opened:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&codec::to_hex(root.expose())[..8]));
    }

    #[test]
    fn vault_ids_are_unique() {
        let (a, _aroot, _aocc) = make();
        let (b, _broot, _bocc) = make();
        assert_ne!(a.vault_id, b.vault_id);
        assert_ne!(a.short_id(), b.short_id());
    }
}
