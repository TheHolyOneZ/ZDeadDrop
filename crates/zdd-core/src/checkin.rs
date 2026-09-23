use ed25519_dalek::{Signer, SigningKey};

use crate::aead::{self, Sealed};
use crate::clock::Timestamp;
use crate::error::{Error, Result};
use crate::identity::{Fingerprint, VaultIdentity, VaultPublicIdentity, SIGNATURE_LEN};
use crate::kdf::{self, label};
use crate::merkle::{self, InclusionProof};
use crate::policy::LadderConfig;
use crate::secret::Key32;

const CHECKIN_DOMAIN: &[u8] = b"zdd/v1/checkin";

const STH_DOMAIN: &[u8] = b"zdd/v1/signed-tree-head";

pub const ENVELOPE_LEN: usize = Sealed::OVERHEAD + 1;

pub fn duress_channel_key(root: &Key32) -> Key32 {
    kdf::derive_subkey(root, label::DURESS_CHANNEL)
}

fn envelope_aad(vault: &Fingerprint, counter: u64) -> Vec<u8> {
    aead::aad(&[b"zdd/v1/duress-envelope", &vault.0, &counter.to_be_bytes()])
}

fn seal_envelope(
    key: &Key32,
    under_duress: bool,
    vault: &Fingerprint,
    counter: u64,
) -> Result<Sealed> {
    let flag = [u8::from(under_duress)];
    let sealed = aead::seal(key, &flag, &envelope_aad(vault, counter))?;
    debug_assert_eq!(sealed.as_bytes().len(), ENVELOPE_LEN);
    Ok(sealed)
}

pub fn read_envelope(
    key: &Key32,
    envelope: &Sealed,
    vault: &Fingerprint,
    counter: u64,
) -> Result<bool> {
    let plain = aead::unseal(key, envelope, &envelope_aad(vault, counter))?;
    match plain.expose() {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Error::Authentication),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckIn {
    pub vault: Fingerprint,

    pub counter: u64,

    pub asserted_at: Timestamp,

    #[serde(with = "crate::codec::base64_array")]
    pub nonce: [u8; 16],

    pub duress_envelope: Sealed,
}

impl CheckIn {
    pub fn signing_bytes(&self) -> Vec<u8> {
        aead::aad(&[
            CHECKIN_DOMAIN,
            &self.vault.0,
            &self.counter.to_be_bytes(),
            &self.asserted_at.0.to_be_bytes(),
            &self.nonce,
            self.duress_envelope.as_bytes(),
        ])
    }

    pub fn leaf(&self) -> [u8; 32] {
        merkle::leaf_hash(&self.signing_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedCheckIn {
    pub checkin: CheckIn,
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedCheckIn {
    pub fn verify(&self, owner: &VaultPublicIdentity) -> Result<()> {
        owner.verify(&self.checkin.signing_bytes(), &self.signature)
    }

    pub fn leaf(&self) -> [u8; 32] {
        self.checkin.leaf()
    }
}

pub fn issue(
    identity: &VaultIdentity,
    root: &Key32,
    counter: u64,
    asserted_at: Timestamp,
    under_duress: bool,
) -> Result<SignedCheckIn> {
    use rand::RngCore;

    let vault = identity.public().vigil_fingerprint();
    let mut nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let channel = duress_channel_key(root);
    let duress_envelope = seal_envelope(&channel, under_duress, &vault, counter)?;

    let checkin = CheckIn {
        vault,
        counter,
        asserted_at,
        nonce,
        duress_envelope,
    };
    let signature = identity.sign(&checkin.signing_bytes());

    Ok(SignedCheckIn { checkin, signature })
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Receipt {
    pub index: u64,
    pub inclusion: InclusionProof,
    pub sth: SignedTreeHead,
}

impl Receipt {
    pub fn verify(&self, record: &SignedCheckIn, relay_key: &[u8; 32]) -> bool {
        self.sth.verify(relay_key).is_ok()
            && merkle::verify_inclusion(
                &record.leaf(),
                &self.inclusion,
                &self.sth.root,
                self.sth.size,
            )
    }
}

pub const MAX_HOLD_SECS: u64 = 90 * crate::clock::SECONDS_PER_DAY;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedHold {
    pub vault: Fingerprint,
    pub until: Timestamp,
    pub issued_at: Timestamp,
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedHold {
    fn signing_bytes(vault: &Fingerprint, until: Timestamp, issued_at: Timestamp) -> Vec<u8> {
        aead::aad(&[
            b"zdd/v1/hold",
            &vault.0,
            &until.0.to_be_bytes(),
            &issued_at.0.to_be_bytes(),
        ])
    }

    pub fn issue(identity: &VaultIdentity, until: Timestamp, issued_at: Timestamp) -> Self {
        let vault = identity.public().vigil_fingerprint();
        let signature = identity.sign(&Self::signing_bytes(&vault, until, issued_at));
        Self {
            vault,
            until,
            issued_at,
            signature,
        }
    }

    pub fn verify(&self, owner: &VaultPublicIdentity) -> Result<()> {
        if self.vault != owner.vigil_fingerprint() {
            return Err(Error::Signature);
        }
        owner.verify(
            &Self::signing_bytes(&self.vault, self.until, self.issued_at),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrusteeEntry {
    pub index: u8,
    pub token: String,
    pub contact: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedTrustees {
    pub vault: Fingerprint,
    pub issued_at: Timestamp,
    pub trustees: Vec<TrusteeEntry>,
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedTrustees {
    fn signing_bytes(vault: &Fingerprint, issued_at: Timestamp, list: &[TrusteeEntry]) -> Vec<u8> {
        let mut parts: Vec<Vec<u8>> = vec![
            b"zdd/v1/trustees".to_vec(),
            vault.0.to_vec(),
            issued_at.0.to_be_bytes().to_vec(),
            (list.len() as u64).to_be_bytes().to_vec(),
        ];
        for t in list {
            parts.push(vec![t.index]);
            parts.push(t.token.as_bytes().to_vec());
            parts.push(t.contact.as_deref().unwrap_or("").as_bytes().to_vec());
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        aead::aad(&refs)
    }

    pub fn issue(
        identity: &VaultIdentity,
        issued_at: Timestamp,
        trustees: Vec<TrusteeEntry>,
    ) -> Self {
        let vault = identity.public().vigil_fingerprint();
        let signature = identity.sign(&Self::signing_bytes(&vault, issued_at, &trustees));
        Self {
            vault,
            issued_at,
            trustees,
            signature,
        }
    }

    pub fn verify(&self, owner: &VaultPublicIdentity) -> Result<()> {
        if self.vault != owner.vigil_fingerprint() {
            return Err(Error::Signature);
        }
        owner.verify(
            &Self::signing_bytes(&self.vault, self.issued_at, &self.trustees),
            &self.signature,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedSettings {
    pub vault: Fingerprint,
    pub silence_threshold: u64,
    pub release_delay: u64,
    pub owner_contact: Option<String>,
    pub issued_at: Timestamp,
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedSettings {
    fn signing_bytes(
        vault: &Fingerprint,
        threshold: u64,
        delay: u64,
        contact: Option<&str>,
        issued_at: Timestamp,
    ) -> Vec<u8> {
        aead::aad(&[
            b"zdd/v1/relay-settings",
            &vault.0,
            &threshold.to_be_bytes(),
            &delay.to_be_bytes(),
            contact.unwrap_or("").as_bytes(),
            &issued_at.0.to_be_bytes(),
        ])
    }

    pub fn issue(
        identity: &VaultIdentity,
        silence_threshold: u64,
        release_delay: u64,
        owner_contact: Option<String>,
        issued_at: Timestamp,
    ) -> Self {
        let vault = identity.public().vigil_fingerprint();
        let signature = identity.sign(&Self::signing_bytes(
            &vault,
            silence_threshold,
            release_delay,
            owner_contact.as_deref(),
            issued_at,
        ));
        Self {
            vault,
            silence_threshold,
            release_delay,
            owner_contact,
            issued_at,
            signature,
        }
    }

    pub fn verify(&self, owner: &VaultPublicIdentity) -> Result<()> {
        if self.vault != owner.vigil_fingerprint() {
            return Err(Error::Signature);
        }
        owner.verify(
            &Self::signing_bytes(
                &self.vault,
                self.silence_threshold,
                self.release_delay,
                self.owner_contact.as_deref(),
                self.issued_at,
            ),
            &self.signature,
        )
    }
}

pub fn find_gaps(checkins: &[SignedCheckIn]) -> Vec<u64> {
    if checkins.is_empty() {
        return Vec::new();
    }
    let mut counters: Vec<u64> = checkins.iter().map(|c| c.checkin.counter).collect();
    counters.sort_unstable();
    counters.dedup();

    let mut gaps = Vec::new();
    for window in counters.windows(2) {
        for missing in (window[0] + 1)..window[1] {
            gaps.push(missing);
        }
    }
    gaps
}

pub struct RelayKeypair {
    signing: SigningKey,
}

impl core::fmt::Debug for RelayKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RelayKeypair")
            .field("verifying", &crate::codec::to_hex(&self.verifying()))
            .field("signing", &"redacted")
            .finish()
    }
}

impl RelayKeypair {
    pub fn generate() -> Self {
        let seed = Key32::random();
        Self {
            signing: SigningKey::from_bytes(seed.expose()),
        }
    }

    pub fn from_seed(seed: &Key32) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed.expose()),
        }
    }

    pub fn verifying(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn sign_tree_head(
        &self,
        log_id: [u8; 16],
        size: u64,
        root: [u8; 32],
        asserted_at: Timestamp,
    ) -> SignedTreeHead {
        let mut head = SignedTreeHead {
            log_id,
            size,
            root,
            asserted_at,
            signature: [0u8; SIGNATURE_LEN],
        };
        head.signature = self.signing.sign(&head.signing_bytes()).to_bytes();
        head
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SignedTreeHead {
    #[serde(with = "crate::codec::base64_array")]
    pub log_id: [u8; 16],
    pub size: u64,
    #[serde(with = "crate::codec::base64_array")]
    pub root: [u8; 32],
    pub asserted_at: Timestamp,
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; SIGNATURE_LEN],
}

impl SignedTreeHead {
    fn signing_bytes(&self) -> Vec<u8> {
        aead::aad(&[
            STH_DOMAIN,
            &self.log_id,
            &self.size.to_be_bytes(),
            &self.root,
            &self.asserted_at.0.to_be_bytes(),
        ])
    }

    pub fn verify(&self, relay_verifying: &[u8; 32]) -> Result<()> {
        crate::identity::verify_with(relay_verifying, &self.signing_bytes(), &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SilenceProof {
    pub last_checkin: SignedCheckIn,

    pub inclusion: InclusionProof,

    pub sth: SignedTreeHead,
}

pub fn verify_silence_proof(
    proof: &SilenceProof,
    owner: &VaultPublicIdentity,
    relay_verifying: &[u8; 32],
    config: &LadderConfig,
    veto_count: u8,
    now: Timestamp,
) -> Result<()> {
    proof.sth.verify(relay_verifying)?;

    proof.last_checkin.verify(owner)?;

    if proof.last_checkin.checkin.vault != owner.vigil_fingerprint() {
        return Err(Error::format(
            "silence proof",
            "check-in belongs to a different vault",
        ));
    }

    if !merkle::verify_inclusion(
        &proof.last_checkin.leaf(),
        &proof.inclusion,
        &proof.sth.root,
        proof.sth.size,
    ) {
        return Err(Error::format(
            "silence proof",
            "inclusion proof does not verify",
        ));
    }

    if proof.inclusion.index.saturating_add(1) != proof.sth.size {
        return Err(Error::format(
            "silence proof",
            format!(
                "the proven check-in is leaf {} of {}, so the relay is holding {} later \
                 entries it has not disclosed",
                proof.inclusion.index,
                proof.sth.size,
                proof.sth.size.saturating_sub(proof.inclusion.index + 1)
            ),
        ));
    }

    let threshold = config.effective_silence_threshold(veto_count);
    let silence = now.since(proof.last_checkin.checkin.asserted_at);
    if silence < threshold {
        return Err(crate::ReleaseRefusal::OwnerStillPresent.into());
    }

    if proof.sth.asserted_at < proof.last_checkin.checkin.asserted_at {
        return Err(Error::format(
            "silence proof",
            "the tree head predates the check-in it claims to contain",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SECONDS_PER_DAY;
    use crate::merkle::MerkleLog;

    const T0: Timestamp = Timestamp(1_800_000_000);

    struct Fixture {
        root: Key32,
        identity: VaultIdentity,
        relay: RelayKeypair,
        log: MerkleLog,
        log_id: [u8; 16],
    }

    impl Fixture {
        fn new() -> Self {
            let root = Key32::random();
            Self {
                identity: VaultIdentity::derive(&root),
                root,
                relay: RelayKeypair::generate(),
                log: MerkleLog::new(),
                log_id: [7u8; 16],
            }
        }

        fn check_in(&mut self, counter: u64, at: Timestamp, duress: bool) -> SignedCheckIn {
            let signed = issue(&self.identity, &self.root, counter, at, duress).unwrap();
            self.log.append(&signed.checkin.signing_bytes());
            signed
        }

        fn prove(&self, signed: &SignedCheckIn, index: u64, at: Timestamp) -> SilenceProof {
            SilenceProof {
                last_checkin: signed.clone(),
                inclusion: self.log.prove(index).unwrap(),
                sth: self
                    .relay
                    .sign_tree_head(self.log_id, self.log.len(), self.log.root(), at),
            }
        }
    }

    fn cfg() -> LadderConfig {
        LadderConfig::default()
    }

    #[test]
    fn a_checkin_verifies() {
        let f = Fixture::new();
        let signed = issue(&f.identity, &f.root, 1, T0, false).unwrap();
        signed.verify(&f.identity.public()).unwrap();
    }

    #[test]
    fn the_relay_cannot_forge_a_checkin() {
        let f = Fixture::new();
        let impostor = Fixture::new();
        let forged = issue(&impostor.identity, &impostor.root, 1, T0, false).unwrap();
        assert!(
            forged.verify(&f.identity.public()).is_err(),
            "a check-in signed by anyone else must not verify"
        );
    }

    #[test]
    fn tampering_with_any_field_breaks_the_signature() {
        let f = Fixture::new();
        let signed = issue(&f.identity, &f.root, 5, T0, false).unwrap();
        let pubid = f.identity.public();

        let mut c = signed.clone();
        c.checkin.counter = 6;
        assert!(c.verify(&pubid).is_err());

        let mut c = signed.clone();
        c.checkin.asserted_at = T0.plus_days(30);
        assert!(
            c.verify(&pubid).is_err(),
            "backdating a check-in must break it"
        );

        let mut c = signed.clone();
        c.checkin.nonce[0] ^= 1;
        assert!(c.verify(&pubid).is_err());

        let mut c = signed.clone();
        c.signature[0] ^= 1;
        assert!(c.verify(&pubid).is_err());
    }

    #[test]
    fn a_duress_checkin_is_indistinguishable_to_the_relay() {
        let f = Fixture::new();
        let normal = issue(&f.identity, &f.root, 1, T0, false).unwrap();
        let duress = issue(&f.identity, &f.root, 1, T0, true).unwrap();

        assert_eq!(
            normal.checkin.duress_envelope.as_bytes().len(),
            duress.checkin.duress_envelope.as_bytes().len()
        );
        assert_eq!(
            normal.checkin.duress_envelope.as_bytes().len(),
            ENVELOPE_LEN
        );
        normal.verify(&f.identity.public()).unwrap();
        duress.verify(&f.identity.public()).unwrap();

        assert_eq!(
            serde_json::to_string(&normal).unwrap().len(),
            serde_json::to_string(&duress).unwrap().len()
        );
    }

    #[test]
    fn a_trustee_can_read_the_duress_flag() {
        let f = Fixture::new();
        let channel = duress_channel_key(&f.root);

        let normal = issue(&f.identity, &f.root, 1, T0, false).unwrap();
        let duress = issue(&f.identity, &f.root, 2, T0, true).unwrap();

        assert!(!read_envelope(
            &channel,
            &normal.checkin.duress_envelope,
            &normal.checkin.vault,
            1
        )
        .unwrap());
        assert!(read_envelope(
            &channel,
            &duress.checkin.duress_envelope,
            &duress.checkin.vault,
            2
        )
        .unwrap());
    }

    #[test]
    fn the_relay_cannot_read_the_duress_flag() {
        let f = Fixture::new();
        let duress = issue(&f.identity, &f.root, 1, T0, true).unwrap();
        let not_the_key = Key32::random();
        assert!(read_envelope(
            &not_the_key,
            &duress.checkin.duress_envelope,
            &duress.checkin.vault,
            1
        )
        .is_err());
    }

    #[test]
    fn an_envelope_cannot_be_replayed_onto_another_checkin() {
        let f = Fixture::new();
        let channel = duress_channel_key(&f.root);
        let first = issue(&f.identity, &f.root, 1, T0, false).unwrap();

        assert!(
            read_envelope(
                &channel,
                &first.checkin.duress_envelope,
                &first.checkin.vault,
                2
            )
            .is_err(),
            "an envelope is bound to its counter"
        );

        let other_vault = Fingerprint([9u8; 32]);
        assert!(read_envelope(&channel, &first.checkin.duress_envelope, &other_vault, 1).is_err());
    }

    #[test]
    fn contiguous_checkins_have_no_gaps() {
        let mut f = Fixture::new();
        let all: Vec<_> = (1..=10)
            .map(|i| f.check_in(i, T0.plus_days(i), false))
            .collect();
        assert!(find_gaps(&all).is_empty());
    }

    #[test]
    fn a_suppressed_checkin_leaves_a_gap() {
        let mut f = Fixture::new();
        let mut kept = Vec::new();
        for i in 1..=10u64 {
            let signed = f.check_in(i, T0.plus_days(i), false);
            if i != 7 {
                kept.push(signed);
            }
        }
        assert_eq!(find_gaps(&kept), vec![7]);
    }

    #[test]
    fn multiple_and_consecutive_gaps_are_reported() {
        let mut f = Fixture::new();
        let kept: Vec<_> = [1u64, 2, 6, 7, 11]
            .iter()
            .map(|&i| f.check_in(i, T0.plus_days(i), false))
            .collect();
        assert_eq!(find_gaps(&kept), vec![3, 4, 5, 8, 9, 10]);
    }

    #[test]
    fn gap_detection_handles_unsorted_and_duplicate_input() {
        let mut f = Fixture::new();
        let mut all: Vec<_> = [5u64, 1, 3, 1]
            .iter()
            .map(|&i| f.check_in(i, T0, false))
            .collect();
        all.reverse();
        assert_eq!(find_gaps(&all), vec![2, 4]);
        assert!(find_gaps(&[]).is_empty());
    }

    #[test]
    fn a_tree_head_verifies() {
        let f = Fixture::new();
        let head = f
            .relay
            .sign_tree_head(f.log_id, 0, merkle::empty_root(), T0);
        head.verify(&f.relay.verifying()).unwrap();
    }

    #[test]
    fn a_tree_head_from_another_relay_is_rejected() {
        let f = Fixture::new();
        let other = RelayKeypair::generate();
        let head = other.sign_tree_head(f.log_id, 0, merkle::empty_root(), T0);
        assert!(head.verify(&f.relay.verifying()).is_err());
    }

    #[test]
    fn tampering_with_a_tree_head_breaks_it() {
        let f = Fixture::new();
        let head = f.relay.sign_tree_head(f.log_id, 5, [3u8; 32], T0);
        let key = f.relay.verifying();

        let mut h = head.clone();
        h.size = 6;
        assert!(h.verify(&key).is_err());

        let mut h = head.clone();
        h.root[0] ^= 1;
        assert!(h.verify(&key).is_err());

        let mut h = head.clone();
        h.asserted_at = T0.plus_days(1);
        assert!(h.verify(&key).is_err());
    }

    #[test]
    fn a_genuine_silence_proof_verifies() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);
        let proof = f.prove(&last, 0, now);

        verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now,
        )
        .unwrap();
    }

    #[test]
    fn a_proof_is_refused_before_the_threshold() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(40);
        let proof = f.prove(&last, 0, now);

        let err = verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            Error::ReleaseRefused(crate::ReleaseRefusal::OwnerStillPresent)
        ));
    }

    #[test]
    fn a_relay_cannot_prove_an_old_checkin_while_hiding_newer_ones() {
        let mut f = Fixture::new();
        let old = f.check_in(1, T0, false);

        f.check_in(2, T0.plus_days(20), false);
        f.check_in(3, T0.plus_days(40), false);

        let now = T0.plus_days(50);
        let proof = f.prove(&old, 0, now);

        let err = verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now,
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Format { .. }),
            "proving a non-final leaf must be refused, got {err:?}"
        );
    }

    #[test]
    fn excluding_a_checkin_contradicts_the_owners_receipt() {
        let mut f = Fixture::new();
        f.check_in(1, T0, false);
        f.check_in(2, T0.plus_days(20), false);

        let receipt_size = f.log.len();
        let receipt_root = f.log.root();

        let mut rewritten = MerkleLog::new();
        let first = issue(&f.identity, &f.root, 1, T0, false).unwrap();
        rewritten.append(&first.checkin.signing_bytes());

        assert!(
            !rewritten.extends(receipt_size, &receipt_root),
            "a log missing a check-in must fail the owner's earlier receipt"
        );
    }

    #[test]
    fn a_forged_inclusion_proof_is_refused() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);

        let mut proof = f.prove(&last, 0, now);
        proof.inclusion.path.push([0u8; 32]);
        assert!(verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now
        )
        .is_err());
    }

    #[test]
    fn a_proof_with_a_foreign_checkin_is_refused() {
        let mut f = Fixture::new();
        let other = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);
        let mut proof = f.prove(&last, 0, now);

        proof.last_checkin = issue(&other.identity, &other.root, 1, T0, false).unwrap();
        assert!(verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now
        )
        .is_err());
    }

    #[test]
    fn a_proof_signed_by_the_wrong_relay_is_refused() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);
        let proof = f.prove(&last, 0, now);

        let other_relay = RelayKeypair::generate();
        assert!(verify_silence_proof(
            &proof,
            &f.identity.public(),
            &other_relay.verifying(),
            &cfg(),
            0,
            now
        )
        .is_err());
    }

    #[test]
    fn an_incoherent_tree_head_time_is_refused() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0.plus_days(60), false);
        let now = T0.plus_days(120);

        let proof = SilenceProof {
            last_checkin: last.clone(),
            inclusion: f.log.prove(0).unwrap(),
            sth: f
                .relay
                .sign_tree_head(f.log_id, f.log.len(), f.log.root(), T0),
        };
        assert!(verify_silence_proof(
            &proof,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now
        )
        .is_err());
    }

    #[test]
    fn vetoes_extend_the_required_silence() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);
        let proof = f.prove(&last, 0, now);
        let pubid = f.identity.public();
        let relay_key = f.relay.verifying();

        verify_silence_proof(&proof, &pubid, &relay_key, &cfg(), 0, now).unwrap();
        assert!(
            verify_silence_proof(&proof, &pubid, &relay_key, &cfg(), 1, now).is_err(),
            "one veto should push the threshold past day 50"
        );

        let later = T0.plus_days(80);
        let proof = f.prove(&last, 0, later);
        verify_silence_proof(&proof, &pubid, &relay_key, &cfg(), 1, later).unwrap();
    }

    #[test]
    fn proofs_survive_json() {
        let mut f = Fixture::new();
        let last = f.check_in(1, T0, false);
        let now = T0.plus_days(50);
        let proof = f.prove(&last, 0, now);

        let json = serde_json::to_string(&proof).unwrap();
        let back: SilenceProof = serde_json::from_str(&json).unwrap();
        verify_silence_proof(
            &back,
            &f.identity.public(),
            &f.relay.verifying(),
            &cfg(),
            0,
            now,
        )
        .unwrap();
    }

    #[test]
    fn signing_bytes_are_unambiguous() {
        let f = Fixture::new();
        let a = issue(&f.identity, &f.root, 1, Timestamp(100), false).unwrap();
        let b = issue(&f.identity, &f.root, 100, Timestamp(1), false).unwrap();
        assert_ne!(
            a.checkin.signing_bytes(),
            b.checkin.signing_bytes(),
            "length-prefixing must keep counter and timestamp from being confusable"
        );
    }

    #[test]
    fn a_full_year_of_checkins_stays_consistent() {
        let mut f = Fixture::new();
        let mut receipts = Vec::new();
        for i in 1..=12u64 {
            f.check_in(i, T0.plus_days(i * 30), false);
            receipts.push((f.log.len(), f.log.root()));
        }
        assert!(find_gaps(&[]).is_empty());
        for (size, root) in receipts {
            assert!(f.log.extends(size, &root));
        }
        assert_eq!(f.log.len(), 12);
        let _ = SECONDS_PER_DAY;
    }

    #[test]
    fn a_hold_verifies_only_for_its_owner_and_its_terms() {
        let owner = VaultIdentity::derive(&Key32::random());
        let hold = SignedHold::issue(&owner, Timestamp(2_000), Timestamp(1_000));
        assert!(hold.verify(&owner.public()).is_ok());

        let other = VaultIdentity::derive(&Key32::random());
        assert!(hold.verify(&other.public()).is_err());

        let mut longer = hold.clone();
        longer.until = Timestamp(9_000);
        assert!(
            longer.verify(&owner.public()).is_err(),
            "extending a hold must break it"
        );
    }

    #[test]
    fn a_trustee_list_cannot_be_altered() {
        let owner = VaultIdentity::derive(&Key32::random());
        let list = vec![TrusteeEntry {
            index: 0,
            token: "abc".into(),
            contact: Some("mailto:sam@example.org".into()),
        }];
        let signed = SignedTrustees::issue(&owner, Timestamp(5), list);
        assert!(signed.verify(&owner.public()).is_ok());

        let mut swapped = signed.clone();
        swapped.trustees[0].contact = Some("mailto:attacker@example.org".into());
        assert!(
            swapped.verify(&owner.public()).is_err(),
            "a trustee's contact was swapped"
        );

        let mut added = signed;
        added.trustees.push(TrusteeEntry {
            index: 1,
            token: "x".into(),
            contact: None,
        });
        assert!(
            added.verify(&owner.public()).is_err(),
            "a trustee was slipped in"
        );
    }

    #[test]
    fn relay_settings_cannot_be_shortened_by_anyone_else() {
        let owner = VaultIdentity::derive(&Key32::random());
        let set = SignedSettings::issue(&owner, 45 * 86_400, 3 * 86_400, None, Timestamp(9));
        assert!(set.verify(&owner.public()).is_ok());
        let mut shorter = set;
        shorter.silence_threshold = 86_400;
        assert!(shorter.verify(&owner.public()).is_err());
    }
}
