use crate::error::{Error, ReleaseRefusal, Result};
use crate::kdf::{self, label};
use crate::secret::Key32;
use crate::shamir::{self, Share, SplitId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateId(#[serde(with = "crate::codec::base64_array")] pub [u8; 16]);

impl GateId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Self(id)
    }

    pub fn short(&self) -> String {
        crate::codec::fingerprint_string(&self.0, 2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatePolicy {
    RelayAndQuorum { threshold: u8, total: u8 },

    QuorumOnly { threshold: u8, total: u8 },

    RelayOnly,
}

impl GatePolicy {
    pub fn weakness(&self) -> Option<&'static str> {
        match self {
            GatePolicy::RelayAndQuorum { .. } => None,
            GatePolicy::QuorumOnly { .. } => Some(
                "Without a relay share, a quorum of your trustees can open this capsule \
                 at any time — including while you are alive and well.",
            ),
            GatePolicy::RelayOnly => Some(
                "Without trustees, whoever controls the relay can open this capsule by \
                 declaring you silent. They become a single point of failure.",
            ),
        }
    }

    pub fn satisfies_no_single_point_of_release(&self) -> bool {
        matches!(self, GatePolicy::RelayAndQuorum { .. })
    }

    fn quorum(&self) -> Option<(u8, u8)> {
        match *self {
            GatePolicy::RelayAndQuorum { threshold, total }
            | GatePolicy::QuorumOnly { threshold, total } => Some((threshold, total)),
            GatePolicy::RelayOnly => None,
        }
    }

    fn uses_relay(&self) -> bool {
        matches!(
            self,
            GatePolicy::RelayAndQuorum { .. } | GatePolicy::RelayOnly
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseGate {
    pub gate_id: GateId,
    pub policy: GatePolicy,

    pub split_id: Option<SplitId>,
}

pub struct GateMaterial {
    pub relay_share: Option<Key32>,

    pub trustee_shares: Vec<Share>,

    pub release_key: Key32,
}

impl core::fmt::Debug for GateMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GateMaterial")
            .field(
                "relay_share",
                &self.relay_share.as_ref().map(|_| "redacted"),
            )
            .field("trustee_shares", &self.trustee_shares.len())
            .field("release_key", &"redacted")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShareDeposit {
    pub gate_id: GateId,
    #[serde(with = "crate::codec::base64_array")]
    pub share: [u8; 32],
    #[serde(with = "crate::codec::base64_array")]
    pub signature: [u8; crate::identity::SIGNATURE_LEN],
}

impl core::fmt::Debug for ShareDeposit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShareDeposit")
            .field("gate_id", &self.gate_id.short())
            .field("share", &"redacted")
            .finish()
    }
}

impl ShareDeposit {
    fn signing_bytes(
        vault: &crate::identity::Fingerprint,
        gate_id: &GateId,
        share: &[u8; 32],
    ) -> Vec<u8> {
        crate::aead::aad(&[b"zdd/v1/relay-share-deposit", &vault.0, &gate_id.0, share])
    }

    pub fn create(owner: &crate::identity::VaultIdentity, gate_id: GateId, share: &Key32) -> Self {
        let vault = owner.public().vigil_fingerprint();
        let signature = owner.sign(&Self::signing_bytes(&vault, &gate_id, share.expose()));
        Self {
            gate_id,
            share: *share.expose(),
            signature,
        }
    }

    pub fn verify(&self, identity: &crate::identity::VaultPublicIdentity) -> Result<()> {
        let vault = identity.vigil_fingerprint();
        identity.verify(
            &Self::signing_bytes(&vault, &self.gate_id, &self.share),
            &self.signature,
        )
    }
}

fn combine_halves(
    policy: GatePolicy,
    gate_id: &GateId,
    relay: Option<&Key32>,
    quorum: Option<&Key32>,
) -> Result<Key32> {
    let mut info = Vec::with_capacity(label::RELEASE_GATE.len() + 1 + 16);
    info.extend_from_slice(label::RELEASE_GATE);
    info.push(0x1F);
    info.extend_from_slice(&gate_id.0);

    match policy {
        GatePolicy::RelayAndQuorum { .. } => {
            let relay = relay.ok_or(Error::ReleaseRefused(ReleaseRefusal::NoRelayProof))?;
            let quorum = quorum.ok_or(Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet {
                have: 0,
                need: 0,
            }))?;
            Ok(kdf::derive_combined(relay, quorum, &info))
        }
        GatePolicy::QuorumOnly { .. } => {
            let quorum = quorum.ok_or(Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet {
                have: 0,
                need: 0,
            }))?;
            Ok(kdf::derive_subkey_ctx(
                quorum,
                label::RELEASE_GATE,
                &gate_id.0,
            ))
        }
        GatePolicy::RelayOnly => {
            let relay = relay.ok_or(Error::ReleaseRefused(ReleaseRefusal::NoRelayProof))?;
            Ok(kdf::derive_subkey_ctx(
                relay,
                label::RELEASE_GATE,
                &gate_id.0,
            ))
        }
    }
}

pub fn create(policy: GatePolicy) -> Result<(ReleaseGate, GateMaterial)> {
    if let Some((threshold, total)) = policy.quorum() {
        if threshold < 2 {
            return Err(crate::SharingError::ThresholdTooLow(threshold).into());
        }
        if threshold > total {
            return Err(crate::SharingError::ThresholdTooHigh { threshold, total }.into());
        }
    }

    let gate_id = GateId::random();

    let relay_share = policy.uses_relay().then(Key32::random);

    let (quorum_secret, trustee_shares, split_id) = match policy.quorum() {
        Some((threshold, total)) => {
            let secret = Key32::random();
            let shares = shamir::split_key(&secret, threshold, total)?;
            let split_id = shares[0].split_id;
            (Some(secret), shares, Some(split_id))
        }
        None => (None, Vec::new(), None),
    };

    let release_key = combine_halves(
        policy,
        &gate_id,
        relay_share.as_ref(),
        quorum_secret.as_ref(),
    )?;

    Ok((
        ReleaseGate {
            gate_id,
            policy,
            split_id,
        },
        GateMaterial {
            relay_share,
            trustee_shares,
            release_key,
        },
    ))
}

pub fn assemble(
    gate: &ReleaseGate,
    relay_share: Option<&Key32>,
    trustee_shares: &[Share],
) -> Result<Key32> {
    if gate.policy.uses_relay() && relay_share.is_none() {
        return Err(ReleaseRefusal::NoRelayProof.into());
    }

    let quorum_secret = match gate.policy.quorum() {
        Some((threshold, _)) => {
            if trustee_shares.len() < threshold as usize {
                return Err(ReleaseRefusal::QuorumNotMet {
                    have: trustee_shares.len().min(u8::MAX as usize) as u8,
                    need: threshold,
                }
                .into());
            }

            if let Some(expected) = gate.split_id {
                for share in trustee_shares {
                    if share.split_id != expected {
                        return Err(Error::format(
                            "trustee share",
                            format!(
                                "share belongs to split {} but this gate expects {}",
                                share.split_id.short(),
                                expected.short()
                            ),
                        ));
                    }
                }
            }

            Some(shamir::combine_key(trustee_shares)?)
        }
        None => None,
    };

    combine_halves(
        gate.policy,
        &gate.gate_id,
        relay_share,
        quorum_secret.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> GatePolicy {
        GatePolicy::RelayAndQuorum {
            threshold: 3,
            total: 5,
        }
    }

    #[test]
    fn a_full_gate_reassembles() {
        let (gate, material) = create(default_policy()).unwrap();
        let relay = material.relay_share.as_ref().unwrap();
        let assembled = assemble(&gate, Some(relay), &material.trustee_shares[..3]).unwrap();
        assert_eq!(assembled, material.release_key);
    }

    #[test]
    fn the_relay_alone_cannot_release() {
        let (gate, material) = create(default_policy()).unwrap();
        let relay = material.relay_share.as_ref().unwrap();

        assert!(assemble(&gate, Some(relay), &[]).is_err());

        let err = assemble(&gate, Some(relay), &material.trustee_shares[..2]).unwrap_err();
        assert!(matches!(
            err,
            Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet { have: 2, need: 3 })
        ));
    }

    #[test]
    fn all_trustees_colluding_cannot_release() {
        let (gate, material) = create(default_policy()).unwrap();

        assert!(assemble(&gate, None, &material.trustee_shares).is_err());

        let guessed = Key32::random();
        let wrong = assemble(&gate, Some(&guessed), &material.trustee_shares[..3]).unwrap();
        assert_ne!(wrong, material.release_key);
    }

    #[test]
    fn a_wrong_relay_share_yields_a_wrong_key() {
        let (gate, material) = create(default_policy()).unwrap();
        let wrong = assemble(&gate, Some(&Key32::random()), &material.trustee_shares[..3]).unwrap();
        assert_ne!(wrong, material.release_key);
    }

    #[test]
    fn shares_from_another_gate_are_refused() {
        let (gate_a, material_a) = create(default_policy()).unwrap();
        let (_gate_b, material_b) = create(default_policy()).unwrap();

        let relay_a = material_a.relay_share.as_ref().unwrap();
        assert!(assemble(&gate_a, Some(relay_a), &material_b.trustee_shares[..3]).is_err());
    }

    #[test]
    fn gate_id_binds_the_release_key() {
        let (mut gate, material) = create(default_policy()).unwrap();
        let relay = material.relay_share.as_ref().unwrap();

        let correct = assemble(&gate, Some(relay), &material.trustee_shares[..3]).unwrap();
        assert_eq!(correct, material.release_key);

        gate.gate_id = GateId::random();
        let elsewhere = assemble(&gate, Some(relay), &material.trustee_shares[..3]).unwrap();
        assert_ne!(elsewhere, material.release_key);
    }

    #[test]
    fn any_quorum_subset_works() {
        let (gate, material) = create(default_policy()).unwrap();
        let relay = material.relay_share.as_ref().unwrap();

        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let subset = [
                        Share::from_json(&material.trustee_shares[i].to_json().unwrap()).unwrap(),
                        Share::from_json(&material.trustee_shares[j].to_json().unwrap()).unwrap(),
                        Share::from_json(&material.trustee_shares[k].to_json().unwrap()).unwrap(),
                    ];
                    let got = assemble(&gate, Some(relay), &subset).unwrap();
                    assert_eq!(got, material.release_key, "trustees {i},{j},{k} failed");
                }
            }
        }
    }

    #[test]
    fn quorum_only_policy_works_without_a_relay() {
        let policy = GatePolicy::QuorumOnly {
            threshold: 2,
            total: 3,
        };
        let (gate, material) = create(policy).unwrap();
        assert!(material.relay_share.is_none());

        let got = assemble(&gate, None, &material.trustee_shares[..2]).unwrap();
        assert_eq!(got, material.release_key);

        assert!(assemble(&gate, None, &material.trustee_shares[..1]).is_err());
    }

    #[test]
    fn relay_only_policy_works_without_trustees() {
        let (gate, material) = create(GatePolicy::RelayOnly).unwrap();
        assert!(material.trustee_shares.is_empty());

        let relay = material.relay_share.as_ref().unwrap();
        assert_eq!(
            assemble(&gate, Some(relay), &[]).unwrap(),
            material.release_key
        );
        assert!(assemble(&gate, None, &[]).is_err());
    }

    #[test]
    fn weaker_policies_declare_their_weakness() {
        assert!(default_policy().satisfies_no_single_point_of_release());
        assert!(default_policy().weakness().is_none());

        for weak in [
            GatePolicy::QuorumOnly {
                threshold: 2,
                total: 3,
            },
            GatePolicy::RelayOnly,
        ] {
            assert!(!weak.satisfies_no_single_point_of_release());
            let text = weak
                .weakness()
                .expect("a weaker policy must explain itself");
            assert!(text.len() > 40, "the explanation must be a real sentence");
        }
    }

    #[test]
    fn rejects_impossible_quorums() {
        assert!(create(GatePolicy::RelayAndQuorum {
            threshold: 1,
            total: 5
        })
        .is_err());
        assert!(create(GatePolicy::RelayAndQuorum {
            threshold: 6,
            total: 5
        })
        .is_err());
        assert!(create(GatePolicy::QuorumOnly {
            threshold: 0,
            total: 3
        })
        .is_err());
    }

    #[test]
    fn rotating_a_gate_invalidates_old_shares() {
        let (old_gate, old_material) = create(default_policy()).unwrap();
        let (new_gate, new_material) = create(default_policy()).unwrap();

        assert_ne!(old_material.release_key, new_material.release_key);

        let old_relay = old_material.relay_share.as_ref().unwrap();
        assert!(assemble(
            &new_gate,
            Some(old_relay),
            &old_material.trustee_shares[..3]
        )
        .is_err());

        assert_eq!(
            assemble(
                &old_gate,
                Some(old_relay),
                &old_material.trustee_shares[..3]
            )
            .unwrap(),
            old_material.release_key
        );
    }

    #[test]
    fn gates_are_unique() {
        let (a, _) = create(default_policy()).unwrap();
        let (b, _) = create(default_policy()).unwrap();
        assert_ne!(a.gate_id, b.gate_id);
        assert_ne!(a.split_id, b.split_id);
    }

    #[test]
    fn public_gate_carries_no_secrets() {
        let (gate, material) = create(default_policy()).unwrap();
        let json = serde_json::to_string(&gate).unwrap();

        use base64::Engine as _;
        let engine = base64::engine::general_purpose::STANDARD;
        let release_b64 = engine.encode(material.release_key.expose());
        let relay_b64 = engine.encode(material.relay_share.as_ref().unwrap().expose());

        assert!(
            !json.contains(&release_b64),
            "release key leaked into the public gate"
        );
        assert!(
            !json.contains(&relay_b64),
            "relay share leaked into the public gate"
        );

        let back: ReleaseGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, gate);
    }

    #[test]
    fn debug_never_reveals_gate_material() {
        let (_, material) = create(default_policy()).unwrap();
        let rendered = format!("{material:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains(&crate::codec::to_hex(material.release_key.expose())[..8]));
    }

    #[test]
    fn a_share_deposit_verifies_only_for_its_owner() {
        let owner = crate::identity::VaultIdentity::derive(&Key32::random());
        let other = crate::identity::VaultIdentity::derive(&Key32::random());
        let share = Key32::random();
        let deposit = ShareDeposit::create(&owner, GateId::random(), &share);
        assert!(deposit.verify(&owner.public()).is_ok());
        assert!(deposit.verify(&other.public()).is_err());

        let mut swapped = deposit.clone();
        swapped.share[0] ^= 1;
        assert!(
            swapped.verify(&owner.public()).is_err(),
            "a replaced share must not verify"
        );

        let mut moved = deposit;
        moved.gate_id = GateId::random();
        assert!(
            moved.verify(&owner.public()).is_err(),
            "a share moved to another gate must not verify"
        );
    }
}
