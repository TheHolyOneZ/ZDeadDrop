use zdd_core::capsule::{
    simple_recipient, Capsule, EntryKind, Manifest, ManifestEntry, PayloadRef, RecipientSlot,
};
use zdd_core::checkin::{self, RelayKeypair, SignedCheckIn, SilenceProof};
use zdd_core::clock::{Clock, ClockIntegrity, Timestamp, VirtualClock, SECONDS_PER_DAY};
use zdd_core::identity::{RecipientIdentity, VaultIdentity};
use zdd_core::merkle::MerkleLog;
use zdd_core::policy::{self, LadderConfig, Stage, TrusteeResponse, TrusteeVerdict, VigilState};
use zdd_core::release::{self, GatePolicy};
use zdd_core::secret::Key32;
use zdd_core::stream;
use zdd_core::{Error, ReleaseRefusal};

const START: Timestamp = Timestamp(1_800_000_000);

const LETTER: &[u8] = b"The deed is in the safe. The combination is my mother's birthday, \
                        backwards. I am sorry I never said any of this out loud.";

struct World {
    clock: VirtualClock,
    integrity: ClockIntegrity,

    owner: VaultIdentity,
    owner_root: Key32,

    alex: RecipientIdentity,

    relay: RelayKeypair,
    log: MerkleLog,
    log_id: [u8; 16],

    stored: Vec<SignedCheckIn>,

    capsule: Capsule,
    cdk: Key32,
    relay_share: Key32,
    trustee_shares: Vec<zdd_core::shamir::Share>,

    payload_ciphertext: Vec<u8>,

    config: LadderConfig,
    state: VigilState,

    quorum: u8,
}

impl World {
    fn new() -> Self {
        let clock = VirtualClock::starting_at(START);
        let owner_root = Key32::random();
        let owner = VaultIdentity::derive(&owner_root);
        let alex = RecipientIdentity::generate();

        let manifest = Manifest {
            name: "For Alex".to_string(),
            note: Some("Read this first.".to_string()),
            entries: vec![ManifestEntry {
                path: "letter.txt".to_string(),
                size: LETTER.len() as u64,
                kind: EntryKind::Note,
                content_hash: *blake3::hash(LETTER).as_bytes(),
                offset: 0,
            }],
            recipient_labels: [(0u8, "Alex".to_string())].into_iter().collect(),
            total_bytes: LETTER.len() as u64,
        };

        let mut draft = Capsule::create(
            &owner,
            vec![simple_recipient(0, alex.public())],
            GatePolicy::RelayAndQuorum {
                threshold: 3,
                total: 5,
            },
            &manifest,
            clock.now(),
        )
        .expect("capsule creation");

        let payload_key = Capsule::payload_key(&draft.cdk);
        let mut ciphertext = Vec::new();
        let (prefix, written) = stream::seal_reader(
            &payload_key,
            &draft.capsule.id.0,
            &mut &LETTER[..],
            &mut ciphertext,
            |_| {},
        )
        .expect("payload encryption");

        draft.capsule.attach_payload(PayloadRef {
            prefix,
            plaintext_len: written,
            ciphertext_len: ciphertext.len() as u64,
            blob_id: *blake3::hash(&ciphertext).as_bytes(),
        });
        draft.capsule.validate().expect("capsule should be valid");

        let mut world = Self {
            clock,
            integrity: ClockIntegrity::new(),
            owner,
            owner_root,
            alex,
            relay: RelayKeypair::generate(),
            log: MerkleLog::new(),
            log_id: [42u8; 16],
            stored: Vec::new(),
            capsule: draft.capsule,
            cdk: draft.cdk,
            relay_share: draft.gate_material.relay_share.expect("relay share"),
            trustee_shares: draft.gate_material.trustee_shares,
            payload_ciphertext: ciphertext,
            config: LadderConfig::default(),
            state: VigilState::starting_at(START),
            quorum: 3,
        };
        world
            .config
            .validate()
            .expect("default ladder must be valid");
        world.check_in(false);
        world
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    fn check_in(&mut self, under_duress: bool) {
        let signed = checkin::issue(
            &self.owner,
            &self.owner_root,
            self.state.checkin_counter,
            self.now(),
            under_duress,
        )
        .expect("check-in");
        self.log.append(&signed.checkin.signing_bytes());
        self.stored.push(signed);
        self.state.check_in(self.now(), under_duress);
    }

    fn stage(&self) -> Stage {
        policy::evaluate(
            &self.config,
            &self.state,
            self.quorum,
            self.now(),
            self.integrity.frozen().is_some(),
        )
    }

    fn may_release(&self) -> Result<(), Error> {
        policy::may_release(
            &self.config,
            &self.state,
            self.quorum,
            self.now(),
            self.integrity.frozen().is_some(),
        )
    }

    fn trustee_says(&mut self, index: u8, verdict: TrusteeVerdict) {
        self.state.record_response(TrusteeResponse {
            trustee_index: index,
            verdict,
            at: self.now(),
        });
        if self.state.confirmations() >= self.quorum && self.state.quorum_met_at.is_none() {
            self.state.quorum_met_at = Some(self.now());
        }
    }

    fn silence_proof(&self) -> SilenceProof {
        self.proof_for(self.log.len() - 1)
    }

    fn proof_for(&self, index: u64) -> SilenceProof {
        SilenceProof {
            last_checkin: self.stored[index as usize].clone(),
            inclusion: self.log.prove(index).expect("inclusion proof"),
            sth: self.relay.sign_tree_head(
                self.log_id,
                self.log.len(),
                self.log.root(),
                self.now(),
            ),
        }
    }

    fn pass_days(&mut self, days: u64) {
        for _ in 0..days {
            self.clock.advance_days(1);
            let _ = self.integrity.observe(&self.clock);
        }
    }

    fn alex_opens(&self, shares: &[zdd_core::shamir::Share]) -> Result<Vec<u8>, Error> {
        let release_key = release::assemble(&self.capsule.gate, Some(&self.relay_share), shares)?;
        let cdk = self
            .capsule
            .open_as_recipient(&self.alex, 0, &release_key)?;

        let manifest = self.capsule.read_manifest(&cdk)?;
        assert_eq!(manifest.name, "For Alex");

        let payload = self.capsule.payload.as_ref().expect("payload");
        let mut out = Vec::new();
        stream::open_reader(
            &Capsule::payload_key(&cdk),
            payload.prefix,
            &self.capsule.id.0,
            &mut &self.payload_ciphertext[..],
            &mut out,
            |_| {},
        )?;
        Ok(out)
    }
}

#[test]
fn a_genuine_death_delivers_the_letter_to_exactly_one_person() {
    let mut w = World::new();

    for _ in 0..3 {
        w.pass_days(25);
        assert!(matches!(w.stage(), Stage::Held { .. }));
        w.check_in(false);
    }

    w.pass_days(31);
    assert!(
        matches!(w.stage(), Stage::Grace { .. }),
        "got {:?}",
        w.stage()
    );
    assert!(!w.stage().is_noisy(), "grace must be silent");

    w.pass_days(7);
    assert!(
        matches!(w.stage(), Stage::Escalating { .. }),
        "got {:?}",
        w.stage()
    );
    assert!(w.stage().is_noisy(), "reminders should be going out by now");

    w.pass_days(8);
    assert!(
        matches!(
            w.stage(),
            Stage::AwaitingQuorum {
                have: 0,
                need: 3,
                ..
            }
        ),
        "got {:?}",
        w.stage()
    );
    assert!(w.may_release().is_err());

    let proof = w.silence_proof();
    checkin::verify_silence_proof(
        &proof,
        &w.owner.public(),
        &w.relay.verifying(),
        &w.config,
        0,
        w.now(),
    )
    .expect("a genuine silence proof must verify");

    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    assert!(w.may_release().is_err(), "two of three is not a quorum");

    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    assert!(
        matches!(w.stage(), Stage::Countdown { .. }),
        "got {:?}",
        w.stage()
    );
    assert!(
        w.may_release().is_err(),
        "the final countdown must still run"
    );

    w.pass_days(3);
    assert_eq!(w.stage(), Stage::ReadyToRelease);
    w.may_release().expect("release should now be permitted");

    let recovered = w
        .alex_opens(&w.trustee_shares[..3])
        .expect("Alex should be able to open it");
    assert_eq!(
        recovered, LETTER,
        "Alex must receive the letter byte for byte"
    );
}

#[test]
fn nothing_releases_one_day_early() {
    let mut w = World::new();

    let mut confirmed = false;
    for day in 1..=60u64 {
        w.pass_days(1);

        if matches!(w.stage(), Stage::AwaitingQuorum { .. }) && !confirmed {
            w.trustee_says(1, TrusteeVerdict::BelievesGone);
            w.trustee_says(2, TrusteeVerdict::BelievesGone);
            w.trustee_says(3, TrusteeVerdict::BelievesGone);
            confirmed = true;
        }

        let permitted = w.may_release().is_ok();
        let expected = w.stage() == Stage::ReadyToRelease;
        assert_eq!(
            permitted,
            expected,
            "day {day}: may_release disagreed with stage {:?}",
            w.stage()
        );

        if permitted {
            let earliest = (w.config.silence_threshold + w.config.countdown) / SECONDS_PER_DAY;
            assert!(
                day >= earliest,
                "released on day {day}, but the configuration forbids it before day {earliest}"
            );
            return;
        }

        if !permitted && confirmed {
            assert!(w.may_release().is_err());
        }
    }
    panic!("the capsule never became releasable within 60 days");
}

#[test]
fn every_refusal_explains_itself() {
    let mut w = World::new();

    w.pass_days(31);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::OwnerStillPresent)
    ));

    w.pass_days(15);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet { have: 0, need: 3 })
    ));

    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet { have: 1, need: 3 })
    ));

    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::CountdownRunning)
    ));
}

#[test]
fn a_checkin_at_any_rung_resets_everything() {
    for interrupt_day in [1u64, 31, 38, 46, 47, 48] {
        let mut w = World::new();
        w.pass_days(interrupt_day);

        if matches!(
            w.stage(),
            Stage::AwaitingQuorum { .. } | Stage::Countdown { .. }
        ) {
            w.trustee_says(1, TrusteeVerdict::BelievesGone);
            w.trustee_says(2, TrusteeVerdict::BelievesGone);
            w.trustee_says(3, TrusteeVerdict::BelievesGone);
        }

        w.check_in(false);

        assert!(
            matches!(w.stage(), Stage::Held { .. }),
            "checking in on day {interrupt_day} left the vigil at {:?}",
            w.stage()
        );
        assert_eq!(
            w.state.confirmations(),
            0,
            "day {interrupt_day}: trustee poll not cleared"
        );
        assert!(
            w.state.quorum_met_at.is_none(),
            "day {interrupt_day}: countdown not cleared"
        );
        assert!(w.may_release().is_err());

        w.pass_days(44);
        assert!(
            !matches!(w.stage(), Stage::ReadyToRelease),
            "day {interrupt_day}: the ladder did not restart"
        );
    }
}

#[test]
fn cancelling_during_the_countdown_stops_the_release_permanently() {
    let mut w = World::new();
    w.pass_days(46);
    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    assert!(matches!(w.stage(), Stage::Countdown { .. }));

    w.state.cancelled = true;

    for _ in 0..40 {
        w.pass_days(10);
        assert_eq!(w.stage(), Stage::Cancelled);
        assert!(
            w.may_release().is_err(),
            "a cancelled release must not resume, however much time passes"
        );
    }
}

#[test]
fn a_vacation_hold_suspends_and_then_expires() {
    let mut w = World::new();
    let now = w.now();
    let until = now.plus_days(80);
    let config = w.config.clone();
    policy::place_hold(&config, &mut w.state, now, until).expect("80 days is within the cap");

    w.pass_days(70);
    assert!(matches!(w.stage(), Stage::OnHold { .. }));
    assert!(w.may_release().is_err());

    let now = w.now();
    assert!(
        policy::place_hold(&config, &mut w.state, now, now.plus_days(400)).is_err(),
        "an uncapped hold would defeat the switch"
    );

    w.pass_days(15);
    assert!(
        !matches!(w.stage(), Stage::OnHold { .. }),
        "the hold should have lapsed, leaving {:?}",
        w.stage()
    );
}

#[test]
fn setting_the_clock_forward_freezes_rather_than_releasing() {
    let mut w = World::new();
    w.pass_days(10);
    assert!(matches!(w.stage(), Stage::Held { .. }));

    w.clock.tamper_wall_forward(365 * SECONDS_PER_DAY);
    let err = w.integrity.observe(&w.clock).unwrap_err();
    assert!(
        matches!(err, Error::Clock(_)),
        "the jump must be detected: {err:?}"
    );

    assert_eq!(w.stage(), Stage::Frozen);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::VigilFrozen)
    ));

    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    assert_eq!(w.stage(), Stage::Frozen);
    assert!(w.may_release().is_err());

    for _ in 0..10 {
        w.pass_days(30);
        assert_eq!(w.stage(), Stage::Frozen, "a freeze must not self-heal");
    }
}

#[test]
fn the_relay_alone_cannot_release_the_capsule() {
    let mut w = World::new();
    w.pass_days(60);

    assert!(
        release::assemble(&w.capsule.gate, Some(&w.relay_share), &[]).is_err(),
        "the relay must not assemble a release key alone"
    );

    assert!(release::assemble(
        &w.capsule.gate,
        Some(&w.relay_share),
        &w.trustee_shares[..2]
    )
    .is_err());

    let stranger = RecipientIdentity::generate();
    let real_key = release::assemble(
        &w.capsule.gate,
        Some(&w.relay_share),
        &w.trustee_shares[..3],
    )
    .unwrap();
    assert!(
        w.capsule
            .open_as_recipient(&stranger, 0, &real_key)
            .is_err(),
        "the release key alone must not open the capsule"
    );
}

#[test]
fn all_trustees_colluding_cannot_release_the_capsule() {
    let w = World::new();
    assert!(
        release::assemble(&w.capsule.gate, None, &w.trustee_shares).is_err(),
        "five of five trustees must not assemble a release key without the relay"
    );
}

#[test]
fn one_trustee_cannot_fake_a_quorum() {
    let mut w = World::new();
    w.pass_days(46);

    for _ in 0..5 {
        w.trustee_says(1, TrusteeVerdict::BelievesGone);
    }
    assert_eq!(w.state.confirmations(), 1);
    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::QuorumNotMet { have: 1, need: 3 })
    ));

    let json = w.trustee_shares[0].to_json().unwrap();
    let tripled: Vec<_> = (0..3)
        .map(|_| zdd_core::shamir::Share::from_json(&json).unwrap())
        .collect();
    assert!(release::assemble(&w.capsule.gate, Some(&w.relay_share), &tripled).is_err());
}

#[test]
fn a_relay_suppressing_a_checkin_cannot_produce_a_valid_proof() {
    let mut w = World::new();

    w.pass_days(20);
    w.check_in(false);
    w.pass_days(20);
    w.check_in(false);
    w.pass_days(50);

    assert_eq!(w.log.len(), 3);
    let dishonest = w.proof_for(0);
    assert!(
        zdd_core::merkle::verify_inclusion(
            &dishonest.last_checkin.leaf(),
            &dishonest.inclusion,
            &dishonest.sth.root,
            dishonest.sth.size,
        ),
        "the inclusion proof itself must be valid, or this test proves nothing"
    );

    let err = checkin::verify_silence_proof(
        &dishonest,
        &w.owner.public(),
        &w.relay.verifying(),
        &w.config,
        0,
        w.now(),
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Format { .. }),
        "proving a non-final leaf must be refused, got {err:?}"
    );
}

#[test]
fn a_relay_rewriting_its_log_contradicts_the_owners_receipt() {
    let mut w = World::new();
    w.pass_days(20);
    w.check_in(false);

    let receipt_size = w.log.len();
    let receipt_root = w.log.root();

    let mut rewritten = MerkleLog::new();
    rewritten.append(&w.stored[0].checkin.signing_bytes());
    assert_eq!(rewritten.len(), 1);

    assert!(
        !rewritten.extends(receipt_size, &receipt_root),
        "a rewritten log must fail a receipt the owner already holds"
    );
}

#[test]
fn substituting_a_recipient_key_is_visible_and_useless() {
    let w = World::new();
    let original_seal = w.capsule.seal();

    let mut hijacked = w.capsule.clone();
    let attacker = RecipientIdentity::generate();
    hijacked.recipients[0].public_key = attacker.public();

    assert_ne!(
        hijacked.seal(),
        original_seal,
        "a swapped recipient key must change the seal a person can see"
    );
    assert_ne!(hijacked.seal().short(), original_seal.short());

    let release_key = release::assemble(
        &w.capsule.gate,
        Some(&w.relay_share),
        &w.trustee_shares[..3],
    )
    .unwrap();
    assert!(hijacked
        .open_as_recipient(&attacker, 0, &release_key)
        .is_err());
}

#[test]
fn a_duress_checkin_is_invisible_to_the_relay_but_reaches_trustees() {
    let mut w = World::new();
    w.pass_days(10);

    let normal = checkin::issue(&w.owner, &w.owner_root, 10, w.now(), false).unwrap();
    let coerced = checkin::issue(&w.owner, &w.owner_root, 10, w.now(), true).unwrap();

    normal.verify(&w.owner.public()).unwrap();
    coerced.verify(&w.owner.public()).unwrap();
    assert_eq!(
        serde_json::to_string(&normal).unwrap().len(),
        serde_json::to_string(&coerced).unwrap().len(),
        "the relay must not be able to tell them apart by size"
    );

    let mut a = w.state.clone();
    let mut b = w.state.clone();
    a.check_in(w.now(), false);
    b.check_in(w.now(), true);
    assert_eq!(
        policy::evaluate(&w.config, &a, w.quorum, w.now().plus_days(20), false),
        policy::evaluate(&w.config, &b, w.quorum, w.now().plus_days(20), false),
    );

    let channel = checkin::duress_channel_key(&w.owner_root);
    assert!(!checkin::read_envelope(
        &channel,
        &normal.checkin.duress_envelope,
        &normal.checkin.vault,
        10
    )
    .unwrap());
    assert!(checkin::read_envelope(
        &channel,
        &coerced.checkin.duress_envelope,
        &coerced.checkin.vault,
        10
    )
    .unwrap());
}

#[test]
fn a_trustee_veto_buys_time_but_cannot_bury_the_capsule() {
    let mut w = World::new();
    w.pass_days(46);
    assert!(matches!(w.stage(), Stage::AwaitingQuorum { .. }));

    w.trustee_says(1, TrusteeVerdict::BelievesPresent);
    assert!(
        matches!(w.stage(), Stage::Escalating { .. }),
        "a veto should push the poll out, leaving {:?}",
        w.stage()
    );

    w.trustee_says(2, TrusteeVerdict::BelievesPresent);
    w.trustee_says(3, TrusteeVerdict::BelievesPresent);
    w.trustee_says(4, TrusteeVerdict::BelievesPresent);
    w.trustee_says(5, TrusteeVerdict::BelievesPresent);
    assert_eq!(w.state.vetoes(), 5);

    let capped = w.config.effective_silence_threshold(w.state.vetoes());
    assert_eq!(
        capped,
        w.config.effective_silence_threshold(w.config.max_vetoes)
    );

    w.pass_days(capped / SECONDS_PER_DAY + 1);
    assert!(
        matches!(w.stage(), Stage::AwaitingQuorum { .. }),
        "vetoes must run out, leaving {:?}",
        w.stage()
    );
}

#[test]
fn an_unreachable_recipient_falls_through_to_the_fallback() {
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
                claim_window: 60 * SECONDS_PER_DAY,
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
        GatePolicy::RelayAndQuorum {
            threshold: 2,
            total: 3,
        },
        &Manifest::default(),
        START,
    )
    .unwrap();

    let released = START;
    assert_eq!(
        draft.capsule.eligible_recipients(released, released, &[]),
        vec![0]
    );
    assert_eq!(
        draft
            .capsule
            .eligible_recipients(released, released.plus_days(59), &[]),
        vec![0],
        "Sam must not be eligible while Alex's window is open"
    );
    assert_eq!(
        draft
            .capsule
            .eligible_recipients(released, released.plus_days(60), &[]),
        vec![0, 1],
        "Sam must become eligible once Alex's window lapses"
    );

    let release_key = release::assemble(
        &draft.capsule.gate,
        draft.gate_material.relay_share.as_ref(),
        &draft.gate_material.trustee_shares[..2],
    )
    .unwrap();
    assert_eq!(
        draft
            .capsule
            .open_as_recipient(&sam, 1, &release_key)
            .unwrap(),
        draft.cdk
    );

    assert_eq!(
        draft
            .capsule
            .eligible_recipients(released, released.plus_days(9999), &[0]),
        vec![0]
    );
}

#[test]
fn a_recipient_who_lost_their_key_can_be_rotated_in() {
    let mut w = World::new();
    let release_key = release::assemble(
        &w.capsule.gate,
        Some(&w.relay_share),
        &w.trustee_shares[..3],
    )
    .unwrap();

    let payload_before = w.capsule.payload.clone();
    let new_alex = RecipientIdentity::generate();
    w.capsule
        .rotate_recipient_key(&w.cdk, &release_key, 0, new_alex.public(), w.now())
        .unwrap();

    assert_eq!(
        w.capsule.payload, payload_before,
        "rotation must not rewrite the payload"
    );
    w.capsule.validate().unwrap();

    let cdk = w
        .capsule
        .open_as_recipient(&new_alex, 0, &release_key)
        .unwrap();
    assert_eq!(cdk, w.cdk);

    assert!(w
        .capsule
        .open_as_recipient(&w.alex, 0, &release_key)
        .is_err());
}

#[test]
fn the_owner_can_always_read_their_own_capsule() {
    let w = World::new();
    let cdk = w.capsule.open_as_owner(&w.owner).unwrap();
    assert_eq!(cdk, w.cdk);

    let mut out = Vec::new();
    stream::open_reader(
        &Capsule::payload_key(&cdk),
        w.capsule.payload.as_ref().unwrap().prefix,
        &w.capsule.id.0,
        &mut &w.payload_ciphertext[..],
        &mut out,
        |_| {},
    )
    .unwrap();
    assert_eq!(out, LETTER);
}

#[test]
fn a_rehearsal_reaches_the_end_of_the_ladder_and_still_refuses() {
    let mut w = World::new();
    w.state.is_rehearsal = true;

    w.pass_days(46);
    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    w.pass_days(4);

    assert_eq!(w.stage(), Stage::ReadyToRelease);

    assert!(matches!(
        w.may_release().unwrap_err(),
        Error::ReleaseRefused(ReleaseRefusal::RehearsalOnly)
    ));
}

#[test]
fn a_truncated_payload_is_never_delivered_as_though_complete() {
    let w = World::new();
    let cdk = w.capsule.open_as_owner(&w.owner).unwrap();
    let key = Capsule::payload_key(&cdk);
    let prefix = w.capsule.payload.as_ref().unwrap().prefix;

    for cut in 1..w.payload_ciphertext.len() {
        let mut out = Vec::new();
        let result = stream::open_reader(
            &key,
            prefix,
            &w.capsule.id.0,
            &mut &w.payload_ciphertext[..cut],
            &mut out,
            |_| {},
        );
        assert!(result.is_err(), "truncation to {cut} bytes went undetected");
    }
}

#[test]
fn ten_years_of_monthly_checkins_stay_consistent() {
    let mut w = World::new();
    let mut receipts = Vec::new();

    for month in 0..120 {
        w.pass_days(25);
        assert!(
            matches!(w.stage(), Stage::Held { .. }),
            "month {month}: expected Held, got {:?}",
            w.stage()
        );
        w.check_in(false);
        receipts.push((w.log.len(), w.log.root()));
    }

    assert_eq!(w.log.len(), 121);
    assert_eq!(w.state.checkin_counter, 122);

    for (size, root) in receipts {
        assert!(
            w.log.extends(size, &root),
            "log failed a receipt at size {size}"
        );
    }

    w.pass_days(46);
    w.trustee_says(1, TrusteeVerdict::BelievesGone);
    w.trustee_says(2, TrusteeVerdict::BelievesGone);
    w.trustee_says(3, TrusteeVerdict::BelievesGone);
    w.pass_days(4);
    assert_eq!(w.alex_opens(&w.trustee_shares[..3]).unwrap(), LETTER);
}
