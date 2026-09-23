use std::sync::{Arc, Mutex};

use zdd_core::checkin::{self, RelayKeypair, SignedCheckIn, SilenceProof};
use zdd_core::clock::{Timestamp, SECONDS_PER_DAY};
use zdd_core::identity::VaultIdentity;
use zdd_core::merkle::MerkleLog;
use zdd_core::policy::LadderConfig;
use zdd_core::secret::Key32;
use zdd_relay::{api, log, store, Receipt};

const T0: Timestamp = Timestamp(1_800_000_000);

struct Harness {
    _dir: tempfile::TempDir,
    state: Arc<api::Relay>,
    base: String,
    relay_key: [u8; 32],
    owner: VaultIdentity,
    owner_root: Key32,
    vault: String,
    client: reqwest::Client,
}

async fn start() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let db = store::open(&dir.path().join("relay.db")).unwrap();
    let keypair = RelayKeypair::from_seed(&Key32::new([9u8; 32]));
    let relay_key = keypair.verifying();

    let state = Arc::new(api::Relay {
        db: Mutex::new(db),
        keypair,
        clock: zdd_core::clock::SystemClock,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = api::router(Arc::clone(&state));
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let owner_root = Key32::random();
    let owner = VaultIdentity::derive(&owner_root);
    let vault = owner.public().vigil_fingerprint().short();

    let h = Harness {
        _dir: dir,
        state: Arc::clone(&state),
        base: format!("http://{addr}"),
        relay_key,
        owner,
        owner_root,
        vault,
        client: reqwest::Client::new(),
    };

    let body = serde_json::json!({
        "vault": h.vault,
        "identity": h.owner.public(),
        "relay_share": zdd_core::codec::to_hex(Key32::new([3u8; 32]).expose()),
        "silence_threshold": 45 * SECONDS_PER_DAY,
        "trustees": [
            { "index": 1, "token": "tok-one" },
            { "index": 2, "token": "tok-two" },
            { "index": 3, "token": "tok-three" },
        ],
    });
    let res = h
        .client
        .post(format!("{}/v1/vault", h.base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        res.status().is_success(),
        "enrolment failed: {}",
        res.text().await.unwrap()
    );

    h
}

impl Harness {
    async fn check_in(&self, counter: u64, at: Timestamp) -> (SignedCheckIn, reqwest::Response) {
        let record = checkin::issue(&self.owner, &self.owner_root, counter, at, false).unwrap();
        let res = self
            .client
            .post(format!("{}/v1/vault/{}/checkin", self.base, self.vault))
            .json(&record)
            .send()
            .await
            .unwrap();
        (record, res)
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn every_checkin_returns_a_verifiable_receipt() {
    let h = start().await;

    for counter in 1..=5u64 {
        let (record, res) = h.check_in(counter, T0.plus_days(counter * 30)).await;
        assert!(res.status().is_success(), "check-in {counter} rejected");

        let receipt: Receipt = res.json().await.unwrap();
        assert!(
            receipt.verify(&record, &h.relay_key),
            "receipt for check-in {counter} did not verify"
        );
        assert_eq!(receipt.index, counter - 1);
        assert_eq!(receipt.sth.size, counter);
    }
}

#[tokio::test]
async fn a_receipt_from_the_wrong_key_is_rejected() {
    let h = start().await;
    let (record, res) = h.check_in(1, T0).await;
    let receipt: Receipt = res.json().await.unwrap();

    let impostor = RelayKeypair::generate().verifying();
    assert!(!receipt.verify(&record, &impostor));
}

#[tokio::test]
async fn an_auditor_can_rebuild_the_log_and_check_old_receipts() {
    let h = start().await;

    let mut receipts = Vec::new();
    for counter in 1..=6u64 {
        let (record, res) = h.check_in(counter, T0.plus_days(counter * 20)).await;
        let receipt: Receipt = res.json().await.unwrap();
        receipts.push((record, receipt));
    }

    let published: serde_json::Value = h
        .get(&format!("/v1/vault/{}/log", h.vault))
        .await
        .json()
        .await
        .unwrap();
    let records = published["records"].as_array().unwrap();
    assert_eq!(records.len(), 6);

    let mut tree = MerkleLog::new();
    for value in records {
        let record: SignedCheckIn = serde_json::from_value(value.clone()).unwrap();

        record
            .verify(&h.owner.public())
            .expect("published record is not the owner's");
        tree.append(&record.checkin.signing_bytes());
    }

    assert_eq!(
        zdd_core::codec::to_hex(&tree.root()),
        published["root"].as_str().unwrap(),
        "the relay's published root does not match its own records"
    );

    for (_, receipt) in &receipts {
        assert!(
            tree.extends(receipt.sth.size, &receipt.sth.root),
            "the relay's current log contradicts a head it signed at size {}",
            receipt.sth.size
        );
    }
}

#[tokio::test]
async fn a_suppressed_checkin_contradicts_the_receipt_the_owner_holds() {
    let h = start().await;

    let (_, res) = h.check_in(1, T0).await;
    let first: Receipt = res.json().await.unwrap();
    let (_, res) = h.check_in(2, T0.plus_days(30)).await;
    let second: Receipt = res.json().await.unwrap();

    assert_eq!(first.sth.size, 1);
    assert_eq!(second.sth.size, 2);

    let mut shorter = MerkleLog::new();
    let record = checkin::issue(&h.owner, &h.owner_root, 1, T0, false).unwrap();
    shorter.append(&record.checkin.signing_bytes());
    assert!(!shorter.extends(second.sth.size, &second.sth.root));
}

#[tokio::test]
async fn a_replayed_checkin_is_refused() {
    let h = start().await;
    let record = checkin::issue(&h.owner, &h.owner_root, 1, T0, false).unwrap();

    let send = |body: SignedCheckIn| {
        let client = h.client.clone();
        let url = format!("{}/v1/vault/{}/checkin", h.base, h.vault);
        async move { client.post(url).json(&body).send().await.unwrap() }
    };

    assert!(send(record.clone()).await.status().is_success());
    let again = send(record).await;
    assert_eq!(
        again.status(),
        reqwest::StatusCode::CONFLICT,
        "the same check-in was accepted twice"
    );
}

#[tokio::test]
async fn an_out_of_order_checkin_is_refused() {
    let h = start().await;
    let (_, res) = h.check_in(1, T0).await;
    assert!(res.status().is_success());

    let (_, res) = h.check_in(5, T0.plus_days(1)).await;
    assert_eq!(res.status(), reqwest::StatusCode::CONFLICT);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("#2"),
        "the client needs to know where to resume: {body}"
    );
}

#[tokio::test]
async fn a_forged_checkin_is_refused() {
    let h = start().await;
    let impostor_root = Key32::random();
    let impostor = VaultIdentity::derive(&impostor_root);
    let forged = checkin::issue(&impostor, &impostor_root, 1, T0, false).unwrap();

    let res = h
        .client
        .post(format!("{}/v1/vault/{}/checkin", h.base, h.vault))
        .json(&forged)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_release_share_is_withheld_while_the_owner_is_present() {
    let h = start().await;
    let (_, res) = h
        .check_in(
            1,
            zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock),
        )
        .await;
    assert!(res.status().is_success());

    let res = h
        .client
        .post(format!("{}/v1/vault/{}/release-share", h.base, h.vault))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);

    let res = h.get(&format!("/v1/vault/{}/silence-proof", h.vault)).await;
    assert_eq!(res.status(), reqwest::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_genuine_silence_proof_verifies_and_terminates_the_log() {
    let h = start().await;

    let long_ago = Timestamp(
        zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock).0 - 60 * SECONDS_PER_DAY,
    );
    let (_, res) = h.check_in(1, long_ago).await;
    assert!(res.status().is_success());

    let res = h.get(&format!("/v1/vault/{}/silence-proof", h.vault)).await;
    assert!(
        res.status().is_success(),
        "proof refused: {}",
        res.text().await.unwrap()
    );

    let proof: SilenceProof = res.json().await.unwrap();
    checkin::verify_silence_proof(
        &proof,
        &h.owner.public(),
        &h.relay_key,
        &LadderConfig::default(),
        0,
        zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock),
    )
    .expect("a genuine silence proof must verify");

    assert_eq!(
        proof.inclusion.index + 1,
        proof.sth.size,
        "the proof must be about the last leaf"
    );

    let res = h
        .client
        .post(format!("{}/v1/vault/{}/release-share", h.base, h.vault))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
}

#[tokio::test]
async fn a_trustee_learns_only_the_question() {
    let h = start().await;
    h.check_in(1, T0).await;

    let res = h.get("/v1/trustee/tok-one").await;
    assert!(res.status().is_success());
    let body = res.text().await.unwrap();

    assert!(
        body.contains("still reachable"),
        "the prompt is missing: {body}"
    );
    assert!(
        !body.contains(&h.vault),
        "the prompt leaked the vault id: {body}"
    );
    assert!(
        !body.to_lowercase().contains("capsule"),
        "the prompt mentions capsules: {body}"
    );
    assert!(
        !body.contains("tok-two"),
        "the prompt leaked another trustee: {body}"
    );
}

#[tokio::test]
async fn a_trustee_can_answer_once_and_it_is_recorded() {
    let h = start().await;
    h.check_in(1, T0).await;

    let res = h
        .client
        .post(format!("{}/v1/trustee/tok-one", h.base))
        .json(&serde_json::json!({ "verdict": "gone" }))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let prompt: serde_json::Value = h.get("/v1/trustee/tok-one").await.json().await.unwrap();
    assert_eq!(prompt["already_answered"], serde_json::json!(true));

    let status: serde_json::Value = h
        .get(&format!("/v1/vault/{}/status", h.vault))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(status["confirmations"], serde_json::json!(1));
}

#[tokio::test]
async fn a_trustee_is_not_told_how_close_the_quorum_is() {
    let h = start().await;
    h.check_in(1, T0).await;

    for token in ["tok-one", "tok-two"] {
        h.client
            .post(format!("{}/v1/trustee/{token}", h.base))
            .json(&serde_json::json!({ "verdict": "gone" }))
            .send()
            .await
            .unwrap();
    }

    let res = h
        .client
        .post(format!("{}/v1/trustee/tok-three", h.base))
        .json(&serde_json::json!({ "verdict": "gone" }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body["answers_so_far"].as_u64().unwrap() <= 1,
        "the relay told a trustee the running tally: {body}"
    );
}

#[tokio::test]
async fn an_unrecognised_trustee_token_reveals_nothing() {
    let h = start().await;
    let res = h.get("/v1/trustee/not-a-real-token").await;
    assert_eq!(res.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_vault_cannot_be_enrolled_twice() {
    let h = start().await;
    let body = serde_json::json!({
        "vault": h.vault,
        "identity": h.owner.public(),
        "silence_threshold": 45 * SECONDS_PER_DAY,
    });
    let res = h
        .client
        .post(format!("{}/v1/vault", h.base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), reqwest::StatusCode::CONFLICT);
}

#[tokio::test]
async fn an_absurd_silence_threshold_is_refused() {
    let h = start().await;
    let other = VaultIdentity::derive(&Key32::random());
    let body = serde_json::json!({
        "vault": other.public().vigil_fingerprint().short(),
        "identity": other.public(),
        "silence_threshold": 5,
    });
    let res = h
        .client
        .post(format!("{}/v1/vault", h.base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        !res.status().is_success(),
        "a five-second threshold was accepted"
    );
}

#[tokio::test]
async fn an_unknown_vault_is_indistinguishable_from_a_bad_signature() {
    let h = start().await;

    let unknown = h.get("/v1/vault/0000-0000-0000/status").await;
    assert_eq!(unknown.status(), reqwest::StatusCode::NOT_FOUND);

    let impostor_root = Key32::random();
    let impostor = VaultIdentity::derive(&impostor_root);
    let forged = checkin::issue(&impostor, &impostor_root, 1, T0, false).unwrap();
    let bad_sig = h
        .client
        .post(format!("{}/v1/vault/{}/checkin", h.base, h.vault))
        .json(&forged)
        .send()
        .await
        .unwrap();

    assert_eq!(bad_sig.status(), unknown.status());
}

#[tokio::test]
async fn checking_in_resets_the_reminder_counters() {
    let h = start().await;
    h.check_in(1, T0).await;

    {
        let db = h.state.db();
        db.execute(
            "UPDATE vaults SET reminders_sent = 4, trustees_polled = 1 WHERE vault = ?1",
            rusqlite::params![h.vault],
        )
        .unwrap();
        db.execute(
            "UPDATE trustees SET verdict = 'gone' WHERE vault = ?1",
            rusqlite::params![h.vault],
        )
        .unwrap();
    }

    let (_, res) = h.check_in(2, T0.plus_days(1)).await;
    assert!(res.status().is_success());

    let db = h.state.db();
    let (sent, polled): (i64, i64) = db
        .query_row(
            "SELECT reminders_sent, trustees_polled FROM vaults WHERE vault = ?1",
            rusqlite::params![h.vault],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(sent, 0, "reminders were not reset by a check-in");
    assert_eq!(polled, 0, "the trustee poll was not reset by a check-in");

    let confirmations: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM trustees WHERE vault = ?1 AND verdict = 'gone'",
            rusqlite::params![h.vault],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        confirmations, 0,
        "a check-in must clear the previous poll's answers"
    );
}

#[tokio::test]
async fn the_relay_publishes_its_verifying_key() {
    let h = start().await;
    let body: serde_json::Value = h.get("/v1/key").await.json().await.unwrap();
    assert_eq!(
        body["verifying_key"].as_str().unwrap(),
        zdd_core::codec::to_hex(&h.relay_key)
    );
}

#[tokio::test]
async fn the_log_id_is_derived_so_a_restore_keeps_receipts_valid() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let owner = VaultIdentity::derive(&Key32::random());
    let vault = owner.public().vigil_fingerprint().short();

    let mut ids = Vec::new();
    for dir in [&a, &b] {
        let conn = store::open(&dir.path().join("relay.db")).unwrap();
        ids.push(
            store::enroll(
                &conn,
                &vault,
                &owner.public(),
                None,
                45 * SECONDS_PER_DAY,
                None,
                0,
            )
            .unwrap(),
        );
    }
    assert_eq!(ids[0], ids[1]);
    let _ = log::load;
}

#[tokio::test]
async fn only_the_owner_can_deposit_a_capsule_share() {
    use zdd_core::release::{GateId, ShareDeposit};

    let h = start().await;
    let share = Key32::random();
    let gate = GateId::random();
    let url = format!("{}/v1/vault/{}/shares", h.base, h.vault);

    let stranger = VaultIdentity::derive(&Key32::random());
    let forged = ShareDeposit::create(&stranger, gate, &share);
    let res = h.client.post(&url).json(&forged).send().await.unwrap();
    assert!(
        !res.status().is_success(),
        "a stranger's deposit was accepted"
    );

    let real = ShareDeposit::create(&h.owner, gate, &share);
    let res = h.client.post(&url).json(&real).send().await.unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());

    let release = format!("{}/v1/vault/{}/release-share", h.base, h.vault);
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let (_, res) = h.check_in(1, now).await;
    assert!(res.status().is_success());
    let res = h.client.post(&release).send().await.unwrap();
    assert!(
        !res.status().is_success(),
        "released while the owner is present"
    );

    let long_ago = Timestamp(now.0 - 60 * SECONDS_PER_DAY);
    let (_, res) = h.check_in(2, long_ago).await;
    assert!(res.status().is_success());
    let res = h.client.post(&release).send().await.unwrap();
    assert!(res.status().is_success());
    let body: serde_json::Value = res.json().await.unwrap();
    let gate_hex = zdd_core::codec::to_hex(&gate.0);
    assert_eq!(
        body["shares"][&gate_hex].as_str(),
        Some(zdd_core::codec::to_hex(share.expose()).as_str())
    );
}

#[tokio::test]
async fn a_relay_only_capsule_opens_with_the_deposited_share() {
    use zdd_core::capsule::{simple_recipient, Capsule, Manifest};
    use zdd_core::identity::RecipientIdentity;
    use zdd_core::release::{self, GatePolicy, ShareDeposit};

    let h = start().await;
    let recipient = RecipientIdentity::generate();
    let manifest = Manifest {
        name: "Server credentials".into(),
        ..Default::default()
    };
    let draft = Capsule::create(
        &h.owner,
        vec![simple_recipient(0, recipient.public())],
        GatePolicy::RelayOnly,
        &manifest,
        Timestamp(1),
    )
    .unwrap();
    let share = draft.gate_material.relay_share.as_ref().unwrap();
    let deposit = ShareDeposit::create(&h.owner, draft.capsule.gate.gate_id, share);
    let res = h
        .client
        .post(format!("{}/v1/vault/{}/shares", h.base, h.vault))
        .json(&deposit)
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let (_, res) = h.check_in(1, Timestamp(now.0 - 60 * SECONDS_PER_DAY)).await;
    assert!(res.status().is_success());

    let body: serde_json::Value = h
        .client
        .post(format!("{}/v1/vault/{}/release-share", h.base, h.vault))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hex = body["shares"][zdd_core::codec::to_hex(&draft.capsule.gate.gate_id.0)]
        .as_str()
        .expect("the relay returned this capsule's share");
    let relay_share = Key32::from_slice(&zdd_core::codec::from_hex(hex).unwrap()).unwrap();

    let release_key = release::assemble(&draft.capsule.gate, Some(&relay_share), &[]).unwrap();
    let cdk = draft
        .capsule
        .open_as_recipient(&recipient, 0, &release_key)
        .expect("the recipient opens it with the relay's share");
    assert_eq!(
        draft.capsule.read_manifest(&cdk).unwrap().name,
        "Server credentials"
    );
}

#[tokio::test]
async fn a_hold_pauses_the_relay_and_cannot_be_replayed() {
    use zdd_core::checkin::SignedHold;

    let h = start().await;
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let url = format!("{}/v1/vault/{}/hold", h.base, h.vault);
    let release = format!("{}/v1/vault/{}/release-share", h.base, h.vault);

    let (_, res) = h.check_in(1, Timestamp(now.0 - 60 * SECONDS_PER_DAY)).await;
    assert!(res.status().is_success());

    let greedy = SignedHold::issue(&h.owner, now.plus_days(400), now);
    assert!(!h
        .client
        .post(&url)
        .json(&greedy)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let away = SignedHold::issue(&h.owner, now.plus_days(14), now);
    let res = h.client.post(&url).json(&away).send().await.unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    let res = h.client.post(&release).send().await.unwrap();
    assert!(!res.status().is_success(), "released during a hold");

    let back = SignedHold::issue(&h.owner, now.plus_secs(1), now.plus_secs(1));
    assert!(h
        .client
        .post(&url)
        .json(&back)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let res = h.client.post(&url).json(&away).send().await.unwrap();
    assert!(!res.status().is_success(), "an old hold was replayed");

    let stranger = VaultIdentity::derive(&Key32::random());
    let forged = SignedHold::issue(&stranger, now.plus_days(14), now.plus_secs(5));
    assert!(!h
        .client
        .post(&url)
        .json(&forged)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}

#[tokio::test]
async fn a_tap_link_counts_once_and_only_when_tapped() {
    let h = start().await;
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let (_, res) = h.check_in(1, Timestamp(now.0 - 60 * SECONDS_PER_DAY)).await;
    assert!(res.status().is_success());

    let token = {
        let db = h.state.db();
        store::new_tap(&db, &h.vault, now.0).unwrap()
    };
    let release = format!("{}/v1/vault/{}/release-share", h.base, h.vault);
    let tap = format!("{}/v1/tap/{token}", h.base);

    let page = h
        .client
        .get(&tap)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("I'm here"));
    assert!(h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let body = h
        .client
        .post(&tap)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(body.contains("noted"), "{body}");
    assert!(!h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let again = h
        .client
        .post(&tap)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(again.contains("already been used"), "{again}");
}

#[test]
fn taps_cannot_postpone_forever() {
    let dir = tempfile::tempdir().unwrap();
    let db = store::open(&dir.path().join("r.db")).unwrap();
    let owner = VaultIdentity::derive(&Key32::random());
    let vault = owner.public().vigil_fingerprint().short();
    store::enroll(
        &db,
        &vault,
        &owner.public(),
        None,
        45 * SECONDS_PER_DAY,
        None,
        0,
    )
    .unwrap();
    let signed_at = 1_000_000u64;
    let rec = checkin::issue(&owner, &Key32::random(), 1, Timestamp(signed_at), false).unwrap();

    zdd_relay::log::append(&db, &vault, &rec, Timestamp(signed_at))
        .unwrap_or_else(|_| panic!("append"));
    let far_future = signed_at + 400 * SECONDS_PER_DAY;
    let token = store::new_tap(&db, &vault, far_future).unwrap();
    store::use_tap(&db, &token, far_future).unwrap();
    let (_, effective) = store::last_checkin(&db, &vault).unwrap().unwrap();
    assert_eq!(effective, signed_at + store::MAX_TAP_EXTENSION);
}

#[tokio::test]
async fn a_signed_trustee_list_and_a_page_a_person_can_answer() {
    use zdd_core::checkin::{SignedTrustees, TrusteeEntry};

    let h = start().await;
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let url = format!("{}/v1/vault/{}/trustees", h.base, h.vault);
    let token = "0123456789abcdef0123456789abcdef".to_string();
    let list = vec![TrusteeEntry {
        index: 0,
        token: token.clone(),
        contact: Some("mailto:sam@example.org".into()),
    }];

    let stranger = VaultIdentity::derive(&Key32::random());
    let forged = SignedTrustees::issue(&stranger, now, list.clone());
    assert!(!h
        .client
        .post(&url)
        .json(&forged)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let signed = SignedTrustees::issue(&h.owner, now, list);
    let res = h.client.post(&url).json(&signed).send().await.unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());

    assert!(!h
        .client
        .post(&url)
        .json(&signed)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let page = h
        .client
        .get(format!("{}/v1/trustee/{token}", h.base))
        .header("accept", "text/html")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(page.contains("still reachable"), "{page}");
    assert!(!page.contains(&h.vault), "the page leaked the vault id");

    let res = h
        .client
        .post(format!("{}/v1/trustee/{token}", h.base))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("verdict=present")
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    let status: serde_json::Value = h
        .get(&format!("/v1/vault/{}/status", h.vault))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(status["vetoes"], 1);
}

#[test]
fn a_reordered_trustee_list_is_accepted() {
    use zdd_core::checkin::TrusteeEntry;
    let dir = tempfile::tempdir().unwrap();
    let db = store::open(&dir.path().join("r.db")).unwrap();
    let owner = VaultIdentity::derive(&Key32::random());
    let vault = owner.public().vigil_fingerprint().short();
    store::enroll(
        &db,
        &vault,
        &owner.public(),
        None,
        45 * SECONDS_PER_DAY,
        None,
        0,
    )
    .unwrap();
    let t = |i: u8, tok: &str| TrusteeEntry {
        index: i,
        token: tok.into(),
        contact: None,
    };
    store::replace_trustees(&db, &vault, 1, &[t(0, "aaaa"), t(1, "bbbb")]).unwrap();
    store::replace_trustees(&db, &vault, 2, &[t(0, "bbbb"), t(1, "aaaa")]).unwrap();
    store::replace_trustees(&db, &vault, 3, &[t(0, "cccc")]).unwrap();
    let n: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM trustees WHERE vault = ?1",
            [&vault],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn the_final_countdown_holds_the_share_back() {
    use zdd_core::checkin::SignedSettings;

    let h = start().await;
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let url = format!("{}/v1/vault/{}/settings", h.base, h.vault);
    let release = format!("{}/v1/vault/{}/release-share", h.base, h.vault);

    let (_, res) = h.check_in(1, Timestamp(now.0 - 46 * SECONDS_PER_DAY)).await;
    assert!(res.status().is_success());
    let set = SignedSettings::issue(
        &h.owner,
        45 * SECONDS_PER_DAY,
        3 * SECONDS_PER_DAY,
        None,
        now,
    );
    let res = h.client.post(&url).json(&set).send().await.unwrap();
    assert!(res.status().is_success(), "{}", res.text().await.unwrap());
    assert!(!h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let stranger = VaultIdentity::derive(&Key32::random());
    let cut = SignedSettings::issue(&stranger, 45 * SECONDS_PER_DAY, 0, None, now.plus_secs(1));
    assert!(!h
        .client
        .post(&url)
        .json(&cut)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let none = SignedSettings::issue(&h.owner, 45 * SECONDS_PER_DAY, 0, None, now.plus_secs(2));
    assert!(h
        .client
        .post(&url)
        .json(&none)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert!(h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}

#[tokio::test]
async fn a_trustee_veto_postpones_the_relay() {
    use zdd_core::checkin::{SignedTrustees, TrusteeEntry};

    let h = start().await;
    let now = zdd_core::clock::Clock::now(&zdd_core::clock::SystemClock);
    let release = format!("{}/v1/vault/{}/release-share", h.base, h.vault);
    let (_, res) = h.check_in(1, Timestamp(now.0 - 50 * SECONDS_PER_DAY)).await;
    assert!(res.status().is_success());
    assert!(h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());

    let token = "fedcba9876543210fedcba9876543210".to_string();
    let list = SignedTrustees::issue(
        &h.owner,
        now,
        vec![TrusteeEntry {
            index: 0,
            token: token.clone(),
            contact: None,
        }],
    );
    let url = format!("{}/v1/vault/{}/trustees", h.base, h.vault);
    assert!(h
        .client
        .post(&url)
        .json(&list)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    let res = h
        .client
        .post(format!("{}/v1/trustee/{token}", h.base))
        .json(&serde_json::json!({ "verdict": "present" }))
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());

    assert!(!h
        .client
        .post(&release)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
}
