use zdd_core::capsule::{simple_recipient, Capsule, Manifest};
use zdd_core::clock::Timestamp;
use zdd_core::identity::{RecipientIdentity, VaultIdentity};
use zdd_core::kdf::Argon2Params;
use zdd_core::policy::VigilState;
use zdd_core::release::GatePolicy;
use zdd_core::secret::SecretBytes;
use zdd_core::vault::{CredentialKind, RecoveryPolicy, SlotRole};
use zdd_store::{LockedVault, OpenVault, StoreError};

const T0: Timestamp = Timestamp(1_800_000_000);
const PASS: &str = "correct horse battery staple";

fn pw(s: &str) -> SecretBytes {
    SecretBytes::from_slice(s.as_bytes())
}

fn fast() -> Argon2Params {
    Argon2Params::MINIMUM
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    owner: VaultIdentity,
}

impl Fixture {
    fn new() -> (Self, OpenVault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let vault = OpenVault::create(&path, &pw(PASS), fast(), RecoveryPolicy::Standard, T0)
            .expect("create vault");
        let owner = vault.identity();

        (
            Self {
                _dir: dir,
                path,
                owner,
            },
            vault,
        )
    }

    fn reopen(&self) -> OpenVault {
        LockedVault::open(&self.path)
            .expect("find vault")
            .unlock(CredentialKind::Passphrase, &pw(PASS))
            .expect("unlock")
    }

    fn capsule(&self, name: &str) -> Capsule {
        let alex = RecipientIdentity::generate();
        let manifest = Manifest {
            name: name.to_string(),
            ..Default::default()
        };
        Capsule::create(
            &self.owner,
            vec![simple_recipient(0, alex.public())],
            GatePolicy::RelayAndQuorum {
                threshold: 3,
                total: 5,
            },
            &manifest,
            T0,
        )
        .expect("create capsule")
        .capsule
    }
}

#[test]
fn a_vault_round_trips_across_a_restart() {
    let (f, mut vault) = Fixture::new();
    let capsule = f.capsule("For Alex");
    let id = capsule.id.short();
    vault.put_capsule(&capsule, T0).unwrap();

    let mut vigil = VigilState::starting_at(T0);
    vigil.checkin_counter = 42;
    vault.save_vigil(&vigil, T0).unwrap();
    drop(vault);

    let reopened = f.reopen();
    reopened
        .verify_chain()
        .expect("chain must survive a clean restart");

    let back = reopened
        .get_capsule(&id)
        .unwrap()
        .expect("capsule should persist");
    assert_eq!(back.id, capsule.id);
    assert_eq!(reopened.load_vigil().unwrap().unwrap().checkin_counter, 42);
}

#[test]
fn the_wrong_passphrase_does_not_open_the_vault() {
    let (f, vault) = Fixture::new();
    drop(vault);

    let locked = LockedVault::open(&f.path).unwrap();
    let err = locked
        .unlock(CredentialKind::Passphrase, &pw("wrong"))
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::Core(zdd_core::Error::UnlockRejected)
    ));
}

#[test]
fn capsules_list_and_delete() {
    let (f, mut vault) = Fixture::new();
    for name in ["One", "Two", "Three"] {
        vault.put_capsule(&f.capsule(name), T0).unwrap();
    }
    assert_eq!(vault.list_capsules().unwrap().len(), 3);

    let id = vault.list_capsules().unwrap()[0].id.short();
    assert!(vault.delete_capsule(&id, T0).unwrap());
    assert_eq!(vault.list_capsules().unwrap().len(), 2);
    assert!(vault.get_capsule(&id).unwrap().is_none());

    assert!(!vault.delete_capsule(&id, T0).unwrap());
}

#[test]
fn a_recovery_sheet_opens_the_same_vault() {
    let (f, mut vault) = Fixture::new();
    vault.put_capsule(&f.capsule("For Alex"), T0).unwrap();
    vault
        .add_unlock_path(SlotRole::RecoverySheet, &pw("abandon abandon ability"), T0)
        .unwrap();
    drop(vault);

    let recovered = LockedVault::open(&f.path)
        .unwrap()
        .unlock(
            CredentialKind::RecoverySheet,
            &pw("abandon abandon ability"),
        )
        .expect("the recovery sheet must open the vault");

    assert_eq!(recovered.list_capsules().unwrap().len(), 1);
    recovered.verify_chain().unwrap();
}

#[test]
fn enrolling_several_paths_keeps_them_all_working() {
    let (f, mut vault) = Fixture::new();
    vault
        .add_unlock_path(SlotRole::RecoverySheet, &pw("sheet one"), T0)
        .unwrap();
    vault
        .add_unlock_path(SlotRole::SocialRecovery, &pw("social one"), T0)
        .unwrap();
    drop(vault);

    for (kind, credential) in [
        (CredentialKind::Passphrase, PASS),
        (CredentialKind::RecoverySheet, "sheet one"),
        (CredentialKind::SocialRecovery, "social one"),
    ] {
        LockedVault::open(&f.path)
            .unwrap()
            .unlock(kind, &pw(credential))
            .unwrap_or_else(|e| panic!("{kind:?} stopped working: {e}"));
    }
}

#[test]
fn restoring_an_older_database_is_detected() {
    let (f, mut vault) = Fixture::new();
    vault.put_capsule(&f.capsule("For Alex"), T0).unwrap();
    drop(vault);

    let backup = f.path.join("vault.db.backup");
    std::fs::copy(f.path.join("vault.db"), &backup).unwrap();

    let mut vault = f.reopen();
    vault.put_capsule(&f.capsule("Second"), T0).unwrap();
    let head_mac_now = vault.events().unwrap().len();
    assert_eq!(head_mac_now, 3);
    drop(vault);

    std::fs::copy(&backup, f.path.join("vault.db")).unwrap();

    let _ = std::fs::remove_file(f.path.join("vault.db-wal"));
    let _ = std::fs::remove_file(f.path.join("vault.db-shm"));

    let rolled_back = f.reopen();

    let events = rolled_back.events().unwrap();
    assert!(
        events.len() < head_mac_now,
        "the rollback should be visible as a shorter history"
    );
}

#[test]
fn tampering_with_the_event_log_is_detected() {
    let (f, mut vault) = Fixture::new();
    vault.put_capsule(&f.capsule("For Alex"), T0).unwrap();
    vault.put_capsule(&f.capsule("Second"), T0).unwrap();
    drop(vault);

    let conn = rusqlite::Connection::open(f.path.join("vault.db")).unwrap();
    let sealed: Vec<u8> = conn
        .query_row("SELECT sealed FROM events WHERE seq = 2", [], |r| r.get(0))
        .unwrap();
    let mut tampered = sealed.clone();
    tampered[30] ^= 0x01;
    conn.execute(
        "UPDATE events SET sealed = ?1 WHERE seq = 2",
        rusqlite::params![tampered],
    )
    .unwrap();
    drop(conn);

    let vault = f.reopen();
    let err = vault.verify_chain().unwrap_err();
    assert!(
        matches!(err, StoreError::ChainBroken { seq: 2 }),
        "got {err:?}"
    );
    assert!(err.is_tampering());
}

#[test]
fn deleting_an_event_is_detected() {
    let (f, mut vault) = Fixture::new();
    for name in ["A", "B", "C"] {
        vault.put_capsule(&f.capsule(name), T0).unwrap();
    }
    drop(vault);

    let conn = rusqlite::Connection::open(f.path.join("vault.db")).unwrap();
    conn.execute("DELETE FROM events WHERE seq = 2", [])
        .unwrap();
    drop(conn);

    let vault = f.reopen();
    assert!(matches!(
        vault.verify_chain(),
        Err(StoreError::ChainBroken { .. })
    ));
}

#[test]
fn a_rebuilt_chain_fails_the_head_mac() {
    let (f, mut vault) = Fixture::new();
    for name in ["A", "B", "C"] {
        vault.put_capsule(&f.capsule(name), T0).unwrap();
    }
    drop(vault);

    let conn = rusqlite::Connection::open(f.path.join("vault.db")).unwrap();
    conn.execute("DELETE FROM events WHERE seq > 2", [])
        .unwrap();
    let hash: Vec<u8> = conn
        .query_row("SELECT hash FROM events WHERE seq = 2", [], |r| r.get(0))
        .unwrap();
    conn.execute(
        "UPDATE chain_head SET seq = 2, hash = ?1 WHERE id = 1",
        rusqlite::params![hash],
    )
    .unwrap();
    drop(conn);

    let vault = f.reopen();
    let err = vault.verify_chain().unwrap_err();
    assert!(
        matches!(err, StoreError::ChainBroken { .. }),
        "a rebuilt chain must fail the head MAC, got {err:?}"
    );
}

#[test]
fn a_capsule_row_cannot_be_moved_to_another_id() {
    let (f, mut vault) = Fixture::new();
    let a = f.capsule("For Alex");
    let b = f.capsule("For Sam");
    vault.put_capsule(&a, T0).unwrap();
    vault.put_capsule(&b, T0).unwrap();
    drop(vault);

    let conn = rusqlite::Connection::open(f.path.join("vault.db")).unwrap();
    let sealed_a: Vec<u8> = conn
        .query_row(
            "SELECT sealed FROM capsules WHERE id = ?1",
            rusqlite::params![a.id.short()],
            |r| r.get(0),
        )
        .unwrap();

    conn.execute(
        "UPDATE capsules SET sealed = ?1 WHERE id = ?2",
        rusqlite::params![sealed_a, b.id.short()],
    )
    .unwrap();
    drop(conn);

    let vault = f.reopen();
    let err = vault.get_capsule(&b.id.short()).unwrap_err();
    assert!(
        matches!(err, StoreError::Core(zdd_core::Error::Authentication)),
        "a relocated row must fail to authenticate, got {err:?}"
    );
}

#[test]
fn a_vigil_row_cannot_be_pasted_into_the_capsule_table() {
    let (f, mut vault) = Fixture::new();
    vault.save_vigil(&VigilState::starting_at(T0), T0).unwrap();
    let capsule = f.capsule("For Alex");
    vault.put_capsule(&capsule, T0).unwrap();
    drop(vault);

    let conn = rusqlite::Connection::open(f.path.join("vault.db")).unwrap();
    let vigil_row: Vec<u8> = conn
        .query_row("SELECT sealed FROM vigil WHERE id = 1", [], |r| r.get(0))
        .unwrap();
    conn.execute(
        "UPDATE capsules SET sealed = ?1 WHERE id = ?2",
        rusqlite::params![vigil_row, capsule.id.short()],
    )
    .unwrap();
    drop(conn);

    let vault = f.reopen();
    assert!(vault.get_capsule(&capsule.id.short()).is_err());
}

#[test]
fn a_row_from_another_vault_is_inert() {
    let (f1, mut v1) = Fixture::new();
    let (f2, mut v2) = Fixture::new();

    let c1 = f1.capsule("Mine");
    v1.put_capsule(&c1, T0).unwrap();
    let c2 = f2.capsule("Theirs");
    v2.put_capsule(&c2, T0).unwrap();
    drop(v1);
    drop(v2);

    let src = rusqlite::Connection::open(f1.path.join("vault.db")).unwrap();
    let row: Vec<u8> = src
        .query_row(
            "SELECT sealed FROM capsules WHERE id = ?1",
            rusqlite::params![c1.id.short()],
            |r| r.get(0),
        )
        .unwrap();
    drop(src);

    let dst = rusqlite::Connection::open(f2.path.join("vault.db")).unwrap();
    dst.execute(
        "UPDATE capsules SET sealed = ?1 WHERE id = ?2",
        rusqlite::params![row, c2.id.short()],
    )
    .unwrap();
    drop(dst);

    let vault = f2.reopen();
    assert!(vault.get_capsule(&c2.id.short()).is_err());
}

#[test]
fn a_corrupt_header_is_refused() {
    let (f, vault) = Fixture::new();
    drop(vault);

    std::fs::write(f.path.join("header.json"), "{ not json").unwrap();
    assert!(matches!(
        LockedVault::open(&f.path),
        Err(StoreError::Corrupt { .. })
    ));
}

#[test]
fn a_downgraded_header_is_refused() {
    let (f, vault) = Fixture::new();
    drop(vault);

    let text = std::fs::read_to_string(f.path.join("header.json")).unwrap();
    let mut header: serde_json::Value = serde_json::from_str(&text).unwrap();
    header["argon"]["m_cost"] = serde_json::json!(8);
    header["argon"]["t_cost"] = serde_json::json!(1);
    std::fs::write(f.path.join("header.json"), header.to_string()).unwrap();

    assert!(
        LockedVault::open(&f.path).is_err(),
        "a downgraded cost lets an attacker grind the passphrase"
    );
}

#[test]
fn opening_a_directory_with_no_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        LockedVault::open(dir.path()),
        Err(StoreError::NotFound(_))
    ));
}

#[test]
fn creating_over_an_existing_vault_is_refused() {
    let (f, vault) = Fixture::new();
    drop(vault);

    let err = OpenVault::create(
        &f.path,
        &pw("different"),
        fast(),
        RecoveryPolicy::Standard,
        T0,
    )
    .unwrap_err();
    assert!(
        matches!(err, StoreError::AlreadyExists(_)),
        "creating over a vault would destroy it"
    );
}

#[test]
fn payload_blobs_survive_a_restart_and_verify() {
    let (f, vault) = Fixture::new();
    let payload = vec![0xABu8; 3_000_000];
    let (id, len) = vault.blobs().put(&mut payload.as_slice()).unwrap();
    assert_eq!(len, payload.len() as u64);
    drop(vault);

    let reopened = f.reopen();
    let mut out = Vec::new();
    reopened.blobs().get(id, &mut out).unwrap();
    assert_eq!(out, payload);
}

#[test]
fn a_corrupted_payload_is_caught_at_read() {
    let (f, vault) = Fixture::new();
    let payload = vec![0x5Au8; 100_000];
    let (id, _) = vault.blobs().put(&mut payload.as_slice()).unwrap();

    let hex = id.hex();
    let path = vault
        .blobs()
        .root()
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(&hex[4..]);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[500] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();
    drop(vault);

    let reopened = f.reopen();
    let mut out = Vec::new();
    assert!(matches!(
        reopened.blobs().get(id, &mut out),
        Err(StoreError::BlobCorrupt { .. })
    ));
}
