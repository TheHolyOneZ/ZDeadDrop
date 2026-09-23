use rusqlite::{params, Connection, OptionalExtension};

use zdd_core::checkin::{SignedCheckIn, SignedTreeHead};
use zdd_core::clock::Timestamp;
use zdd_core::merkle::{InclusionProof, MerkleLog};

use crate::error::{RelayError, Result};

pub struct VaultLog {
    pub vault: String,
    pub log_id: [u8; 16],
    tree: MerkleLog,
}

impl VaultLog {
    pub fn len(&self) -> u64 {
        self.tree.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    pub fn prove(&self, index: u64) -> Option<InclusionProof> {
        self.tree.prove(index)
    }

    pub fn extends(&self, size: u64, root: &[u8; 32]) -> bool {
        self.tree.extends(size, root)
    }
}

pub fn load(conn: &Connection, vault: &str) -> Result<VaultLog> {
    let log_id: Vec<u8> = conn
        .query_row(
            "SELECT log_id FROM vaults WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| RelayError::UnknownVault(vault.to_string()))?;

    let log_id: [u8; 16] = log_id
        .try_into()
        .map_err(|_| RelayError::Corrupt("vault has a malformed log id".into()))?;

    let mut stmt =
        conn.prepare("SELECT record FROM checkins WHERE vault = ?1 ORDER BY leaf_index ASC")?;
    let rows = stmt.query_map(params![vault], |r| r.get::<_, String>(0))?;

    let mut tree = MerkleLog::new();
    for row in rows {
        let record: SignedCheckIn = serde_json::from_str(&row?)
            .map_err(|e| RelayError::Corrupt(format!("stored check-in is unreadable: {e}")))?;
        tree.append(&record.checkin.signing_bytes());
    }

    Ok(VaultLog {
        vault: vault.to_string(),
        log_id,
        tree,
    })
}

pub fn append(
    conn: &Connection,
    vault: &str,
    record: &SignedCheckIn,
    received_at: Timestamp,
) -> Result<u64> {
    let identity = crate::store::identity_of(conn, vault)?;

    record
        .verify(&identity)
        .map_err(|_| RelayError::BadSignature)?;

    if record.checkin.vault != identity.vigil_fingerprint() {
        return Err(RelayError::WrongVault);
    }

    let last: Option<i64> = conn
        .query_row(
            "SELECT MAX(counter) FROM checkins WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?
        .flatten();

    let expected = last.map(|c| c as u64 + 1).unwrap_or(1);
    if record.checkin.counter != expected {
        return Err(RelayError::OutOfOrder {
            expected,
            got: record.checkin.counter,
        });
    }

    let index = last.map(|c| c as u64).unwrap_or(0);
    let encoded = serde_json::to_string(record).map_err(|e| RelayError::Corrupt(e.to_string()))?;

    conn.execute(
        "INSERT INTO checkins (vault, counter, leaf_index, asserted_at, received_at, record)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            vault,
            record.checkin.counter as i64,
            index as i64,
            record.checkin.asserted_at.0 as i64,
            received_at.0 as i64,
            encoded
        ],
    )?;

    Ok(index)
}

pub fn sign_head(
    keypair: &zdd_core::checkin::RelayKeypair,
    log: &VaultLog,
    now: Timestamp,
) -> SignedTreeHead {
    keypair.sign_tree_head(log.log_id, log.len(), log.root(), now)
}

pub use zdd_core::checkin::Receipt;
