use rusqlite::{params, Connection, OptionalExtension};

use zdd_core::identity::VaultPublicIdentity;
use zdd_core::secret::Key32;

use crate::error::{RelayError, Result};

pub fn open(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    migrate(&conn)?;
    Ok(conn)
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS vaults (
            vault             TEXT PRIMARY KEY,
            log_id            BLOB NOT NULL,
            identity          TEXT NOT NULL,
            relay_share       BLOB,
            silence_threshold INTEGER NOT NULL,
            enrolled_at       INTEGER NOT NULL,
            -- Where to reach the owner. "mailto:..." or a webhook URL.
            owner_contact     TEXT,
            -- How many reminders have gone out since the last check-in. Reset
            -- on check-in; see schedule::reset for why that matters.
            reminders_sent    INTEGER NOT NULL DEFAULT 0,
            trustees_polled   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS checkins (
            vault       TEXT NOT NULL REFERENCES vaults(vault) ON DELETE CASCADE,
            counter     INTEGER NOT NULL,
            leaf_index  INTEGER NOT NULL,
            asserted_at INTEGER NOT NULL,
            received_at INTEGER NOT NULL,
            record      TEXT NOT NULL,
            PRIMARY KEY (vault, counter)
        );

        CREATE TABLE IF NOT EXISTS trustees (
            vault     TEXT NOT NULL REFERENCES vaults(vault) ON DELETE CASCADE,
            idx       INTEGER NOT NULL,
            token     TEXT NOT NULL UNIQUE,
            contact   TEXT,
            verdict   TEXT,
            answered  INTEGER,
            PRIMARY KEY (vault, idx)
        );

        CREATE TABLE IF NOT EXISTS deliveries (
            vault        TEXT NOT NULL,
            channel_kind TEXT NOT NULL,
            -- Redacted. See notify::Channel::redacted.
            destination  TEXT NOT NULL,
            message      TEXT NOT NULL,
            ok           INTEGER NOT NULL,
            detail       TEXT,
            at           INTEGER NOT NULL
        );

        -- The relay's half of each capsule's release key, one per gate, as
        -- deposited and signed by the owner. Handed out only after silence.
        CREATE TABLE IF NOT EXISTS gate_shares (
            vault     TEXT NOT NULL REFERENCES vaults(vault) ON DELETE CASCADE,
            gate_id   TEXT NOT NULL,
            share     BLOB NOT NULL,
            deposited INTEGER NOT NULL,
            PRIMARY KEY (vault, gate_id)
        );

        -- One-tap "I'm here" links from reminder emails. Relay-attested, so
        -- they can only ever postpone a release, and only for so long.
        CREATE TABLE IF NOT EXISTS taps (
            token   TEXT PRIMARY KEY,
            vault   TEXT NOT NULL REFERENCES vaults(vault) ON DELETE CASCADE,
            issued  INTEGER NOT NULL,
            used_at INTEGER
        );

        -- The owner's signed terms, beyond enrolment: the final countdown that
        -- follows the silence threshold.
        CREATE TABLE IF NOT EXISTS vault_settings (
            vault         TEXT PRIMARY KEY REFERENCES vaults(vault) ON DELETE CASCADE,
            release_delay INTEGER NOT NULL,
            issued_at     INTEGER NOT NULL
        );

        -- Whether the final-countdown warning has gone out for this silence.
        CREATE TABLE IF NOT EXISTS countdowns (
            vault   TEXT PRIMARY KEY REFERENCES vaults(vault) ON DELETE CASCADE,
            sent_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS trustee_lists (
            vault     TEXT PRIMARY KEY REFERENCES vaults(vault) ON DELETE CASCADE,
            issued_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS holds (
            vault      TEXT PRIMARY KEY REFERENCES vaults(vault) ON DELETE CASCADE,
            until      INTEGER NOT NULL,
            issued_at  INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS checkins_asserted ON checkins (vault, asserted_at DESC);
        CREATE INDEX IF NOT EXISTS deliveries_at ON deliveries (vault, at DESC);
        "#,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn enroll(
    conn: &Connection,
    vault: &str,
    identity: &VaultPublicIdentity,
    relay_share: Option<&Key32>,
    silence_threshold: u64,
    owner_contact: Option<&str>,
    now: u64,
) -> Result<[u8; 16]> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM vaults WHERE vault = ?1",
            params![vault],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if exists {
        return Err(RelayError::AlreadyEnrolled);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zdd/v1/relay-log-id");
    hasher.update(vault.as_bytes());
    let mut log_id = [0u8; 16];
    log_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);

    let identity_json =
        serde_json::to_string(identity).map_err(|e| RelayError::Corrupt(e.to_string()))?;

    conn.execute(
        "INSERT INTO vaults
             (vault, log_id, identity, relay_share, silence_threshold, owner_contact, enrolled_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            vault,
            &log_id[..],
            identity_json,
            relay_share.map(|k| k.expose().to_vec()),
            silence_threshold as i64,
            owner_contact,
            now as i64
        ],
    )?;

    Ok(log_id)
}

pub fn identity_of(conn: &Connection, vault: &str) -> Result<VaultPublicIdentity> {
    let json: String = conn
        .query_row(
            "SELECT identity FROM vaults WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| RelayError::UnknownVault(vault.to_string()))?;
    serde_json::from_str(&json).map_err(|e| RelayError::Corrupt(e.to_string()))
}

pub fn silence_threshold(conn: &Connection, vault: &str) -> Result<u64> {
    let secs: i64 = conn
        .query_row(
            "SELECT silence_threshold FROM vaults WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?
        .ok_or_else(|| RelayError::UnknownVault(vault.to_string()))?;
    Ok(secs as u64)
}

pub fn last_checkin(conn: &Connection, vault: &str) -> Result<Option<(u64, u64)>> {
    let last: Option<(u64, u64)> = conn
        .query_row(
            "SELECT counter, asserted_at FROM checkins WHERE vault = ?1
             ORDER BY counter DESC LIMIT 1",
            params![vault],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
        .optional()?;
    let hold = hold_until(conn, vault)?.unwrap_or(0);
    let tap = last_tap(conn, vault)?.unwrap_or(0);
    Ok(last.map(|(counter, at)| {
        let tap = tap.min(at.saturating_add(MAX_TAP_EXTENSION));
        (counter, at.max(hold).max(tap))
    }))
}

pub const MAX_TAP_EXTENSION: u64 = 90 * 86_400;

pub const TAP_LIFETIME: u64 = 30 * 86_400;

pub fn new_tap(conn: &Connection, vault: &str, now: u64) -> Result<String> {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let token = zdd_core::codec::to_hex(&bytes);
    conn.execute(
        "INSERT INTO taps (token, vault, issued) VALUES (?1, ?2, ?3)",
        params![token, vault, now as i64],
    )?;
    Ok(token)
}

pub fn use_tap(conn: &Connection, token: &str, now: u64) -> Result<Option<String>> {
    let row: Option<(String, i64, Option<i64>)> = conn
        .query_row(
            "SELECT vault, issued, used_at FROM taps WHERE token = ?1",
            params![token],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((vault, issued, used)) = row else {
        return Ok(None);
    };
    if used.is_some() || now.saturating_sub(issued as u64) > TAP_LIFETIME {
        return Ok(None);
    }
    conn.execute(
        "UPDATE taps SET used_at = ?1 WHERE token = ?2",
        params![now as i64, token],
    )?;
    Ok(Some(vault))
}

pub fn last_tap(conn: &Connection, vault: &str) -> Result<Option<u64>> {
    Ok(conn
        .query_row(
            "SELECT MAX(used_at) FROM taps WHERE vault = ?1",
            params![vault],
            |r| r.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten()
        .map(|v| v as u64))
}

pub fn hold_until(conn: &Connection, vault: &str) -> Result<Option<u64>> {
    Ok(conn
        .query_row(
            "SELECT until FROM holds WHERE vault = ?1",
            params![vault],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .map(|v| v as u64))
}

pub fn set_hold(conn: &Connection, vault: &str, until: u64, issued_at: u64) -> Result<()> {
    let newest: Option<i64> = conn
        .query_row(
            "SELECT issued_at FROM holds WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?;
    if newest.is_some_and(|n| issued_at as i64 <= n) {
        return Err(RelayError::Corrupt(
            "that hold is older than one already recorded".into(),
        ));
    }
    conn.execute(
        "INSERT INTO holds (vault, until, issued_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(vault) DO UPDATE SET until = excluded.until, issued_at = excluded.issued_at",
        params![vault, until as i64, issued_at as i64],
    )?;
    Ok(())
}

pub fn last_record(
    conn: &Connection,
    vault: &str,
) -> Result<Option<zdd_core::checkin::SignedCheckIn>> {
    let json: Option<String> = conn
        .query_row(
            "SELECT record FROM checkins WHERE vault = ?1 ORDER BY counter DESC LIMIT 1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?;

    match json {
        Some(text) => Ok(Some(
            serde_json::from_str(&text).map_err(|e| RelayError::Corrupt(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

pub fn relay_share(conn: &Connection, vault: &str) -> Result<Option<Key32>> {
    let bytes: Option<Vec<u8>> = conn
        .query_row(
            "SELECT relay_share FROM vaults WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?
        .flatten();

    match bytes {
        Some(b) => {
            Ok(Some(Key32::from_slice(&b).map_err(|_| {
                RelayError::Corrupt("bad relay share".into())
            })?))
        }
        None => Ok(None),
    }
}

pub fn deposit_share(
    conn: &Connection,
    vault: &str,
    gate_id: &str,
    share: &[u8; 32],
    now: u64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO gate_shares (vault, gate_id, share, deposited) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault, gate_id) DO UPDATE SET share = excluded.share, deposited = excluded.deposited",
        params![vault, gate_id, &share[..], now as i64],
    )?;
    Ok(())
}

pub fn gate_shares(conn: &Connection, vault: &str) -> Result<Vec<(String, Key32)>> {
    let mut stmt =
        conn.prepare("SELECT gate_id, share FROM gate_shares WHERE vault = ?1 ORDER BY gate_id")?;
    let rows = stmt.query_map(params![vault], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (gate, bytes) = row?;
        let key = Key32::from_slice(&bytes)
            .map_err(|_| RelayError::Corrupt("bad deposited share".into()))?;
        out.push((gate, key));
    }
    Ok(out)
}

pub fn add_trustee(
    conn: &Connection,
    vault: &str,
    index: u8,
    token: &str,
    contact: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO trustees (vault, idx, token, contact) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(vault, idx) DO UPDATE SET token = excluded.token, contact = excluded.contact",
        params![vault, index as i64, token, contact],
    )?;
    Ok(())
}

pub fn replace_trustees(
    conn: &Connection,
    vault: &str,
    issued_at: u64,
    list: &[zdd_core::checkin::TrusteeEntry],
) -> Result<()> {
    let newest: Option<i64> = conn
        .query_row(
            "SELECT issued_at FROM trustee_lists WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?;
    if newest.is_some_and(|n| issued_at as i64 <= n) {
        return Err(RelayError::Corrupt(
            "that trustee list is older than one already recorded".into(),
        ));
    }
    let tx = conn.unchecked_transaction()?;
    let keep: Vec<String> = list.iter().map(|t| t.token.clone()).collect();
    {
        let mut stmt = tx.prepare("SELECT token FROM trustees WHERE vault = ?1")?;
        let existing: Vec<String> = stmt
            .query_map(params![vault], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        for token in existing.iter().filter(|t| !keep.contains(t)) {
            tx.execute("DELETE FROM trustees WHERE token = ?1", params![token])?;
        }
    }

    tx.execute(
        "UPDATE trustees SET idx = -1 - idx WHERE vault = ?1",
        params![vault],
    )?;
    for t in list {
        tx.execute(
            "INSERT INTO trustees (vault, idx, token, contact) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(token) DO UPDATE SET idx = excluded.idx, contact = excluded.contact",
            params![vault, t.index as i64, t.token, t.contact],
        )?;
    }
    tx.execute(
        "INSERT INTO trustee_lists (vault, issued_at) VALUES (?1, ?2)
         ON CONFLICT(vault) DO UPDATE SET issued_at = excluded.issued_at",
        params![vault, issued_at as i64],
    )?;
    tx.commit()?;
    Ok(())
}

pub fn apply_settings(
    conn: &Connection,
    vault: &str,
    threshold: u64,
    delay: u64,
    contact: Option<&str>,
    issued_at: u64,
) -> Result<()> {
    let newest: Option<i64> = conn
        .query_row(
            "SELECT issued_at FROM vault_settings WHERE vault = ?1",
            params![vault],
            |r| r.get(0),
        )
        .optional()?;
    if newest.is_some_and(|n| issued_at as i64 <= n) {
        return Err(RelayError::Corrupt(
            "those settings are older than ones already recorded".into(),
        ));
    }
    conn.execute(
        "UPDATE vaults SET silence_threshold = ?1, owner_contact = ?2 WHERE vault = ?3",
        params![threshold as i64, contact, vault],
    )?;
    conn.execute(
        "INSERT INTO vault_settings (vault, release_delay, issued_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(vault) DO UPDATE SET release_delay = excluded.release_delay,
                                          issued_at = excluded.issued_at",
        params![vault, delay as i64, issued_at as i64],
    )?;
    Ok(())
}

pub fn release_delay(conn: &Connection, vault: &str) -> Result<u64> {
    Ok(conn
        .query_row(
            "SELECT release_delay FROM vault_settings WHERE vault = ?1",
            params![vault],
            |r| r.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0) as u64)
}

pub fn record_verdict(conn: &Connection, token: &str, verdict: &str, now: u64) -> Result<String> {
    let vault: Option<String> = conn
        .query_row(
            "SELECT vault FROM trustees WHERE token = ?1",
            params![token],
            |r| r.get(0),
        )
        .optional()?;

    let vault = vault.ok_or_else(|| RelayError::UnknownVault("trustee".into()))?;
    conn.execute(
        "UPDATE trustees SET verdict = ?1, answered = ?2 WHERE token = ?3",
        params![verdict, now as i64, token],
    )?;
    Ok(vault)
}

pub fn confirmations(conn: &Connection, vault: &str) -> Result<u32> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM trustees WHERE vault = ?1 AND verdict = 'gone'",
        params![vault],
        |r| r.get::<_, i64>(0),
    )? as u32)
}

pub fn effective_threshold(conn: &Connection, vault: &str) -> Result<u64> {
    let ladder = zdd_core::policy::LadderConfig::default();
    let vetoes = vetoes(conn, vault)?.min(ladder.max_vetoes as u32) as u64;
    Ok(silence_threshold(conn, vault)?.saturating_add(vetoes * ladder.veto_extension))
}

pub fn vetoes(conn: &Connection, vault: &str) -> Result<u32> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM trustees WHERE vault = ?1 AND verdict = 'present'",
        params![vault],
        |r| r.get::<_, i64>(0),
    )? as u32)
}
