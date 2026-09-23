use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use zdd_core::aead::{self, Sealed};
use zdd_core::capsule::Capsule;
use zdd_core::clock::Timestamp;
use zdd_core::identity::VaultIdentity;
use zdd_core::kdf::{self, label, Argon2Params};
use zdd_core::policy::VigilState;
use zdd_core::secret::{Key32, SecretBytes};
use zdd_core::vault::{CredentialKind, RecoveryPolicy, VaultHeader};

use crate::blobs::BlobStore;
use crate::chain::{self, Event, EventKind};
use crate::{Result, StoreError};

const SCHEMA_VERSION: u32 = 1;

const HEADER_FILE: &str = "header.json";
const DB_FILE: &str = "vault.db";
const BLOB_DIR: &str = "blobs";

#[derive(Debug)]
pub struct LockedVault {
    path: PathBuf,
    header: VaultHeader,
}

impl LockedVault {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let header_path = path.join(HEADER_FILE);
        if !header_path.exists() {
            return Err(StoreError::NotFound(path));
        }

        let text = std::fs::read_to_string(&header_path)?;
        let header: VaultHeader = serde_json::from_str(&text).map_err(|e| StoreError::Corrupt {
            path: header_path,
            detail: e.to_string(),
        })?;
        header.validate()?;

        Ok(Self { path, header })
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn short_id(&self) -> String {
        self.header.short_id()
    }

    pub fn unlock(self, kind: CredentialKind, credential: &SecretBytes) -> Result<OpenVault> {
        let opened = zdd_core::vault::unlock(&self.header, kind, credential)?;
        OpenVault::attach(
            self.path,
            self.header,
            opened.root,
            opened.role,
            opened.slot,
        )
    }
}

pub struct OpenVault {
    path: PathBuf,
    header: VaultHeader,
    conn: Connection,
    blobs: BlobStore,
    root: Key32,
    role: zdd_core::vault::SlotRole,
    slot: u8,
}

impl std::fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVault")
            .field("path", &self.path)
            .field("role", &self.role)
            .field("root", &"redacted")
            .finish()
    }
}

impl OpenVault {
    pub fn create(
        path: impl Into<PathBuf>,
        passphrase: &SecretBytes,
        argon: Argon2Params,
        recovery_policy: RecoveryPolicy,
        now: Timestamp,
    ) -> Result<Self> {
        let path = path.into();
        if path.join(HEADER_FILE).exists() {
            return Err(StoreError::AlreadyExists(path));
        }
        std::fs::create_dir_all(&path)?;

        let (header, root, slot) = VaultHeader::create(passphrase, argon, recovery_policy)?;
        write_header(&path, &header)?;

        let mut vault = Self::attach(path, header, root, zdd_core::vault::SlotRole::Primary, slot)?;
        vault.append_event(EventKind::VaultCreated, b"", now)?;
        Ok(vault)
    }

    fn attach(
        path: PathBuf,
        header: VaultHeader,
        root: Key32,
        role: zdd_core::vault::SlotRole,
        slot: u8,
    ) -> Result<Self> {
        let conn = Connection::open(path.join(DB_FILE))?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        migrate(&conn)?;

        let blobs = BlobStore::open(path.join(BLOB_DIR))?;
        blobs.sweep()?;

        Ok(Self {
            path,
            header,
            conn,
            blobs,
            root,
            role,
            slot,
        })
    }

    pub fn identity(&self) -> VaultIdentity {
        VaultIdentity::derive(&self.root)
    }

    pub fn duress_channel_key(&self) -> Key32 {
        zdd_core::checkin::duress_channel_key(&self.root)
    }

    pub fn issue_checkin(
        &self,
        counter: u64,
        at: Timestamp,
        under_duress: bool,
    ) -> Result<zdd_core::checkin::SignedCheckIn> {
        Ok(zdd_core::checkin::issue(
            &self.identity(),
            &self.root,
            counter,
            at,
            under_duress,
        )?)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    pub fn role(&self) -> zdd_core::vault::SlotRole {
        self.role
    }

    pub fn occupied_slots(&self) -> Result<Vec<u8>> {
        match self.get_meta("occupied_slots")? {
            Some(bytes) => Ok(bytes.expose().to_vec()),

            None => Ok(vec![self.slot]),
        }
    }

    fn set_occupied_slots(&self, slots: &[u8]) -> Result<()> {
        self.put_meta("occupied_slots", slots)
    }

    pub fn add_unlock_path(
        &mut self,
        role: zdd_core::vault::SlotRole,
        credential: &SecretBytes,
        now: Timestamp,
    ) -> Result<u8> {
        let mut occupied = self.occupied_slots()?;
        let root = self.root.duplicate();
        let slot = self.header.add_slot(role, &root, credential, &occupied)?;
        occupied.push(slot);
        self.set_occupied_slots(&occupied)?;
        write_header(&self.path, &self.header)?;
        self.append_event(EventKind::UnlockPathAdded, &[role as u8], now)?;
        Ok(slot)
    }

    pub fn put_capsule(&mut self, capsule: &Capsule, now: Timestamp) -> Result<()> {
        capsule.validate()?;
        let id = capsule.id.short();
        let encoded =
            serde_json::to_vec(capsule).map_err(|e| StoreError::Encoding(e.to_string()))?;
        let sealed = self.seal_row("capsules", &id, &encoded)?;

        let existed: bool = self
            .conn
            .query_row("SELECT 1 FROM capsules WHERE id = ?1", params![id], |_| {
                Ok(true)
            })
            .optional()?
            .unwrap_or(false);

        self.conn.execute(
            "INSERT INTO capsules (id, sealed, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET sealed = excluded.sealed",
            params![id, sealed.as_bytes(), capsule.created_at.0 as i64],
        )?;

        let kind = if existed {
            EventKind::CapsuleUpdated
        } else {
            EventKind::CapsuleCreated
        };
        self.append_event(kind, id.as_bytes(), now)?;
        Ok(())
    }

    pub fn get_capsule(&self, id: &str) -> Result<Option<Capsule>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM capsules WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;

        let Some(bytes) = sealed else { return Ok(None) };
        let plain = self.open_row("capsules", id, bytes)?;
        let capsule: Capsule = serde_json::from_slice(plain.expose())
            .map_err(|e| StoreError::Encoding(e.to_string()))?;
        Ok(Some(capsule))
    }

    pub fn list_capsules(&self) -> Result<Vec<Capsule>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, sealed FROM capsules ORDER BY created_at ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, bytes) = row?;
            let plain = self.open_row("capsules", &id, bytes)?;
            out.push(
                serde_json::from_slice(plain.expose())
                    .map_err(|e| StoreError::Encoding(e.to_string()))?,
            );
        }
        Ok(out)
    }

    pub fn delete_capsule(&mut self, id: &str, now: Timestamp) -> Result<bool> {
        let removed = self
            .conn
            .execute("DELETE FROM capsules WHERE id = ?1", params![id])?
            > 0;
        if removed {
            self.append_event(EventKind::CapsuleDeleted, id.as_bytes(), now)?;
        }
        Ok(removed)
    }

    pub fn save_vigil(&mut self, vigil: &VigilState, now: Timestamp) -> Result<()> {
        let encoded = serde_json::to_vec(vigil).map_err(|e| StoreError::Encoding(e.to_string()))?;
        let sealed = self.seal_row("vigil", "1", &encoded)?;
        self.conn.execute(
            "INSERT INTO vigil (id, sealed) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET sealed = excluded.sealed",
            params![sealed.as_bytes()],
        )?;
        self.append_event(
            EventKind::CheckIn,
            &vigil.checkin_counter.to_be_bytes(),
            now,
        )?;
        Ok(())
    }

    pub fn load_vigil(&self) -> Result<Option<VigilState>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT sealed FROM vigil WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        let Some(bytes) = sealed else { return Ok(None) };
        let plain = self.open_row("vigil", "1", bytes)?;
        Ok(Some(
            serde_json::from_slice(plain.expose())
                .map_err(|e| StoreError::Encoding(e.to_string()))?,
        ))
    }

    fn put_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        let sealed = self.seal_row("meta", key, value)?;
        self.conn.execute(
            "INSERT INTO meta (key, sealed) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET sealed = excluded.sealed",
            params![key, sealed.as_bytes()],
        )?;
        Ok(())
    }

    fn get_meta(&self, key: &str) -> Result<Option<SecretBytes>> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT sealed FROM meta WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()?;
        let Some(bytes) = sealed else { return Ok(None) };
        Ok(Some(self.open_row("meta", key, bytes)?))
    }

    pub fn put_setting(&mut self, key: &str, value: &[u8]) -> Result<()> {
        self.put_meta(&format!("app:{key}"), value)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<SecretBytes>> {
        self.get_meta(&format!("app:{key}"))
    }

    pub fn delete_setting(&mut self, key: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM meta WHERE key = ?1",
            params![format!("app:{key}")],
        )?;
        Ok(())
    }

    pub fn append_event(&mut self, kind: EventKind, payload: &[u8], now: Timestamp) -> Result<i64> {
        let (prev_seq, prev_hash) = self.chain_head()?;
        let seq = prev_seq + 1;

        let sealed = self.seal_row("events", &seq.to_string(), payload)?;
        let hash = chain::link_hash(&prev_hash, seq, now.0, kind, sealed.as_bytes());

        self.conn.execute(
            "INSERT INTO events (seq, at, kind, sealed, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                seq,
                now.0 as i64,
                kind.as_str(),
                sealed.as_bytes(),
                &prev_hash[..],
                &hash[..]
            ],
        )?;

        let mac = chain::head_mac(&self.root, seq, &hash);
        self.conn.execute(
            "INSERT INTO chain_head (id, seq, hash, mac) VALUES (1, ?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash, mac = excluded.mac",
            params![seq, &hash[..], &mac[..]],
        )?;

        Ok(seq)
    }

    fn chain_head(&self) -> Result<(i64, [u8; 32])> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row("SELECT seq, hash FROM chain_head WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;

        match row {
            Some((seq, hash)) => {
                let hash: [u8; 32] = hash
                    .try_into()
                    .map_err(|_| StoreError::ChainBroken { seq })?;
                Ok((seq, hash))
            }
            None => Ok((0, chain::genesis())),
        }
    }

    pub fn events(&self) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, at, kind, sealed, prev_hash, hash FROM events ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (seq, at, kind, payload, prev, hash) = row?;
            out.push(Event {
                seq,
                at: at as u64,
                kind: EventKind::parse(&kind).ok_or(StoreError::ChainBroken { seq })?,
                payload,
                prev_hash: prev
                    .try_into()
                    .map_err(|_| StoreError::ChainBroken { seq })?,
                hash: hash
                    .try_into()
                    .map_err(|_| StoreError::ChainBroken { seq })?,
            });
        }
        Ok(out)
    }

    pub fn verify_chain(&self) -> Result<()> {
        let events = self.events()?;
        let computed = chain::verify(&events)?;

        let (seq, stored) = self.chain_head()?;
        if seq as usize != events.len() {
            return Err(StoreError::ChainBroken {
                seq: events.len() as i64 + 1,
            });
        }
        if stored != computed {
            return Err(StoreError::ChainBroken { seq });
        }

        let expected_mac = chain::head_mac(&self.root, seq, &computed);
        let stored_mac: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT mac FROM chain_head WHERE id = 1", [], |r| r.get(0))
            .optional()?;

        match stored_mac {
            Some(mac) if mac == expected_mac => Ok(()),

            None if events.is_empty() => Ok(()),
            _ => Err(StoreError::ChainBroken { seq }),
        }
    }

    fn table_key(&self, table: &str) -> Key32 {
        kdf::derive_subkey_ctx(&self.root, label::STORE_METADATA, table.as_bytes())
    }

    fn row_aad(table: &str, row_id: &str) -> Vec<u8> {
        aead::aad(&[
            b"zdd/v1/store-row",
            table.as_bytes(),
            row_id.as_bytes(),
            &SCHEMA_VERSION.to_be_bytes(),
        ])
    }

    fn seal_row(&self, table: &str, row_id: &str, plaintext: &[u8]) -> Result<Sealed> {
        Ok(aead::seal(
            &self.table_key(table),
            plaintext,
            &Self::row_aad(table, row_id),
        )?)
    }

    fn open_row(&self, table: &str, row_id: &str, bytes: Vec<u8>) -> Result<SecretBytes> {
        let sealed = Sealed::from_bytes(bytes)?;
        Ok(aead::unseal(
            &self.table_key(table),
            &sealed,
            &Self::row_aad(table, row_id),
        )?)
    }
}

fn write_header(path: &Path, header: &VaultHeader) -> Result<()> {
    let json =
        serde_json::to_string_pretty(header).map_err(|e| StoreError::Encoding(e.to_string()))?;

    let temp = path.join(".header.json.new");
    std::fs::write(&temp, json)?;
    std::fs::rename(temp, path.join(HEADER_FILE))?;
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS meta (
            key    TEXT PRIMARY KEY,
            sealed BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS capsules (
            id         TEXT PRIMARY KEY,
            sealed     BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vigil (
            id     INTEGER PRIMARY KEY CHECK (id = 1),
            sealed BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            seq       INTEGER PRIMARY KEY,
            at        INTEGER NOT NULL,
            kind      TEXT NOT NULL,
            sealed    BLOB NOT NULL,
            prev_hash BLOB NOT NULL,
            hash      BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS chain_head (
            id   INTEGER PRIMARY KEY CHECK (id = 1),
            seq  INTEGER NOT NULL,
            hash BLOB NOT NULL,
            mac  BLOB NOT NULL
        );

        CREATE INDEX IF NOT EXISTS events_at ON events (at);
        "#,
    )?;
    Ok(())
}
