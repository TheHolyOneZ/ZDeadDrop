use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use zdd_core::clock::{
    Clock, ClockIntegrity, ClockWitness, SystemClock, Timestamp, SECONDS_PER_DAY,
};
use zdd_core::policy::{LadderConfig, VigilState};
use zdd_core::secret::Key32;
use zdd_core::shamir::Share;
use zdd_store::{LockedVault, OpenVault};

use crate::UiError;

pub fn default_vault_path() -> PathBuf {
    zdd_store::default_vault_path().unwrap_or_else(|| PathBuf::from("zdeaddrop-vault"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Prefs {
    pub checkin_interval_days: u32,
    pub grace_days: u32,
    pub auto_lock_minutes: u32,
    pub relay_url: Option<String>,
    pub relay_key: Option<String>,
    pub owner_contact: Option<String>,
    pub relay_enrolled_at: Option<u64>,
    pub relay_last_receipt_at: Option<u64>,
    pub relay_last_error: Option<String>,

    pub relay_counter: u64,
    pub recovery_sheet_at: Option<u64>,
    pub last_rehearsal_at: Option<u64>,
    pub clock_witness: Option<ClockWitness>,

    pub trustee_tokens: std::collections::BTreeMap<String, String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            checkin_interval_days: 30,
            grace_days: 7,
            auto_lock_minutes: 10,
            relay_url: None,
            relay_key: None,
            owner_contact: None,
            relay_enrolled_at: None,
            relay_last_receipt_at: None,
            relay_last_error: None,
            relay_counter: 0,
            recovery_sheet_at: None,
            last_rehearsal_at: None,
            clock_witness: None,
            trustee_tokens: Default::default(),
        }
    }
}

impl Prefs {
    pub fn ladder(&self) -> LadderConfig {
        ladder_for(self, self.checkin_interval_days + self.grace_days + 8, 3)
    }
}

pub fn ladder_for(prefs: &Prefs, silence_days: u32, countdown_days: u32) -> LadderConfig {
    let interval = prefs.checkin_interval_days.max(1) as u64 * SECONDS_PER_DAY;
    let grace = prefs.grace_days as u64 * SECONDS_PER_DAY;
    let floor = prefs.checkin_interval_days + prefs.grace_days + 1;
    let silence = silence_days.max(floor) as u64 * SECONDS_PER_DAY;
    let window = silence - interval - grace;

    LadderConfig {
        checkin_interval: interval,
        grace,
        reminder_offsets: vec![0, window / 4, window / 2, window * 3 / 4],
        silence_threshold: silence,
        countdown: countdown_days.max(1) as u64 * SECONDS_PER_DAY,
        ..LadderConfig::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleRecord {
    pub name: String,
    pub note: Option<String>,
    pub silence_days: u32,
    pub countdown_days: u32,

    pub release_key: String,
    pub trustees: Vec<String>,

    #[serde(default)]
    pub trustee_contacts: Vec<Option<String>>,
    pub quorum: u8,
    pub recipients: Vec<RecipientRecord>,
    pub size_bytes: u64,
    pub entry_count: usize,
    pub shares_distributed: bool,
    pub exported_at: Option<u64>,
    pub released_at: Option<u64>,
    pub created_at: u64,

    #[serde(default)]
    pub export_stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientRecord {
    pub id: u8,
    pub label: String,
}

pub struct Pending {
    pub capsule_name: String,
    pub seal: String,
    pub relay_share: Option<Key32>,
    pub trustee_shares: Vec<Share>,
    pub trustees: Vec<String>,

    pub handed_out: Vec<String>,

    pub duress_key: Key32,

    pub vault_id: String,
    pub identity: zdd_core::identity::VaultPublicIdentity,
    pub relay_url: Option<String>,

    pub trustee_tokens: std::collections::BTreeMap<String, String>,

    pub gate_id: zdd_core::release::GateId,
}

pub struct Open {
    pub vault: OpenVault,
    pub prefs: Prefs,
    pub clock: ClockIntegrity,
}

impl Open {
    pub fn save_prefs(&mut self) -> Result<(), UiError> {
        if let Some(w) = self.clock.witness() {
            self.prefs.clock_witness = Some(w);
        }
        let bytes = serde_json::to_vec(&self.prefs).map_err(|_| UiError::Opaque)?;
        self.vault.put_setting("prefs", &bytes).map_err(store_err)
    }

    pub fn vigil(&self, now: Timestamp) -> Result<VigilState, UiError> {
        Ok(self
            .vault
            .load_vigil()
            .map_err(store_err)?
            .unwrap_or_else(|| VigilState::starting_at(now)))
    }

    pub fn record(&self, id: &str) -> Result<Option<CapsuleRecord>, UiError> {
        match self
            .vault
            .get_setting(&format!("capsule:{id}"))
            .map_err(store_err)?
        {
            Some(bytes) => Ok(Some(
                serde_json::from_slice(bytes.expose()).map_err(|_| UiError::Opaque)?,
            )),
            None => Ok(None),
        }
    }

    pub fn put_record(&mut self, id: &str, record: &CapsuleRecord) -> Result<(), UiError> {
        let bytes = serde_json::to_vec(record).map_err(|_| UiError::Opaque)?;
        self.vault
            .put_setting(&format!("capsule:{id}"), &bytes)
            .map_err(store_err)
    }

    pub fn now(&mut self) -> (Timestamp, Option<String>) {
        match self.clock.observe(&SystemClock) {
            Ok(now) => (now, None),
            Err(e) => (SystemClock.now(), Some(e.to_string())),
        }
    }
}

pub struct AppState {
    pub path: PathBuf,
    pub inner: Mutex<Option<Open>>,
    pub pending: Mutex<HashMap<String, Pending>>,

    pub last_activity: Mutex<u64>,

    pub pending_sheet: Mutex<Option<crate::sheet::Sheet>>,
}

impl AppState {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(SystemClock.now().0),
            pending_sheet: Mutex::new(None),
        }
    }

    pub fn exists(&self) -> bool {
        self.path.join("header.json").exists()
    }

    pub fn open(&self) -> Result<std::sync::MutexGuard<'_, Option<Open>>, UiError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            return Err(UiError::Locked);
        }
        Ok(guard)
    }

    pub fn touch(&self) {
        *self.last_activity.lock().unwrap_or_else(|e| e.into_inner()) = SystemClock.now().0;
    }

    pub fn attach(&self, vault: OpenVault) -> Result<(), UiError> {
        if vault.verify_chain().is_err() {
            return Err(UiError::Refused(
                "This vault's history has been edited by something other than ZDeadDrop. \
                 It will not be opened until you understand why — see RECOVERY.md."
                    .into(),
            ));
        }

        let prefs: Prefs = match vault.get_setting("prefs").map_err(store_err)? {
            Some(bytes) => serde_json::from_slice(bytes.expose()).unwrap_or_default(),
            None => Prefs::default(),
        };
        let clock = match prefs.clock_witness {
            Some(w) => ClockIntegrity::resuming_from(w),
            None => ClockIntegrity::new(),
        };

        let mut open = Open {
            vault,
            prefs,
            clock,
        };

        let _ = open.now();
        open.save_prefs()?;

        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = Some(open);
        self.touch();
        Ok(())
    }

    pub fn lock(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(open) = guard.as_mut() {
            let _ = open.save_prefs();
        }
        *guard = None;
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self.pending_sheet.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn locked_vault(&self) -> Result<LockedVault, UiError> {
        LockedVault::open(&self.path).map_err(store_err)
    }
}

pub fn store_err(e: zdd_store::StoreError) -> UiError {
    if e.is_tampering() {
        return UiError::Refused(
            "Something in the vault directory has been altered outside ZDeadDrop. \
             Nothing was changed; see RECOVERY.md before continuing."
                .into(),
        );
    }
    match e {
        zdd_store::StoreError::Core(c) => c.into(),
        other => {
            tracing::warn!("store error: {other}");
            UiError::Opaque
        }
    }
}

pub fn safe_file_name(name: &str) -> String {
    zdd_core::paths::component(name).unwrap_or_else(|| "capsule".into())
}

pub fn fresh_path(dir: &Path, name: &str, ext: &str) -> PathBuf {
    let dotted = if ext.is_empty() {
        String::new()
    } else {
        format!(".{ext}")
    };
    let first = dir.join(format!("{name}{dotted}"));
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| dir.join(format!("{name} ({n}){dotted}")))
        .find(|p| !p.exists())
        .expect("an unbounded range always finds a free name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_capsule_ladder_validates() {
        let prefs = Prefs::default();
        for silence in [1, 38, 39, 45, 60, 365] {
            for countdown in [0, 1, 3, 30] {
                ladder_for(&prefs, silence, countdown)
                    .validate()
                    .unwrap_or_else(|e| panic!("{silence}/{countdown}: {e}"));
            }
        }
    }

    #[test]
    fn short_intervals_validate_too() {
        let prefs = Prefs {
            checkin_interval_days: 1,
            grace_days: 0,
            ..Prefs::default()
        };
        ladder_for(&prefs, 2, 1).validate().unwrap();
        prefs.ladder().validate().unwrap();
    }

    #[test]
    fn file_names_are_cleaned() {
        assert_eq!(safe_file_name("a/b:c"), "a-b-c");
        assert_eq!(safe_file_name("..."), "capsule");
    }

    #[test]
    fn fresh_paths_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let a = fresh_path(dir.path(), "x", "json");
        std::fs::write(&a, b"1").unwrap();
        let b = fresh_path(dir.path(), "x", "json");
        assert_ne!(a, b);
        assert!(b.ends_with("x (2).json"));
    }
}
