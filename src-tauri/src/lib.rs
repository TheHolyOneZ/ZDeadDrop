mod relay;
mod sealing;
mod session;
mod sheet;
mod views;

use std::path::PathBuf;
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

use zdd_core::capsule::{Capsule, Manifest, PayloadRef};
use zdd_core::clock::{Clock, SystemClock, SECONDS_PER_DAY};
use zdd_core::kdf::Argon2Params;
use zdd_core::policy::{self, VigilState};
use zdd_core::release::GatePolicy;
use zdd_core::secret::{Key32, SecretBytes};
use zdd_core::vault::{CredentialKind, RecoveryPolicy, SlotRole};
use zdd_store::{LockedVault, OpenVault};

use session::{store_err, AppState, CapsuleRecord, Pending, RecipientRecord};
use views::*;

#[derive(Debug, thiserror::Error)]
pub enum UiError {
    #[error("{0}")]
    Refused(String),
    #[error("that did not unlock the vault")]
    Rejected,
    #[error("the vault is locked")]
    Locked,
    #[error("something went wrong")]
    Opaque,
}

impl serde::Serialize for UiError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl From<zdd_core::Error> for UiError {
    fn from(e: zdd_core::Error) -> Self {
        use zdd_core::Error;
        match e {
            Error::ReleaseRefused(r) => UiError::Refused(r.to_string()),
            Error::Clock(c) => UiError::Refused(c.to_string()),
            Error::Format { detail, .. } => UiError::Refused(detail),
            Error::Sharing(s) => UiError::Refused(s.to_string()),

            Error::Authentication | Error::UnlockRejected | Error::Signature => UiError::Rejected,
            _ => UiError::Opaque,
        }
    }
}

type UiResult<T> = Result<T, UiError>;

fn refuse<T>(msg: impl Into<String>) -> UiResult<T> {
    Err(UiError::Refused(msg.into()))
}

fn io_err(e: std::io::Error) -> UiError {
    tracing::warn!("io: {e}");
    UiError::Refused(format!("The file system refused: {e}"))
}

#[tauri::command]
fn seal_svg(seed: String, state: String, size: u32, simplified: bool) -> UiResult<String> {
    use zdd_seal::{render, SealOptions, SealState};

    let seal_state = match state.as_str() {
        "sealed" => SealState::Sealed,
        "stirring" => SealState::Stirring,
        "breaking" => SealState::Breaking,
        "broken" => SealState::Broken,
        "held" => SealState::Held,
        "frozen" => SealState::Frozen,
        _ => return Err(UiError::Opaque),
    };

    let bytes = zdd_core::codec::from_hex(&seed).ok_or(UiError::Opaque)?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| UiError::Opaque)?;

    let size = size.clamp(8, 2048);

    Ok(render(
        &seed,
        &SealOptions {
            size,
            state: seal_state,
            simplified,
            ..Default::default()
        },
    ))
}

#[tauri::command]
fn status(app: State<'_, AppState>) -> Status {
    let unlocked = app.inner.lock().map(|g| g.is_some()).unwrap_or(false);
    let header = LockedVault::open(&app.path).ok();
    Status {
        exists: app.exists(),
        unlocked,
        short_id: header.as_ref().map(|h| h.short_id()),
        seal_seed: header
            .as_ref()
            .map(|h| h.header().public_identity.vigil_fingerprint().hex()),
        path: app.path.display().to_string(),
        recovery_policy: header.map(|h| match h.header().recovery_policy {
            RecoveryPolicy::Standard => "standard",
            RecoveryPolicy::Unrecoverable => "unrecoverable",
        }),
    }
}

#[tauri::command]
async fn create_vault(
    app: State<'_, AppState>,
    passphrase: String,
    strength: String,
    unrecoverable: bool,
) -> UiResult<()> {
    if app.exists() {
        return refuse("A vault already exists here. Unlock it instead.");
    }
    if passphrase.chars().count() < 10 {
        return refuse("That passphrase is too short to protect anything. Use at least ten characters — four or five unrelated words is better.");
    }
    let argon = match strength.as_str() {
        "interactive" => Argon2Params::INTERACTIVE,
        "paranoid" => Argon2Params::PARANOID,
        _ => Argon2Params::MODERATE,
    };
    let policy = if unrecoverable {
        RecoveryPolicy::Unrecoverable
    } else {
        RecoveryPolicy::Standard
    };
    let path = app.path.clone();
    let pass = SecretBytes::from_string(passphrase);

    let vault = tauri::async_runtime::spawn_blocking(move || {
        let now = SystemClock.now();
        let mut vault = OpenVault::create(&path, &pass, argon, policy, now)?;
        vault.save_vigil(&VigilState::starting_at(now), now)?;
        Ok::<_, zdd_store::StoreError>(vault)
    })
    .await
    .map_err(|_| UiError::Opaque)?
    .map_err(store_err)?;

    app.attach(vault)
}

async fn unlock_with(
    app: &AppState,
    kind: CredentialKind,
    credential: SecretBytes,
) -> UiResult<()> {
    let locked = app.locked_vault()?;
    let vault = tauri::async_runtime::spawn_blocking(move || locked.unlock(kind, &credential))
        .await
        .map_err(|_| UiError::Opaque)?
        .map_err(|e| match e {
            zdd_store::StoreError::Core(_) => UiError::Rejected,
            other => store_err(other),
        })?;
    app.attach(vault)
}

#[tauri::command]
async fn unlock(app: State<'_, AppState>, passphrase: String) -> UiResult<()> {
    unlock_with(
        &app,
        CredentialKind::Passphrase,
        SecretBytes::from_string(passphrase),
    )
    .await
}

#[tauri::command]
async fn unlock_with_sheet(app: State<'_, AppState>, words: String) -> UiResult<()> {
    let credential = sheet::read(&words).map_err(UiError::Refused)?;
    unlock_with(&app, CredentialKind::RecoverySheet, credential).await
}

#[tauri::command]
fn lock(app: State<'_, AppState>) {
    app.lock();
}

#[tauri::command]
fn touch(app: State<'_, AppState>) {
    app.touch();
}

#[tauri::command]
fn load_vault(app: State<'_, AppState>) -> UiResult<VaultView> {
    let guard = app.open()?;
    let open = guard.as_ref().ok_or(UiError::Locked)?;
    let header = open.vault.header();
    let fp = header.public_identity.vigil_fingerprint();

    let mut unlock_paths = vec!["passphrase".to_string()];
    if open.prefs.recovery_sheet_at.is_some() {
        unlock_paths.push("recovery sheet".into());
    }

    let mut trustees = std::collections::BTreeSet::new();
    for c in open.vault.list_capsules().map_err(store_err)? {
        if let Some(r) = open.record(&c.id.short())? {
            trustees.extend(r.trustees);
        }
    }

    Ok(VaultView {
        short_id: header.short_id(),
        vigil_fingerprint: fp.short(),
        vigil_seed: fp.hex(),
        recovery_policy: match header.recovery_policy {
            RecoveryPolicy::Standard => "standard",
            RecoveryPolicy::Unrecoverable => "unrecoverable",
        },
        unlock_paths,
        relay_url: open.prefs.relay_url.clone(),
        owner_contact: open.prefs.owner_contact.clone(),
        trustee_count: trustees.len(),
        checkin_interval_days: open.prefs.checkin_interval_days,
        grace_days: open.prefs.grace_days,
        auto_lock_minutes: open.prefs.auto_lock_minutes,
        recovery_sheet_at: open.prefs.recovery_sheet_at,
        last_rehearsal_at: open.prefs.last_rehearsal_at,
        path: open.vault.path().display().to_string(),
    })
}

#[tauri::command]
fn save_prefs(
    app: State<'_, AppState>,
    checkin_interval_days: u32,
    grace_days: u32,
    auto_lock_minutes: u32,
) -> UiResult<()> {
    if !(1..=365).contains(&checkin_interval_days) {
        return refuse("Check in somewhere between every day and once a year.");
    }
    if grace_days > 60 {
        return refuse("A grace period longer than two months is a second threshold in disguise.");
    }
    let mut guard = app.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;

    let floor = checkin_interval_days + grace_days;
    for c in open.vault.list_capsules().map_err(store_err)? {
        if let Some(r) = open.record(&c.id.short())? {
            if r.silence_days <= floor && r.released_at.is_none() {
                return refuse(format!(
                    "“{}” waits {} days of silence, which would fall inside a {floor}-day \
                     check-in window. Lengthen that capsule's wait first.",
                    r.name, r.silence_days
                ));
            }
        }
    }

    open.prefs.checkin_interval_days = checkin_interval_days;
    open.prefs.grace_days = grace_days;
    open.prefs.auto_lock_minutes = auto_lock_minutes.clamp(1, 240);
    open.save_prefs()
}

#[tauri::command]
fn begin_recovery_sheet(app: State<'_, AppState>) -> UiResult<Vec<String>> {
    let guard = app.open()?;
    let open = guard.as_ref().ok_or(UiError::Locked)?;
    if open.vault.header().recovery_policy == RecoveryPolicy::Unrecoverable {
        return refuse("This vault was created without recovery, and that cannot be changed.");
    }
    if open.prefs.recovery_sheet_at.is_some() {
        return refuse("This vault already has a recovery sheet.");
    }
    let generated = sheet::generate();
    let words = generated.words.clone();
    drop(guard);
    *app.pending_sheet.lock().unwrap_or_else(|e| e.into_inner()) = Some(generated);
    Ok(words)
}

#[tauri::command]
async fn confirm_recovery_sheet(
    app: State<'_, AppState>,
    checks: Vec<(usize, String)>,
) -> UiResult<()> {
    let credential = {
        let pending = app.pending_sheet.lock().unwrap_or_else(|e| e.into_inner());
        let Some(sheet) = pending.as_ref() else {
            return refuse("Start the recovery sheet again.");
        };
        for (i, typed) in &checks {
            let expected = sheet.words.get(*i).map(String::as_str).unwrap_or("");
            if typed.trim().to_lowercase() != expected {
                return refuse(format!(
                    "Word {} does not match. Check what you wrote down.",
                    i + 1
                ));
            }
        }
        if checks.len() < 3 {
            return refuse("Confirm at least three words.");
        }
        SecretBytes::from_slice(sheet.credential.expose())
    };

    let mut guard = app.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let now = SystemClock.now();
    open.vault
        .add_unlock_path(SlotRole::RecoverySheet, &credential, now)
        .map_err(store_err)?;
    open.prefs.recovery_sheet_at = Some(now.0);
    open.save_prefs()?;
    drop(guard);
    *app.pending_sheet.lock().unwrap_or_else(|e| e.into_inner()) = None;
    Ok(())
}

#[tauri::command]
fn cancel_recovery_sheet(app: State<'_, AppState>) {
    *app.pending_sheet.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

fn vigil_view(open: &mut session::Open) -> UiResult<VigilView> {
    let (now, frozen) = open.now();
    let vigil = open.vigil(now)?;
    let config = open.prefs.ladder();
    let stage = policy::evaluate(&config, &vigil, 0, now, frozen.is_some());
    let silence = now.since(vigil.last_checkin);

    Ok(VigilView {
        stage: stage_name(&stage),
        summary: stage.summary(),
        silence_secs: silence,
        due_in_secs: config.checkin_interval as i64 - silence as i64,
        interval_secs: config.checkin_interval,
        counter: vigil.checkin_counter,
        frozen_reason: frozen,
        hold_until: vigil.hold_until.filter(|u| *u > now).map(|t| t.0),
        max_hold_days: config.max_hold / SECONDS_PER_DAY,
        relay: open.prefs.relay_url.as_ref().map(|url| RelayView {
            url: url.clone(),
            last_receipt_at: open.prefs.relay_last_receipt_at,
            last_error: open.prefs.relay_last_error.clone(),
        }),
    })
}

#[tauri::command]
fn load_vigil(app: State<'_, AppState>) -> UiResult<VigilView> {
    let mut guard = app.open()?;
    vigil_view(guard.as_mut().ok_or(UiError::Locked)?)
}

#[tauri::command]
async fn check_in(app: State<'_, AppState>, under_duress: bool) -> UiResult<VigilView> {
    app.touch();
    let ended_hold: bool;
    let relay_job = {
        let mut guard = app.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let (now, frozen) = open.now();
        if let Some(reason) = frozen {
            return refuse(format!(
                "The clock on this machine cannot be trusted ({reason}). Check-ins are paused \
                 until you acknowledge it."
            ));
        }
        let mut vigil = open.vigil(now)?;
        vigil.check_in(now, under_duress);

        ended_hold = vigil.hold_until.take().is_some_and(|u| u > now);
        open.vault.save_vigil(&vigil, now).map_err(store_err)?;
        open.save_prefs()?;

        match (&open.prefs.relay_url, &open.prefs.relay_key) {
            (Some(url), Some(key)) => {
                let counter = open.prefs.relay_counter + 1;
                let record = open
                    .vault
                    .issue_checkin(counter, now, under_duress)
                    .map_err(store_err)?;
                let vault_id = open
                    .vault
                    .header()
                    .public_identity
                    .vigil_fingerprint()
                    .short();
                Some((url.clone(), key.clone(), vault_id, record, counter))
            }
            _ => None,
        }
    };

    if let Some((url, key, vault_id, record, counter)) = relay_job {
        let outcome = relay::check_in(&url, &vault_id, &record, &key).await;
        let mut guard = app.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        match outcome {
            Ok(()) => {
                open.prefs.relay_counter = counter;
                open.prefs.relay_last_receipt_at = Some(SystemClock.now().0);
                open.prefs.relay_last_error = None;
            }
            Err(e) => open.prefs.relay_last_error = Some(e),
        }
        open.save_prefs()?;
    }
    if ended_hold {
        sync_hold(&app, SystemClock.now()).await?;
    }

    let mut guard = app.open()?;
    vigil_view(guard.as_mut().ok_or(UiError::Locked)?)
}

async fn sync_hold(state: &AppState, until: zdd_core::clock::Timestamp) -> UiResult<()> {
    let job = {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        match &open.prefs.relay_url {
            Some(url) => {
                let now = SystemClock.now();
                let notice = zdd_core::checkin::SignedHold::issue(
                    &open.vault.identity(),
                    until.max(now),
                    now,
                );
                let vault = open
                    .vault
                    .header()
                    .public_identity
                    .vigil_fingerprint()
                    .short();
                Some((url.clone(), vault, notice))
            }
            None => None,
        }
    };
    let Some((url, vault, notice)) = job else {
        return Ok(());
    };
    let outcome = relay::hold(&url, &vault, &notice).await;
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    match outcome {
        Ok(()) => open.prefs.relay_last_error = None,
        Err(e) => open.prefs.relay_last_error = Some(e),
    }
    open.save_prefs()
}

#[tauri::command]
async fn set_hold(app: State<'_, AppState>, days: u32) -> UiResult<VigilView> {
    let until = {
        let mut guard = app.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let (now, _) = open.now();
        let max = open.prefs.ladder().max_hold / SECONDS_PER_DAY;
        if days == 0 || days as u64 > max {
            return refuse(format!("A hold can last between 1 and {max} days."));
        }
        let mut vigil = open.vigil(now)?;

        vigil.check_in(now, false);
        let until = now.plus_days(days as u64);
        vigil.hold_until = Some(until);
        open.vault.save_vigil(&vigil, now).map_err(store_err)?;
        until
    };
    sync_hold(&app, until).await?;
    let mut guard = app.open()?;
    vigil_view(guard.as_mut().ok_or(UiError::Locked)?)
}

#[tauri::command]
async fn clear_hold(app: State<'_, AppState>) -> UiResult<VigilView> {
    {
        let mut guard = app.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let (now, _) = open.now();
        let mut vigil = open.vigil(now)?;
        vigil.hold_until = None;
        open.vault.save_vigil(&vigil, now).map_err(store_err)?;
    }
    sync_hold(&app, SystemClock.now()).await?;
    let mut guard = app.open()?;
    vigil_view(guard.as_mut().ok_or(UiError::Locked)?)
}

#[tauri::command]
fn acknowledge_clock(app: State<'_, AppState>) -> UiResult<VigilView> {
    let mut guard = app.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    open.clock.acknowledge(&SystemClock);
    open.save_prefs()?;
    vigil_view(open)
}

fn capsule_view(
    open: &session::Open,
    capsule: &Capsule,
    record: Option<&CapsuleRecord>,
    vigil: &VigilState,
    now: zdd_core::clock::Timestamp,
    frozen: bool,
    pending: bool,
) -> CapsuleView {
    let (need, of) = quorum_of(capsule);
    let (silence, countdown) = record
        .map(|r| (r.silence_days, r.countdown_days))
        .unwrap_or((45, 3));
    let config = session::ladder_for(&open.prefs, silence, countdown);
    let stage = match record.and_then(|r| r.released_at) {
        Some(at) => policy::Stage::Released {
            at: zdd_core::clock::Timestamp(at),
        },
        None => policy::evaluate(&config, vigil, need, now, frozen),
    };
    let seal = capsule.seal();

    CapsuleView {
        id: capsule.id.short(),
        seal_seed: seal.hex(),
        fingerprint: seal.short(),
        figure: zdd_seal::describe(seal.seal_seed()),
        name: record
            .map(|r| r.name.clone())
            .unwrap_or_else(|| "Unnamed capsule".into()),
        state: seal_state_for(&stage),
        stage: stage_name(&stage),
        condition: describe_condition(&config, need),
        recipient_count: capsule.recipients.len(),
        quorum: (need > 0).then(|| Quorum {
            have: vigil.confirmations(),
            need,
            of,
        }),
        size_bytes: record.map(|r| r.size_bytes).unwrap_or(0),
        entry_count: record.map(|r| r.entry_count).unwrap_or(0),
        is_rehearsal: capsule.is_rehearsal,
        created_at: capsule.created_at.0,
        released_at: record.and_then(|r| r.released_at),
        shares_pending: pending,
        shares_distributed: record.map(|r| r.shares_distributed).unwrap_or(false),
        exported_at: record.and_then(|r| r.exported_at),
        silence_days: silence,
        countdown_days: countdown,
    }
}

#[tauri::command]
fn load_capsules(app: State<'_, AppState>) -> UiResult<Vec<CapsuleView>> {
    let pending: Vec<String> = app
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect();
    let mut guard = app.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let (now, frozen) = open.now();
    let vigil = open.vigil(now)?;
    let capsules = open.vault.list_capsules().map_err(store_err)?;
    capsules
        .iter()
        .map(|c| {
            let id = c.id.short();
            let record = open.record(&id)?;
            Ok(capsule_view(
                open,
                c,
                record.as_ref(),
                &vigil,
                now,
                frozen.is_some(),
                pending.contains(&id),
            ))
        })
        .collect()
}

#[tauri::command]
fn capsule_detail(app: State<'_, AppState>, id: String) -> UiResult<CapsuleDetail> {
    let pending = app
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&id);
    let mut guard = app.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let (now, frozen) = open.now();
    let vigil = open.vigil(now)?;
    let capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or_else(|| UiError::Refused("That capsule no longer exists.".into()))?;
    let record = open.record(&id)?;

    let cdk = capsule.open_as_owner(&open.vault.identity())?;
    let manifest = capsule.read_manifest(&cdk)?;

    let view = capsule_view(
        open,
        &capsule,
        record.as_ref(),
        &vigil,
        now,
        frozen.is_some(),
        pending,
    );

    Ok(CapsuleDetail {
        capsule: view,
        note: manifest.note.clone(),
        silence_days: record.as_ref().map(|r| r.silence_days).unwrap_or(45),
        countdown_days: record.as_ref().map(|r| r.countdown_days).unwrap_or(3),
        trustees: record
            .as_ref()
            .map(|r| r.trustees.clone())
            .unwrap_or_default(),
        trustee_contacts: record
            .as_ref()
            .map(|r| r.trustee_contacts.clone())
            .unwrap_or_default(),
        recipients: capsule
            .recipients
            .iter()
            .map(|r| {
                let fp = r.public_key.fingerprint();
                RecipientView {
                    id: r.id,
                    label: manifest
                        .recipient_labels
                        .get(&r.id)
                        .cloned()
                        .unwrap_or_else(|| format!("Recipient {}", r.id + 1)),
                    fingerprint: fp.short(),
                    seal_seed: fp.hex(),
                    figure: zdd_seal::describe(fp.seal_seed()),
                    tier: r.tier,
                    claim_window_days: r.claim_window / SECONDS_PER_DAY,
                    verified_at: r.key_verified_at.map(|t| t.0),
                    rotated_at: r.key_rotated_at.map(|t| t.0),
                }
            })
            .collect(),
        entries: manifest
            .entries
            .iter()
            .map(|e| EntryView {
                path: e.path.clone(),
                size: e.size,
                kind: entry_kind(e.kind),
            })
            .collect(),
        policy_weakness: capsule.gate.policy.weakness(),
    })
}

#[tauri::command]
async fn preview_item(item: sealing::ItemSpec) -> UiResult<sealing::ItemPreview> {
    tauri::async_runtime::spawn_blocking(move || sealing::expand(&item).map(|(_, p)| p))
        .await
        .map_err(|_| UiError::Opaque)?
        .map_err(UiError::Refused)
}

#[tauri::command]
fn inspect_key(text: String) -> UiResult<KeyView> {
    let key = sealing::parse_public_key(&text).map_err(UiError::Refused)?;
    let mut view = key_view(&key);

    view.was_private = serde_json::from_str::<serde_json::Value>(text.trim())
        .map(|v| v.get("secret").is_some())
        .unwrap_or(false);
    Ok(view)
}

fn key_view(key: &zdd_core::identity::RecipientPublicKey) -> KeyView {
    let fp = key.fingerprint();
    KeyView {
        fingerprint: fp.short(),
        seal_seed: fp.hex(),
        figure: zdd_seal::describe(fp.seal_seed()),
        public_key: serde_json::to_value(key)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        was_private: false,
    }
}

#[tauri::command]
async fn pick_paths(app: AppHandle, folders: bool) -> UiResult<Vec<String>> {
    let dialog = app.dialog().file();
    let picked = if folders {
        dialog
            .set_title("Choose folders to seal")
            .blocking_pick_folders()
    } else {
        dialog
            .set_title("Choose files to seal")
            .blocking_pick_files()
    };
    Ok(picked
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
        .collect())
}

#[tauri::command]
async fn pick_key_file(app: AppHandle) -> UiResult<Option<KeyView>> {
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Open their public key")
        .blocking_pick_file()
        .and_then(|p| p.into_path().ok())
    else {
        return Ok(None);
    };
    let meta = std::fs::metadata(&path).map_err(io_err)?;
    if meta.len() > 64 * 1024 {
        return refuse("That file is far too large to be a key.");
    }
    let text = std::fs::read_to_string(&path).map_err(io_err)?;
    inspect_key(text).map(Some)
}

#[tauri::command]
async fn generate_recipient_key(app: AppHandle, label: String) -> UiResult<Option<KeyView>> {
    let Some(dir) = app
        .dialog()
        .file()
        .set_title("Where should their key file go? (a USB stick is ideal)")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
    else {
        return Ok(None);
    };
    let identity = zdd_core::identity::RecipientIdentity::generate();
    let secret = identity.export_secret();
    let doc = serde_json::json!({
        "kind": "zdd-recipient-key",
        "version": 1,
        "for": label,
        "public": identity.public(),
        "secret": zdd_core::codec::to_hex(secret.expose()),
        "note": "This is a PRIVATE key. Whoever holds this file can open anything sealed to it. \
                 Keep it somewhere safe and private; you will need it, with the ZDeadDrop tool, \
                 to open what was left to you.",
    });
    let name = session::safe_file_name(&format!("{label} — ZDeadDrop private key"));
    let path = session::fresh_path(&dir, &name, "json");
    write_private(
        &path,
        serde_json::to_string_pretty(&doc)
            .map_err(|_| UiError::Opaque)?
            .as_bytes(),
    )?;
    Ok(Some(key_view(&identity.public())))
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> UiResult<()> {
    std::fs::write(path, bytes).map_err(io_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[derive(Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    phase: &'static str,
    done: u64,
    total: u64,
}

#[tauri::command]
async fn seal_capsule(
    app: AppHandle,
    state: State<'_, AppState>,
    spec: sealing::CapsuleSpec,
) -> UiResult<SealedView> {
    state.touch();
    let name = spec.name.trim().to_string();
    if name.is_empty() {
        return refuse("Give the capsule a name.");
    }
    if spec.items.is_empty() {
        return refuse("A capsule needs something in it.");
    }
    if spec.recipients.is_empty() {
        return refuse("A capsule needs someone to receive it.");
    }
    let trustees: Vec<String> = spec
        .trustees
        .iter()
        .map(|t| t.name.trim().to_string())
        .collect();
    let trustee_contacts = spec
        .trustees
        .iter()
        .map(|t| sealing::normalise_contact(t.contact.as_deref().unwrap_or("")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(UiError::Refused)?;
    if trustees.iter().any(String::is_empty) {
        return refuse("Every trustee needs a name.");
    }
    let policy = match trustees.len() {
        0 => GatePolicy::RelayOnly,
        1 => return refuse("One trustee cannot form a quorum. Add a second, or use none."),
        n => {
            if spec.quorum < 2 || spec.quorum as usize > n {
                return refuse(format!("The quorum must be between 2 and {n}."));
            }
            GatePolicy::RelayAndQuorum {
                threshold: spec.quorum,
                total: n as u8,
            }
        }
    };

    let (identity, blobs, prefs) = {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        (
            open.vault.identity(),
            open.vault.blobs().clone(),
            open.prefs.clone(),
        )
    };
    let floor = prefs.checkin_interval_days + prefs.grace_days;
    if spec.silence_days <= floor {
        return refuse(format!(
            "The wait must be longer than your {}-day check-in window plus {} days of grace, \
             or trustees would be asked before you had even missed a check-in.",
            prefs.checkin_interval_days, prefs.grace_days
        ));
    }
    if spec.countdown_days == 0 {
        return refuse("The final countdown is your last chance to cancel; it cannot be zero.");
    }

    let (silence_days, countdown_days) = (spec.silence_days, spec.countdown_days);
    let emitter = app.clone();
    let job = tauri::async_runtime::spawn_blocking(move || -> UiResult<_> {
        let now = SystemClock.now();

        let mut sources = Vec::new();
        let mut skipped = Vec::new();
        for item in &spec.items {
            let (s, p) = sealing::expand(item).map_err(UiError::Refused)?;
            skipped.extend(p.skipped);
            sources.extend(s);
        }
        sealing::dedupe(&mut sources);
        let total: u64 = sources.iter().map(|s| s.size).sum();

        let recipients =
            sealing::recipient_slots(&spec.recipients, now).map_err(UiError::Refused)?;
        let labels = spec
            .recipients
            .iter()
            .enumerate()
            .map(|(i, r)| (i as u8, r.label.trim().to_string()))
            .collect();

        let mut manifest = Manifest {
            name: name.clone(),
            note: spec.note.clone().filter(|n| !n.trim().is_empty()),
            entries: sealing::entries(&sources, &vec![[0u8; 32]; sources.len()]),
            recipient_labels: labels,
            total_bytes: total,
        };

        let mut draft = Capsule::create(&identity, recipients, policy, &manifest, now)?;

        let staging = blobs.staging_path();
        let mut sink = std::fs::File::create(&staging).map_err(io_err)?;
        let mut payload = sealing::Payload::new(&sources);
        let mut last = 0u64;
        let sealed = zdd_core::stream::seal_reader(
            &Capsule::payload_key(&draft.cdk),
            &draft.capsule.id.0,
            &mut payload,
            &mut sink,
            |done| {
                if total == 0 || done * 100 / total != last * 100 / total || done == total {
                    last = done;

                    emitter.state::<AppState>().touch();
                    let _ = emitter.emit(
                        "seal-progress",
                        Progress {
                            phase: "sealing",
                            done,
                            total,
                        },
                    );
                }
            },
        );
        let (prefix, written) = match sealed {
            Ok(v) => v,
            Err(e) => {
                drop(sink);
                let _ = std::fs::remove_file(&staging);

                return Err(match e {
                    zdd_core::Error::Io(msg) => UiError::Refused(msg),
                    other => other.into(),
                });
            }
        };
        sink.sync_all().map_err(io_err)?;
        drop(sink);

        manifest.entries = sealing::entries(&sources, &payload.hashes);
        draft.capsule.write_manifest(&draft.cdk, &manifest)?;

        let (blob, ciphertext_len) = blobs.adopt(&staging).map_err(store_err)?;
        draft.capsule.attach_payload(PayloadRef {
            prefix,
            plaintext_len: written,
            ciphertext_len,
            blob_id: blob.0,
        });
        draft.capsule.validate()?;
        Ok((draft, manifest, skipped, now, total))
    });

    let (mut draft, manifest, skipped, now, total) = job.await.map_err(|_| UiError::Opaque)??;

    let id = draft.capsule.id.short();
    let record = CapsuleRecord {
        name: manifest.name.clone(),
        note: manifest.note.clone(),
        silence_days,
        countdown_days,
        release_key: zdd_core::codec::to_hex(draft.gate_material.release_key.expose()),
        trustees: trustees.clone(),
        trustee_contacts,
        quorum: match policy {
            GatePolicy::RelayAndQuorum { threshold, .. }
            | GatePolicy::QuorumOnly { threshold, .. } => threshold,
            GatePolicy::RelayOnly => 0,
        },
        recipients: manifest
            .recipient_labels
            .iter()
            .map(|(id, label)| RecipientRecord {
                id: *id,
                label: label.clone(),
            })
            .collect(),
        size_bytes: total,
        entry_count: manifest.entries.len(),
        shares_distributed: false,
        exported_at: None,
        released_at: None,
        created_at: now.0,
        export_stale: false,
    };

    let trustee_kit = {
        let mut guard = state.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        open.vault
            .put_capsule(&draft.capsule, now)
            .map_err(store_err)?;
        open.put_record(&id, &record)?;

        trustee_roster(open)?;
        trustee_kit(open)
    };

    state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            id.clone(),
            Pending {
                capsule_name: manifest.name.clone(),
                seal: draft.capsule.seal().short(),

                relay_share: draft.gate_material.relay_share.take(),
                trustee_shares: std::mem::take(&mut draft.gate_material.trustee_shares),
                trustees,
                handed_out: Vec::new(),
                duress_key: trustee_kit.0,
                vault_id: trustee_kit.1,
                identity: trustee_kit.2,
                relay_url: trustee_kit.3,
                trustee_tokens: trustee_kit.4,
                gate_id: draft.capsule.gate.gate_id,
            },
        );

    let _ = sync_relay(&state).await;

    Ok(SealedView {
        id,
        name: manifest.name,
        skipped,
    })
}

fn trustee_roster(open: &mut session::Open) -> UiResult<Vec<zdd_core::checkin::TrusteeEntry>> {
    let mut names: Vec<(String, Option<String>)> = Vec::new();
    for c in open.vault.list_capsules().map_err(store_err)? {
        let Some(r) = open.record(&c.id.short())? else {
            continue;
        };
        if r.released_at.is_some() {
            continue;
        }
        for (i, name) in r.trustees.iter().enumerate() {
            let contact = r.trustee_contacts.get(i).cloned().flatten();
            match names.iter_mut().find(|(n, _)| n == name) {
                Some((_, c)) if c.is_none() => *c = contact,
                Some(_) => {}
                None => names.push((name.clone(), contact)),
            }
        }
    }
    let mut changed = false;
    let entries = names
        .into_iter()
        .enumerate()
        .map(|(i, (name, contact))| {
            let token = open
                .prefs
                .trustee_tokens
                .entry(name)
                .or_insert_with(|| {
                    changed = true;
                    zdd_core::codec::to_hex(Key32::random().expose())
                })
                .clone();
            zdd_core::checkin::TrusteeEntry {
                index: i.min(255) as u8,
                token,
                contact,
            }
        })
        .collect();
    if changed {
        open.save_prefs()?;
    }
    Ok(entries)
}

async fn sync_relay(state: &AppState) -> UiResult<()> {
    let job = {
        let mut guard = state.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let roster = trustee_roster(open)?;
        match open.prefs.relay_url.clone() {
            Some(url) => {
                let (mut silence, mut countdown) = (u32::MAX, 0u32);
                for c in open.vault.list_capsules().map_err(store_err)? {
                    if let Some(r) = open.record(&c.id.short())? {
                        if r.released_at.is_none() {
                            silence = silence.min(r.silence_days);
                            countdown = countdown.max(r.countdown_days);
                        }
                    }
                }
                if silence == u32::MAX {
                    silence = open.prefs.checkin_interval_days + open.prefs.grace_days + 8;
                    countdown = 3;
                }
                let identity = open.vault.identity();
                let now = SystemClock.now();
                let settings = zdd_core::checkin::SignedSettings::issue(
                    &identity,
                    silence as u64 * SECONDS_PER_DAY,
                    countdown as u64 * SECONDS_PER_DAY,
                    open.prefs.owner_contact.clone(),
                    now,
                );
                let trustees = zdd_core::checkin::SignedTrustees::issue(&identity, now, roster);
                let vault = open
                    .vault
                    .header()
                    .public_identity
                    .vigil_fingerprint()
                    .short();
                Some((url, vault, settings, trustees))
            }
            None => None,
        }
    };
    let Some((url, vault, settings, signed)) = job else {
        return Ok(());
    };
    let outcome = match relay::settings(&url, &vault, &settings).await {
        Ok(()) => relay::trustees(&url, &vault, &signed).await,
        Err(e) => Err(e),
    };
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    if let Err(e) = outcome {
        open.prefs.relay_last_error = Some(e);
        open.save_prefs()?;
    }
    Ok(())
}

#[tauri::command]
fn pending_shares(app: State<'_, AppState>, id: String) -> UiResult<Option<ShareView>> {
    let relay_connected = app
        .inner
        .lock()
        .map(|g| g.as_ref().is_some_and(|o| o.prefs.relay_url.is_some()))
        .unwrap_or(false);
    let pending = app.pending.lock().unwrap_or_else(|e| e.into_inner());
    Ok(pending.get(&id).map(|p| ShareView {
        capsule: p.capsule_name.clone(),
        seal: p.seal.clone(),
        relay_connected,
        relay: p.relay_share.as_ref().map(|_| ShareSlot {
            which: "relay".into(),
            holder: "Your relay".into(),
            handed_out: p.handed_out.iter().any(|h| h == "relay"),
        }),
        trustees: p
            .trustees
            .iter()
            .enumerate()
            .map(|(i, name)| ShareSlot {
                which: i.to_string(),
                holder: name.clone(),
                handed_out: p.handed_out.contains(&i.to_string()),
            })
            .collect(),
    }))
}

fn trustee_kit(
    open: &session::Open,
) -> (
    Key32,
    String,
    zdd_core::identity::VaultPublicIdentity,
    Option<String>,
    std::collections::BTreeMap<String, String>,
) {
    let identity = open.vault.header().public_identity.clone();
    (
        open.vault.duress_channel_key(),
        identity.vigil_fingerprint().short(),
        identity,
        open.prefs.relay_url.clone(),
        open.prefs.trustee_tokens.clone(),
    )
}

fn share_document(p: &Pending, which: &str) -> UiResult<(String, String)> {
    if which == "relay" {
        let share = p.relay_share.as_ref().ok_or(UiError::Opaque)?;
        let doc = serde_json::json!({
            "kind": "zdd-relay-share",
            "capsule": p.capsule_name,
            "seal": p.seal,
            "share": zdd_core::codec::to_hex(share.expose()),
            "instructions": "Give this to the relay that watches this vault. On its own it \
                             opens nothing.",
        });
        return Ok((
            format!("{} — relay share", p.capsule_name),
            serde_json::to_string_pretty(&doc).map_err(|_| UiError::Opaque)?,
        ));
    }
    let index: usize = which.parse().map_err(|_| UiError::Opaque)?;
    let share = p.trustee_shares.get(index).ok_or(UiError::Opaque)?;
    let holder = p.trustees.get(index).cloned().unwrap_or_default();
    let question = match (&p.relay_url, p.trustee_tokens.get(&holder)) {
        (Some(url), Some(token)) => Some(format!("{url}/v1/trustee/{token}")),
        _ => None,
    };
    let share_json: serde_json::Value =
        serde_json::from_str(&share.to_json()?).map_err(|_| UiError::Opaque)?;
    let doc = serde_json::json!({
        "kind": "zdd-trustee-share",
        "version": 1,
        "for": holder,
        "capsule": p.capsule_name,
        "seal": p.seal,
        "share": share_json,
        "vault": p.vault_id,
        "identity": p.identity,
        "relay": p.relay_url,
        "question": question,
        "duress_key": zdd_core::codec::to_hex(p.duress_key.expose()),
        "instructions": format!(
            "{holder}, you have been trusted with one piece of a key. On its own it opens \
             nothing, and nobody can use it without enough of the other trustees agreeing. \
             Keep it somewhere safe. If you are ever asked whether the person who gave you \
             this is gone, answer honestly — and only then send this piece on to the person \
             they named. To check whether their latest check-in was made under duress, run: \
             zdd trustee-check THIS-FILE"
        ),
    });
    Ok((
        format!("{} — share for {holder}", p.capsule_name),
        serde_json::to_string_pretty(&doc).map_err(|_| UiError::Opaque)?,
    ))
}

#[tauri::command]
async fn save_share(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    which: String,
) -> UiResult<bool> {
    let (name, body) = {
        let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = pending
            .get(&id)
            .ok_or_else(|| UiError::Refused("These shares have already been forgotten.".into()))?;
        share_document(p, &which)?
    };
    let Some(dir) = app
        .dialog()
        .file()
        .set_title("Where should this share go? (their USB stick, not this computer)")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
    else {
        return Ok(false);
    };
    let path = session::fresh_path(&dir, &session::safe_file_name(&name), "json");
    write_private(&path, body.as_bytes())?;
    mark_handed_out(&state, &id, &which);
    Ok(true)
}

#[tauri::command]
fn copy_share(state: State<'_, AppState>, id: String, which: String) -> UiResult<()> {
    let body = {
        let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = pending
            .get(&id)
            .ok_or_else(|| UiError::Refused("These shares have already been forgotten.".into()))?;
        share_document(p, &which)?.1
    };
    copy_and_clear(body)?;
    mark_handed_out(&state, &id, &which);
    Ok(())
}

#[tauri::command]
async fn send_relay_share(state: State<'_, AppState>, id: String) -> UiResult<()> {
    let (deposit, base, vault) = {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        let base = open
            .prefs
            .relay_url
            .clone()
            .ok_or_else(|| UiError::Refused("Connect a relay first, in Settings.".into()))?;
        let pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = pending
            .get(&id)
            .ok_or_else(|| UiError::Refused("These pieces have already been forgotten.".into()))?;
        let share = p
            .relay_share
            .as_ref()
            .ok_or_else(|| UiError::Refused("This capsule has no relay piece.".into()))?;
        let deposit =
            zdd_core::release::ShareDeposit::create(&open.vault.identity(), p.gate_id, share);
        let vault = open
            .vault
            .header()
            .public_identity
            .vigil_fingerprint()
            .short();
        (deposit, base, vault)
    };
    relay::deposit_share(&base, &vault, &deposit)
        .await
        .map_err(UiError::Refused)?;
    mark_handed_out(&state, &id, "relay");
    Ok(())
}

fn mark_handed_out(state: &AppState, id: &str, which: &str) {
    let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = pending.get_mut(id) {
        if !p.handed_out.iter().any(|h| h == which) {
            p.handed_out.push(which.to_string());
        }
    }
}

fn copy_and_clear(text: String) -> UiResult<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = text;
        let mut clipboard = match arboard::Clipboard::new() {
            Ok(c) => c,
            Err(_) => {
                let _ = tx.send(false);
                return;
            }
        };
        let ok = clipboard.set_text(text.clone()).is_ok();
        let _ = tx.send(ok);
        if ok {
            std::thread::sleep(Duration::from_secs(60));
            if clipboard.get_text().map(|t| t == text).unwrap_or(false) {
                let _ = clipboard.clear();
            }
        }
        zeroize::Zeroize::zeroize(&mut text);
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(true) => Ok(()),
        _ => refuse("The clipboard is not available."),
    }
}

const LINKS: &[(&str, &str)] = &[
    ("home", "https://zsync.eu/zdeaddrop/"),
    ("source", "https://github.com/TheHolyOneZ/ZDeadDrop"),
    ("author", "https://github.com/TheHolyOneZ/"),
    ("projects", "https://zsync.eu"),
    ("mods", "https://zlogic.eu"),
];

#[tauri::command]
fn open_link(app: AppHandle, which: String) -> UiResult<()> {
    use tauri_plugin_opener::OpenerExt;
    let url = LINKS
        .iter()
        .find(|(k, _)| *k == which)
        .map(|(_, u)| *u)
        .ok_or(UiError::Opaque)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| UiError::Refused("Could not open a web browser.".into()))
}

#[tauri::command]
fn app_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[tauri::command]
fn reveal_vault(app: AppHandle, state: State<'_, AppState>) -> UiResult<()> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(state.path.display().to_string(), None::<&str>)
        .map_err(|_| UiError::Refused("Could not open a file manager.".into()))
}

#[tauri::command]
fn copy_text(text: String) -> UiResult<()> {
    if text.len() > 400 || text.chars().any(char::is_control) {
        return Err(UiError::Opaque);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let Ok(mut clipboard) = arboard::Clipboard::new() else {
            let _ = tx.send(false);
            return;
        };
        #[cfg(target_os = "linux")]
        {
            use arboard::SetExtLinux;

            let _ = tx.send(true);
            let _ = clipboard.set().wait().text(text);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = tx.send(clipboard.set_text(text).is_ok());
        }
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(true) => Ok(()),
        _ => refuse("The clipboard is not available."),
    }
}

#[tauri::command]
fn finish_shares(state: State<'_, AppState>, id: String) -> UiResult<()> {
    let all_out = {
        let mut pending = state.pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(p) = pending.remove(&id) else {
            return Ok(());
        };
        let needed = p.trustee_shares.len() + usize::from(p.relay_share.is_some());
        p.handed_out.len() >= needed
    };
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    if let Some(mut record) = open.record(&id)? {
        record.shares_distributed = all_out;
        open.put_record(&id, &record)?;
    }
    Ok(())
}

#[tauri::command]
fn reissue_shares(state: State<'_, AppState>, id: String) -> UiResult<()> {
    rotate_gate_now(&state, &id, None, |_| {})
}

fn rotate_gate_now(
    state: &AppState,
    id: &str,
    policy: Option<GatePolicy>,
    update: impl FnOnce(&mut CapsuleRecord),
) -> UiResult<()> {
    let id = id.to_string();
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let now = SystemClock.now();
    let mut capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or(UiError::Opaque)?;
    let mut record = open.record(&id)?.ok_or(UiError::Opaque)?;
    if record.released_at.is_some() {
        return refuse("This capsule has already been released.");
    }
    let cdk = capsule.open_as_owner(&open.vault.identity())?;
    let mut material = capsule.rotate_gate(&cdk, policy.unwrap_or(capsule.gate.policy))?;
    open.vault.put_capsule(&capsule, now).map_err(store_err)?;
    update(&mut record);
    record.release_key = zdd_core::codec::to_hex(material.release_key.expose());
    record.shares_distributed = false;

    if record.exported_at.take().is_some() {
        record.export_stale = true;
    }
    open.put_record(&id, &record)?;
    trustee_roster(open)?;
    let kit = trustee_kit(open);
    drop(guard);

    state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(
            id,
            Pending {
                capsule_name: record.name.clone(),
                seal: capsule.seal().short(),
                relay_share: material.relay_share.take(),
                trustee_shares: std::mem::take(&mut material.trustee_shares),
                trustees: record.trustees.clone(),
                handed_out: Vec::new(),
                duress_key: kit.0,
                vault_id: kit.1,
                identity: kit.2,
                relay_url: kit.3,
                trustee_tokens: kit.4,
                gate_id: capsule.gate.gate_id,
            },
        );
    Ok(())
}

#[tauri::command]
async fn update_terms(
    state: State<'_, AppState>,
    id: String,
    silence_days: u32,
    countdown_days: u32,
    trustees: Vec<sealing::TrusteeSpec>,
    quorum: u8,
) -> UiResult<bool> {
    let names: Vec<String> = trustees.iter().map(|t| t.name.trim().to_string()).collect();
    if names.iter().any(String::is_empty) {
        return refuse("Every trustee needs a name.");
    }
    let contacts = trustees
        .iter()
        .map(|t| sealing::normalise_contact(t.contact.as_deref().unwrap_or("")))
        .collect::<Result<Vec<_>, _>>()
        .map_err(UiError::Refused)?;
    let policy = match names.len() {
        0 => GatePolicy::RelayOnly,
        1 => return refuse("One trustee cannot form a quorum. Add a second, or use none."),
        n => {
            if quorum < 2 || quorum as usize > n {
                return refuse(format!("The quorum must be between 2 and {n}."));
            }
            GatePolicy::RelayAndQuorum {
                threshold: quorum,
                total: n as u8,
            }
        }
    };

    let gate_changes = {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        let floor = open.prefs.checkin_interval_days + open.prefs.grace_days;
        if silence_days <= floor {
            return refuse(format!(
                "The wait must be longer than your {floor}-day check-in window and grace."
            ));
        }
        if countdown_days == 0 {
            return refuse("The final countdown cannot be zero.");
        }
        let record = open.record(&id)?.ok_or(UiError::Opaque)?;
        let capsule = open
            .vault
            .get_capsule(&id)
            .map_err(store_err)?
            .ok_or(UiError::Opaque)?;
        record.trustees != names || capsule.gate.policy != policy
    };

    let set = |r: &mut CapsuleRecord| {
        r.silence_days = silence_days;
        r.countdown_days = countdown_days;
        r.trustees = names.clone();
        r.trustee_contacts = contacts.clone();
        r.quorum = match policy {
            GatePolicy::RelayAndQuorum { threshold, .. }
            | GatePolicy::QuorumOnly { threshold, .. } => threshold,
            GatePolicy::RelayOnly => 0,
        };
    };

    if gate_changes {
        rotate_gate_now(&state, &id, Some(policy), set)?;
    } else {
        let mut guard = state.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let mut record = open.record(&id)?.ok_or(UiError::Opaque)?;
        set(&mut record);
        open.put_record(&id, &record)?;
    }
    let _ = sync_relay(&state).await;
    Ok(gate_changes)
}

#[tauri::command]
fn verify_recipient(state: State<'_, AppState>, id: String, recipient: u8) -> UiResult<()> {
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let now = SystemClock.now();
    let mut capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or(UiError::Opaque)?;
    let slot = capsule
        .recipients
        .iter_mut()
        .find(|r| r.id == recipient)
        .ok_or(UiError::Opaque)?;
    slot.key_verified_at = Some(now);
    open.vault.put_capsule(&capsule, now).map_err(store_err)
}

#[tauri::command]
fn replace_recipient_key(
    state: State<'_, AppState>,
    id: String,
    recipient: u8,
    key: String,
) -> UiResult<()> {
    let new_key = sealing::parse_public_key(&key).map_err(UiError::Refused)?;
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let now = SystemClock.now();
    let mut capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or(UiError::Opaque)?;
    if capsule
        .recipients
        .iter()
        .any(|r| r.public_key == new_key && r.id != recipient)
    {
        return refuse("Someone else on this capsule already has that key.");
    }
    let record = open.record(&id)?.ok_or(UiError::Opaque)?;
    let release = zdd_core::codec::from_hex(&record.release_key)
        .and_then(|b| Key32::from_slice(&b).ok())
        .ok_or(UiError::Opaque)?;
    let cdk = capsule.open_as_owner(&open.vault.identity())?;
    capsule.rotate_recipient_key(&cdk, &release, recipient, new_key, now)?;
    open.vault.put_capsule(&capsule, now).map_err(store_err)?;
    let mut record = record;
    if record.exported_at.take().is_some() {
        record.export_stale = true;
    }
    open.put_record(&id, &record)
}

fn write_package(
    open: &session::Open,
    capsule: &Capsule,
    record: &CapsuleRecord,
    dir: &std::path::Path,
    release_key: Option<&str>,
) -> UiResult<PathBuf> {
    let base = session::safe_file_name(&record.name);
    let suffix = if release_key.is_some() {
        "released"
    } else {
        "sealed capsule"
    };
    let folder = session::fresh_path(dir, &format!("{base} ({suffix})"), "");
    std::fs::create_dir_all(&folder).map_err(io_err)?;

    let file = format!("{base}.zdd");
    std::fs::write(
        folder.join(&file),
        serde_json::to_string_pretty(capsule).map_err(|_| UiError::Opaque)?,
    )
    .map_err(io_err)?;

    if let Some(payload) = &capsule.payload {
        let blob = zdd_store::BlobId(payload.blob_id);
        let dest = folder.join(format!("{}.payload", blob.hex()));
        std::fs::copy(open.vault.blobs().path_of(blob), &dest).map_err(|_| {
            UiError::Refused(
                "This capsule's contents are missing from the vault. Run a verify before \
                 relying on it."
                    .into(),
            )
        })?;
    }

    let seal = capsule.seal();
    let svg = zdd_seal::render(
        seal.seal_seed(),
        &zdd_seal::SealOptions {
            size: 480,
            state: if release_key.is_some() {
                zdd_seal::SealState::Broken
            } else {
                zdd_seal::SealState::Sealed
            },
            ..Default::default()
        },
    );
    std::fs::write(folder.join("seal.svg"), svg).map_err(io_err)?;

    let who = record
        .recipients
        .iter()
        .map(|r| r.label.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let (_, trustees) = quorum_of(capsule);
    let claim = match release_key {
        Some(k) => format!("zdd claim --key YOUR-KEY-FILE --release-key {k} \"{file}\""),
        None => {
            let relay = match &open.prefs.relay_url {
                Some(url) => format!(
                    "{url}/v1/vault/{}",
                    open.vault
                        .header()
                        .public_identity
                        .vigil_fingerprint()
                        .short()
                ),
                None => "RELAY-SHARE-FILE".into(),
            };
            if trustees == 0 {
                format!("zdd claim --key YOUR-KEY-FILE --relay-share {relay} \"{file}\"")
            } else {
                format!(
                    "zdd claim --key YOUR-KEY-FILE --relay-share {relay} \\\n        \
                     --trustee-share TRUSTEE-FILE --trustee-share TRUSTEE-FILE \"{file}\"\n\n\
                     with one --trustee-share for each file the trustees send you."
                )
            }
        }
    };
    let opening = if release_key.is_some() {
        "It has been released to you deliberately, so you can open it straight away."
    } else if trustees == 0 {
        "It is sealed. It opens once the relay confirms the person who sealed it has \
         gone silent; until then the command below will say so and change nothing."
    } else {
        "It is sealed. It opens only once its release condition has been met and you \
         have been sent the pieces of its key by the relay and the trustees."
    };
    let readme = format!(
        "{name}\n{rule}\n\n\
         This folder holds something left for: {who}\n\n\
         {opening}\n\n\
         BEFORE ANYTHING ELSE — check the seal.\n\
         Open seal.svg. It should show: {figure}\n\
         Its code is {code}. If you were told a different picture or code, stop: this may not\n\
         be the capsule that was meant for you.\n\n\
         TO OPEN IT\n\
         You need the ZDeadDrop tool (the `zdd` command) and your private key file.\n\
         In this folder, run:\n\n    {claim}\n\n\
         The tool explains every step before it does anything, and never overwrites a file.\n\n\
         Nothing in this folder can be read without your key. It is safe to copy, email,\n\
         or keep on a USB stick.\n",
        name = record.name,
        rule = "=".repeat(record.name.chars().count().max(3)),
        figure = zdd_seal::describe(seal.seal_seed()),
        code = seal.short(),
    );
    std::fs::write(folder.join("READ ME FIRST.txt"), readme).map_err(io_err)?;
    Ok(folder)
}

#[tauri::command]
async fn export_capsule(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> UiResult<Option<String>> {
    let Some(dir) = app
        .dialog()
        .file()
        .set_title("Where should the capsule go?")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
    else {
        return Ok(None);
    };
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or(UiError::Opaque)?;
    let mut record = open.record(&id)?.ok_or(UiError::Opaque)?;
    let folder = write_package(open, &capsule, &record, &dir, None)?;
    record.exported_at = Some(SystemClock.now().0);
    record.export_stale = false;
    open.put_record(&id, &record)?;
    Ok(Some(folder.display().to_string()))
}

#[tauri::command]
async fn release_capsule(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    typed_name: String,
) -> UiResult<Option<String>> {
    {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        let record = open.record(&id)?.ok_or(UiError::Opaque)?;
        if typed_name.trim() != record.name.trim() {
            return refuse("The name you typed does not match. Nothing was released.");
        }
    }
    let Some(dir) = app
        .dialog()
        .file()
        .set_title("Where should the released capsule go?")
        .blocking_pick_folder()
        .and_then(|p| p.into_path().ok())
    else {
        return Ok(None);
    };
    let folder = {
        let mut guard = state.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        let now = SystemClock.now();
        let capsule = open
            .vault
            .get_capsule(&id)
            .map_err(store_err)?
            .ok_or(UiError::Opaque)?;
        let mut record = open.record(&id)?.ok_or(UiError::Opaque)?;
        let key = record.release_key.clone();
        let folder = write_package(open, &capsule, &record, &dir, Some(&key))?;
        record.released_at = Some(now.0);
        record.exported_at = Some(now.0);
        open.put_record(&id, &record)?;
        open.vault
            .append_event(zdd_store::EventKind::CapsuleUpdated, id.as_bytes(), now)
            .map_err(store_err)?;
        folder
    };
    let _ = sync_relay(&state).await;
    Ok(Some(folder.display().to_string()))
}

#[tauri::command]
async fn delete_capsule(
    state: State<'_, AppState>,
    id: String,
    typed_name: String,
) -> UiResult<()> {
    delete_capsule_now(&state, &id, &typed_name)?;

    let _ = sync_relay(&state).await;
    Ok(())
}

fn delete_capsule_now(state: &AppState, id: &str, typed_name: &str) -> UiResult<()> {
    let id = id.to_string();
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let now = SystemClock.now();
    let record = open.record(&id)?;
    let name = record.as_ref().map(|r| r.name.clone()).unwrap_or_default();
    if typed_name.trim() != name.trim() {
        return refuse("The name you typed does not match. Nothing was deleted.");
    }
    let capsule = open
        .vault
        .get_capsule(&id)
        .map_err(store_err)?
        .ok_or(UiError::Opaque)?;

    open.vault.delete_capsule(&id, now).map_err(store_err)?;
    open.vault
        .delete_setting(&format!("capsule:{id}"))
        .map_err(store_err)?;

    if let Some(p) = &capsule.payload {
        let shared = open
            .vault
            .list_capsules()
            .map_err(store_err)?
            .iter()
            .any(|c| c.payload.as_ref().map(|q| q.blob_id) == Some(p.blob_id));
        if !shared {
            let _ = open.vault.blobs().remove(zdd_store::BlobId(p.blob_id));
        }
    }
    drop(guard);
    state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);
    Ok(())
}

#[tauri::command]
fn load_findings(state: State<'_, AppState>) -> UiResult<Vec<Finding>> {
    let pending: Vec<String> = state
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .keys()
        .cloned()
        .collect();
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    let (now, frozen) = open.now();
    let mut out = Vec::new();

    if let Some(reason) = frozen {
        out.push(Finding {
            id: "clock".into(),
            severity: "critical",
            title: "The clock on this machine was moved".into(),
            detail: format!(
                "{reason}. The vigil is frozen and nothing will advance toward release until \
                 you acknowledge it. If you did not change the clock, someone else did."
            ),
            action: Some("Review".into()),
            target: Some("clock".into()),
        });
    }

    if open.vault.verify_chain().is_err() {
        out.push(Finding {
            id: "chain".into(),
            severity: "critical",
            title: "This vault's history has been edited".into(),
            detail: "Something other than ZDeadDrop changed the vault's event log. The most \
                     likely reason is someone undoing a change you made. See RECOVERY.md."
                .into(),
            action: None,
            target: None,
        });
    }

    let policy = open.vault.header().recovery_policy;
    if policy == RecoveryPolicy::Standard && open.prefs.recovery_sheet_at.is_none() {
        out.push(Finding {
            id: "recovery-sheet".into(),
            severity: "critical",
            title: "You have no recovery sheet".into(),
            detail: "If you forget your passphrase today, nothing can open this vault. The \
                     sheet is 24 words on one page, and it is the only thing standing between \
                     a forgotten passphrase and permanent loss."
                .into(),
            action: Some("Make one".into()),
            target: Some("sheet".into()),
        });
    }

    let capsules = open.vault.list_capsules().map_err(store_err)?;
    let live: Vec<_> = capsules
        .iter()
        .filter_map(|c| {
            let r = open.record(&c.id.short()).ok().flatten()?;
            r.released_at.is_none().then_some((c, r))
        })
        .collect();

    for (c, r) in &live {
        let id = c.id.short();
        if let Some(p) = &c.payload {
            if !open.vault.blobs().exists(zdd_store::BlobId(p.blob_id)) {
                out.push(Finding {
                    id: format!("missing-{id}"),
                    severity: "critical",
                    title: format!("“{}” has lost its contents", r.name),
                    detail: "The encrypted contents of this capsule are no longer in the vault \
                             folder. Unless a copy was exported, it can no longer be delivered."
                        .into(),
                    action: Some("Open".into()),
                    target: Some(format!("capsule:{id}")),
                });
            }
        }
        if !r.shares_distributed {
            let still_held = pending.contains(&id);
            out.push(Finding {
                id: format!("shares-{id}"),
                severity: "warning",
                title: if still_held {
                    format!("“{}” has shares waiting to be handed out", r.name)
                } else {
                    format!("Not every share of “{}” was handed out", r.name)
                },
                detail: if still_held {
                    "Until the trustees and the relay hold their pieces, nothing can release \
                     this capsule. The pieces are held only in memory and vanish when you lock."
                        .into()
                } else {
                    "Some pieces were forgotten before anyone received them, so the quorum may \
                     not be reachable. Issue a fresh set — every old piece stops working."
                        .into()
                },
                action: Some(
                    if still_held {
                        "Hand out"
                    } else {
                        "Issue new shares"
                    }
                    .into(),
                ),
                target: Some(format!("shares:{id}")),
            });
        }
        let unverified = c
            .recipients
            .iter()
            .filter(|s| s.key_verified_at.is_none())
            .count();
        if unverified > 0 {
            out.push(Finding {
                id: format!("unverified-{id}"),
                severity: "warning",
                title: format!(
                    "{unverified} {} on “{}” never been verified",
                    if unverified == 1 {
                        "recipient key has"
                    } else {
                        "recipient keys have"
                    },
                    r.name
                ),
                detail: "You have not confirmed, over a channel you trust, that these keys \
                         belong to the people you named. Compare the seal with them; if a key \
                         was substituted, the picture will not match."
                    .into(),
                action: Some("Verify".into()),
                target: Some(format!("capsule:{id}")),
            });
        }
        if r.trustees.is_empty() {
            out.push(Finding {
                id: format!("no-quorum-{id}"),
                severity: "warning",
                title: format!("“{}” can be released by the relay alone", r.name),
                detail: "This capsule has no trustees, so whoever controls the relay can open \
                         it by declaring you silent. To add trustees, seal it again with them; \
                         the capsule's recipients and contents are shown when you open it."
                    .into(),
                action: Some("Open".into()),
                target: Some(format!("capsule:{id}")),
            });
        }
        if r.export_stale {
            out.push(Finding {
                id: format!("stale-{id}"),
                severity: "warning",
                title: format!("The copy of “{}” you exported no longer opens", r.name),
                detail: "Its pieces or a recipient's key changed after you exported it, so the \
                         old copy is sealed to a gate that no longer exists, and its seal \
                         shows a picture that no longer matches. Export it again, and tell \
                         the recipients the new seal."
                    .into(),
                action: Some("Export again".into()),
                target: Some(format!("export:{id}")),
            });
        } else if r.exported_at.is_none() {
            out.push(Finding {
                id: format!("export-{id}"),
                severity: "note",
                title: format!("“{}” exists only on this machine", r.name),
                detail: "If this disk dies, so does the capsule. Export it — it is encrypted and \
                         safe to give the recipient now, or to keep on a USB stick."
                    .into(),
                action: Some("Export".into()),
                target: Some(format!("export:{id}")),
            });
        }
    }

    if !live.is_empty() && open.prefs.relay_url.is_none() {
        out.push(Finding {
            id: "no-relay".into(),
            severity: "warning",
            title: "No relay is watching".into(),
            detail: "Without a relay, nobody will remind you when you go quiet, and nothing \
                     can release on its own — the capsules only open if you release them by \
                     hand. Connect a relay, ideally one you or a friend run."
                .into(),
            action: Some("Connect".into()),
            target: Some("relay".into()),
        });
    }
    if let Some(e) = &open.prefs.relay_last_error {
        out.push(Finding {
            id: "relay-error".into(),
            severity: "warning",
            title: "The relay did not confirm your last check-in".into(),
            detail: e.clone(),
            action: Some("Check in again".into()),
            target: Some("checkin".into()),
        });
    }

    let year = 365 * SECONDS_PER_DAY;
    let rehearsed = open.prefs.last_rehearsal_at;
    if !live.is_empty() && rehearsed.is_none_or(|t| now.0.saturating_sub(t) > year) {
        out.push(Finding {
            id: "rehearsal".into(),
            severity: "note",
            title: if rehearsed.is_none() {
                "You have never run a rehearsal".into()
            } else {
                "Your last rehearsal was over a year ago".into()
            },
            detail: "A rehearsal walks the whole release end to end without touching anything \
                     real. It is the only way to find out your setup is wrong while you can \
                     still fix it."
                .into(),
            action: Some("Rehearse".into()),
            target: Some("rehearse".into()),
        });
    }

    Ok(out)
}

#[tauri::command]
async fn connect_relay(
    state: State<'_, AppState>,
    url: String,
    contact: Option<String>,
) -> UiResult<()> {
    let base = relay::normalise(&url).map_err(UiError::Refused)?;

    let contact =
        sealing::normalise_contact(contact.as_deref().unwrap_or("")).map_err(UiError::Refused)?;
    let (vault_id, identity, threshold) = {
        let guard = state.open()?;
        let open = guard.as_ref().ok_or(UiError::Locked)?;
        let header = open.vault.header();
        let shortest = open
            .vault
            .list_capsules()
            .map_err(store_err)?
            .iter()
            .filter_map(|c| open.record(&c.id.short()).ok().flatten())
            .map(|r| r.silence_days)
            .min()
            .unwrap_or(open.prefs.checkin_interval_days + open.prefs.grace_days + 8);
        (
            header.public_identity.vigil_fingerprint().short(),
            header.public_identity.clone(),
            shortest as u64 * SECONDS_PER_DAY,
        )
    };
    let key = relay::fetch_key(&base).await.map_err(UiError::Refused)?;
    relay::enroll(&base, &vault_id, &identity, threshold, contact.as_deref())
        .await
        .map_err(UiError::Refused)?;
    let resume_from = relay::last_counter(&base, &vault_id)
        .await
        .map_err(UiError::Refused)?;

    {
        let mut guard = state.open()?;
        let open = guard.as_mut().ok_or(UiError::Locked)?;
        open.prefs.relay_url = Some(base);
        open.prefs.relay_key = Some(key);
        open.prefs.owner_contact = contact;
        open.prefs.relay_enrolled_at = Some(SystemClock.now().0);
        open.prefs.relay_counter = resume_from;
        open.prefs.relay_last_error = None;
        open.save_prefs()?;
    }

    sync_relay(&state).await?;
    check_in(state, false).await.map(|_| ())
}

#[tauri::command]
fn disconnect_relay(state: State<'_, AppState>) -> UiResult<()> {
    let mut guard = state.open()?;
    let open = guard.as_mut().ok_or(UiError::Locked)?;
    open.prefs.relay_url = None;
    open.prefs.relay_key = None;
    open.prefs.relay_enrolled_at = None;
    open.prefs.relay_last_error = None;
    open.prefs.relay_last_receipt_at = None;
    open.save_prefs()
}

#[tauri::command]
fn run_rehearsal(
    state: State<'_, AppState>,
    quorum: u8,
    trustees: u8,
    behaviour: String,
    answering: u8,
    silence_days: Option<u32>,
    countdown_days: Option<u32>,
) -> RehearsalView {
    let mut guard = state.inner.lock().unwrap_or_else(|e| e.into_inner());
    let config = match guard.as_mut() {
        Some(open) => {
            open.prefs.last_rehearsal_at = Some(SystemClock.now().0);
            let _ = open.save_prefs();
            let base = open.prefs.ladder();
            session::ladder_for(
                &open.prefs,
                silence_days.unwrap_or((base.silence_threshold / SECONDS_PER_DAY) as u32),
                countdown_days.unwrap_or(3),
            )
        }
        None => session::ladder_for(
            &session::Prefs::default(),
            silence_days.unwrap_or(45),
            countdown_days.unwrap_or(3),
        ),
    };
    views::rehearse(
        &config,
        quorum.min(64),
        trustees.min(64),
        &behaviour,
        answering.min(64),
    )
}

fn watch_idle(app: AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(15));
        let state = app.state::<AppState>();
        let minutes = match state.inner.lock() {
            Ok(g) => match g.as_ref() {
                Some(open) => open.prefs.auto_lock_minutes,
                None => continue,
            },
            Err(_) => continue,
        };
        let last = *state
            .last_activity
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if SystemClock.now().0.saturating_sub(last) > minutes as u64 * 60 {
            state.lock();
            let _ = app.emit("vault-locked", "idle");
        }
    });
}

pub fn run() {
    if !zdd_core::harden_process() {
        tracing::warn!(
            "could not fully harden the process; a crash dump could contain key material"
        );
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zdeaddrop=info,zdd_core=warn".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::new(session::default_vault_path()))
        .setup(|app| {
            watch_idle(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Destroyed = event {
                window.app_handle().state::<AppState>().lock();
            }
        })
        .invoke_handler(tauri::generate_handler![
            seal_svg,
            status,
            create_vault,
            unlock,
            unlock_with_sheet,
            lock,
            touch,
            load_vault,
            save_prefs,
            begin_recovery_sheet,
            confirm_recovery_sheet,
            cancel_recovery_sheet,
            load_vigil,
            check_in,
            set_hold,
            clear_hold,
            acknowledge_clock,
            load_capsules,
            capsule_detail,
            preview_item,
            inspect_key,
            pick_paths,
            pick_key_file,
            generate_recipient_key,
            seal_capsule,
            pending_shares,
            save_share,
            copy_share,
            send_relay_share,
            copy_text,
            reveal_vault,
            open_link,
            app_version,
            finish_shares,
            reissue_shares,
            update_terms,
            verify_recipient,
            replace_recipient_key,
            export_capsule,
            release_capsule,
            delete_capsule,
            load_findings,
            connect_relay,
            disconnect_relay,
            run_rehearsal,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start ZDeadDrop");
}
