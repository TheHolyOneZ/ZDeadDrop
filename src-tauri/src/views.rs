use serde::Serialize;

use zdd_core::capsule::Capsule;
use zdd_core::clock::SECONDS_PER_DAY;
use zdd_core::policy::{LadderConfig, Stage};
use zdd_core::rehearsal::{self, Severity, TrusteeBehaviour};
use zdd_core::release::GatePolicy;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub exists: bool,
    pub unlocked: bool,
    pub short_id: Option<String>,

    pub seal_seed: Option<String>,
    pub path: String,
    pub recovery_policy: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VigilView {
    pub stage: &'static str,
    pub summary: &'static str,
    pub silence_secs: u64,
    pub due_in_secs: i64,
    pub interval_secs: u64,
    pub counter: u64,
    pub frozen_reason: Option<String>,
    pub hold_until: Option<u64>,
    pub max_hold_days: u64,
    pub relay: Option<RelayView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayView {
    pub url: String,
    pub last_receipt_at: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleView {
    pub id: String,
    pub seal_seed: String,
    pub fingerprint: String,
    pub figure: String,
    pub name: String,
    pub state: &'static str,
    pub stage: &'static str,
    pub condition: String,
    pub recipient_count: usize,
    pub quorum: Option<Quorum>,
    pub size_bytes: u64,
    pub entry_count: usize,
    pub is_rehearsal: bool,
    pub created_at: u64,
    pub released_at: Option<u64>,
    pub shares_pending: bool,
    pub shares_distributed: bool,
    pub exported_at: Option<u64>,
    pub silence_days: u32,
    pub countdown_days: u32,
}

#[derive(Debug, Serialize)]
pub struct Quorum {
    pub have: u8,
    pub need: u8,
    pub of: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleDetail {
    pub capsule: CapsuleView,
    pub note: Option<String>,
    pub silence_days: u32,
    pub countdown_days: u32,
    pub trustees: Vec<String>,
    pub trustee_contacts: Vec<Option<String>>,
    pub recipients: Vec<RecipientView>,
    pub entries: Vec<EntryView>,
    pub policy_weakness: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientView {
    pub id: u8,
    pub label: String,
    pub fingerprint: String,
    pub seal_seed: String,
    pub figure: String,
    pub tier: u8,
    pub claim_window_days: u64,
    pub verified_at: Option<u64>,
    pub rotated_at: Option<u64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryView {
    pub path: String,
    pub size: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub action: Option<String>,

    pub target: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub short_id: String,
    pub vigil_fingerprint: String,
    pub vigil_seed: String,
    pub recovery_policy: &'static str,
    pub unlock_paths: Vec<String>,
    pub relay_url: Option<String>,
    pub owner_contact: Option<String>,
    pub trustee_count: usize,
    pub checkin_interval_days: u32,
    pub grace_days: u32,
    pub auto_lock_minutes: u32,
    pub recovery_sheet_at: Option<u64>,
    pub last_rehearsal_at: Option<u64>,
    pub path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub fingerprint: String,
    pub seal_seed: String,
    pub figure: String,
    pub public_key: String,
    pub was_private: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareView {
    pub capsule: String,
    pub seal: String,

    pub relay_connected: bool,
    pub relay: Option<ShareSlot>,
    pub trustees: Vec<ShareSlot>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSlot {
    pub which: String,
    pub holder: String,
    pub handed_out: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedView {
    pub id: String,
    pub name: String,
    pub skipped: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RehearsalView {
    pub verdict: String,
    pub would_release: bool,
    pub released_on: Option<u64>,
    pub timeline: Vec<MomentView>,
    pub concerns: Vec<ConcernView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MomentView {
    pub day: u64,
    pub stage: &'static str,
    pub lines: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConcernView {
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
}

pub fn rehearse(
    config: &LadderConfig,
    quorum: u8,
    trustees: u8,
    behaviour: &str,
    answering: u8,
) -> RehearsalView {
    let behaviour = match behaviour {
        "some-answer" => TrusteeBehaviour::SomeConfirm {
            count: answering,
            after_days: 2,
        },
        "one-vetoes" => TrusteeBehaviour::SomeVeto {
            vetoes: 1,
            confirms: trustees.saturating_sub(1),
            after_days: 2,
        },
        "nobody-answers" => TrusteeBehaviour::Silent,
        _ => TrusteeBehaviour::AllConfirm,
    };

    let report = rehearsal::run(config, quorum, trustees, &behaviour, 720);

    RehearsalView {
        verdict: report.verdict(),
        would_release: report.would_release(),
        released_on: report.released_on,
        timeline: report
            .timeline
            .iter()
            .map(|m| MomentView {
                day: m.day,
                stage: stage_name(&m.stage),
                lines: m.happenings.iter().map(|h| h.describe()).collect(),
            })
            .collect(),
        concerns: report
            .concerns
            .iter()
            .map(|c| ConcernView {
                severity: match c.severity {
                    Severity::Blocking => "blocking",
                    Severity::Warning => "warning",
                },
                title: c.title.clone(),
                detail: c.detail.clone(),
            })
            .collect(),
    }
}

pub fn quorum_of(capsule: &Capsule) -> (u8, u8) {
    match capsule.gate.policy {
        GatePolicy::RelayAndQuorum { threshold, total }
        | GatePolicy::QuorumOnly { threshold, total } => (threshold, total),
        GatePolicy::RelayOnly => (0, 0),
    }
}

pub fn stage_name(stage: &Stage) -> &'static str {
    match stage {
        Stage::Held { .. } => "held",
        Stage::Grace { .. } => "grace",
        Stage::Escalating { .. } => "escalating",
        Stage::AwaitingQuorum { .. } => "awaiting_quorum",
        Stage::Countdown { .. } => "countdown",
        Stage::ReadyToRelease => "ready_to_release",
        Stage::Released { .. } => "released",
        Stage::Cancelled => "cancelled",
        Stage::OnHold { .. } => "on_hold",
        Stage::Frozen => "frozen",
    }
}

pub fn seal_state_for(stage: &Stage) -> &'static str {
    match stage {
        Stage::Held { .. } => "sealed",
        Stage::Grace { .. } | Stage::Escalating { .. } => "stirring",
        Stage::AwaitingQuorum { .. } | Stage::Countdown { .. } | Stage::ReadyToRelease => {
            "breaking"
        }
        Stage::Released { .. } => "broken",
        Stage::Cancelled | Stage::OnHold { .. } => "held",
        Stage::Frozen => "frozen",
    }
}

pub fn describe_condition(config: &LadderConfig, quorum: u8) -> String {
    let days = config.silence_threshold / SECONDS_PER_DAY;
    let countdown = config.countdown / SECONDS_PER_DAY;
    let tail = format!(
        "{countdown} {}",
        if countdown == 1 { "day" } else { "days" }
    );
    if quorum == 0 {
        format!("{days} days of silence, relay only, then {tail}")
    } else {
        format!("{days} days of silence, then {quorum} trustees agree, then {tail}")
    }
}

pub fn entry_kind(kind: zdd_core::capsule::EntryKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "file".into())
}
