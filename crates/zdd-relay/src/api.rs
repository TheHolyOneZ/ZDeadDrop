use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use rusqlite::Connection;

use zdd_core::checkin::{RelayKeypair, SignedCheckIn, SilenceProof};
use zdd_core::clock::{Clock, SystemClock, Timestamp};
use zdd_core::identity::VaultPublicIdentity;
use zdd_core::secret::Key32;

use crate::error::{RelayError, Result};
use crate::log::{self, Receipt};
use crate::store;

pub struct Relay {
    pub db: Mutex<Connection>,
    pub keypair: RelayKeypair,
    pub clock: SystemClock,
}

pub type Shared = Arc<Relay>;

impl Relay {
    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    pub fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/logo.png", get(logo))
        .route("/v1/key", get(relay_key))
        .route("/v1/vault", post(enroll))
        .route("/v1/vault/{vault}/checkin", post(checkin))
        .route("/v1/vault/{vault}/status", get(status))
        .route("/v1/vault/{vault}/sth", get(tree_head))
        .route("/v1/vault/{vault}/log", get(full_log))
        .route("/v1/vault/{vault}/silence-proof", get(silence_proof))
        .route("/v1/vault/{vault}/release-share", post(release_share))
        .route("/v1/vault/{vault}/shares", post(deposit_share))
        .route("/v1/vault/{vault}/hold", post(hold))
        .route("/v1/vault/{vault}/trustees", post(set_trustees))
        .route("/v1/vault/{vault}/settings", post(set_settings))
        .route("/v1/tap/{token}", get(tap_page).post(tap))
        .route("/v1/trustee/{token}", get(trustee_prompt))
        .route("/v1/trustee/{token}", post(trustee_answer))
        .with_state(state)
}

async fn logo() -> impl axum::response::IntoResponse {
    (
        [
            (axum::http::header::CONTENT_TYPE, "image/png"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        &include_bytes!("../assets/logo.png")[..],
    )
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "service": "zdd-relay", "version": env!("CARGO_PKG_VERSION") }))
}

async fn relay_key(State(relay): State<Shared>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "verifying_key": zdd_core::codec::to_hex(&relay.keypair.verifying())
    }))
}

#[derive(serde::Deserialize)]
pub struct EnrollRequest {
    pub vault: String,
    pub identity: VaultPublicIdentity,

    pub relay_share: Option<String>,
    pub silence_threshold: u64,

    pub owner_contact: Option<String>,
    #[serde(default)]
    pub trustees: Vec<TrusteeEnrollment>,
}

#[derive(serde::Deserialize)]
pub struct TrusteeEnrollment {
    pub index: u8,
    pub token: String,
    pub contact: Option<String>,
}

async fn enroll(
    State(relay): State<Shared>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<serde_json::Value>> {
    if req.silence_threshold < 3600 {
        return Err(RelayError::Corrupt(
            "a silence threshold under an hour is almost certainly a mistake".into(),
        ));
    }

    let share = req
        .relay_share
        .as_deref()
        .map(|hex| {
            zdd_core::codec::from_hex(hex)
                .and_then(|b| Key32::from_slice(&b).ok())
                .ok_or_else(|| RelayError::Corrupt("malformed relay share".into()))
        })
        .transpose()?;

    let db = relay.db();
    let log_id = store::enroll(
        &db,
        &req.vault,
        &req.identity,
        share.as_ref(),
        req.silence_threshold,
        req.owner_contact.as_deref(),
        relay.now().0,
    )?;

    for trustee in &req.trustees {
        store::add_trustee(
            &db,
            &req.vault,
            trustee.index,
            &trustee.token,
            trustee.contact.as_deref(),
        )?;
    }

    Ok(Json(serde_json::json!({
        "log_id": zdd_core::codec::to_hex(&log_id),
        "verifying_key": zdd_core::codec::to_hex(&relay.keypair.verifying()),
    })))
}

async fn checkin(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
    Json(record): Json<SignedCheckIn>,
) -> Result<Json<Receipt>> {
    let db = relay.db();
    let now = relay.now();

    let index = log::append(&db, &vault, &record, now)?;

    crate::schedule::reset(&db, &vault)?;

    let tree = log::load(&db, &vault)?;

    let inclusion = tree
        .prove(index)
        .ok_or_else(|| RelayError::Corrupt("could not prove a record we just stored".into()))?;

    Ok(Json(Receipt {
        index,
        inclusion,
        sth: log::sign_head(&relay.keypair, &tree, now),
    }))
}

#[derive(serde::Serialize)]
pub struct Status {
    pub vault: String,
    pub checkins: u64,
    pub last_counter: Option<u64>,
    pub silence_secs: Option<u64>,
    pub silence_threshold: u64,
    pub past_threshold: bool,
    pub confirmations: u32,
    pub vetoes: u32,
}

async fn status(State(relay): State<Shared>, Path(vault): Path<String>) -> Result<Json<Status>> {
    let db = relay.db();
    let now = relay.now().0;

    let threshold = store::effective_threshold(&db, &vault)?;
    let last = store::last_checkin(&db, &vault)?;
    let tree = log::load(&db, &vault)?;

    let silence = last.map(|(_, at)| now.saturating_sub(at));

    Ok(Json(Status {
        vault: vault.clone(),
        checkins: tree.len(),
        last_counter: last.map(|(c, _)| c),
        silence_secs: silence,
        silence_threshold: threshold,
        past_threshold: silence.is_some_and(|s| s >= threshold),
        confirmations: store::confirmations(&db, &vault)?,
        vetoes: store::vetoes(&db, &vault)?,
    }))
}

async fn tree_head(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
) -> Result<Json<zdd_core::checkin::SignedTreeHead>> {
    let db = relay.db();
    let tree = log::load(&db, &vault)?;
    Ok(Json(log::sign_head(&relay.keypair, &tree, relay.now())))
}

async fn full_log(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let tree = log::load(&db, &vault)?;

    let mut stmt =
        db.prepare("SELECT record FROM checkins WHERE vault = ?1 ORDER BY leaf_index ASC")?;
    let rows = stmt.query_map(rusqlite::params![vault], |r| r.get::<_, String>(0))?;

    let mut records = Vec::new();
    for row in rows {
        let value: serde_json::Value =
            serde_json::from_str(&row?).map_err(|e| RelayError::Corrupt(e.to_string()))?;
        records.push(value);
    }

    Ok(Json(serde_json::json!({
        "vault": tree.vault,
        "log_id": zdd_core::codec::to_hex(&tree.log_id),
        "size": tree.len(),
        "root": zdd_core::codec::to_hex(&tree.root()),
        "records": records,
    })))
}

async fn silence_proof(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
) -> Result<Json<SilenceProof>> {
    let db = relay.db();
    let now = relay.now();

    let record =
        store::last_record(&db, &vault)?.ok_or_else(|| RelayError::UnknownVault(vault.clone()))?;

    let threshold = store::effective_threshold(&db, &vault)?;

    let since = record
        .checkin
        .asserted_at
        .0
        .max(store::hold_until(&db, &vault)?.unwrap_or(0));
    let silence = now.0.saturating_sub(since);
    if silence < threshold {
        return Err(RelayError::StillPresent);
    }

    let tree = log::load(&db, &vault)?;
    let index = tree.len().saturating_sub(1);
    let inclusion = tree
        .prove(index)
        .ok_or_else(|| RelayError::Corrupt("empty log for a vault with check-ins".into()))?;

    Ok(Json(SilenceProof {
        last_checkin: record,
        inclusion,
        sth: log::sign_head(&relay.keypair, &tree, now),
    }))
}

async fn release_share(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let now = relay.now().0;

    let (_, last_at) =
        store::last_checkin(&db, &vault)?.ok_or_else(|| RelayError::UnknownVault(vault.clone()))?;

    let threshold =
        store::effective_threshold(&db, &vault)?.saturating_add(store::release_delay(&db, &vault)?);

    if now.saturating_sub(last_at) < threshold {
        return Err(RelayError::StillPresent);
    }

    let enrolled = store::relay_share(&db, &vault)?;
    let gates = store::gate_shares(&db, &vault)?;
    if enrolled.is_none() && gates.is_empty() {
        return Err(RelayError::Corrupt("no relay share was deposited".into()));
    }

    let shares: serde_json::Map<String, serde_json::Value> = gates
        .iter()
        .map(|(gate, key)| {
            (
                gate.clone(),
                serde_json::Value::String(zdd_core::codec::to_hex(key.expose())),
            )
        })
        .collect();

    Ok(Json(serde_json::json!({
        "relay_share": enrolled.map(|k| zdd_core::codec::to_hex(k.expose())),
        "shares": shares,
    })))
}

async fn set_settings(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
    Json(set): Json<zdd_core::checkin::SignedSettings>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let identity = store::identity_of(&db, &vault)?;
    set.verify(&identity)
        .map_err(|_| RelayError::BadSignature)?;
    if set.silence_threshold < 3600 {
        return Err(RelayError::Corrupt(
            "a silence threshold under an hour is almost certainly a mistake".into(),
        ));
    }
    if set.release_delay > 90 * 86_400 {
        return Err(RelayError::Corrupt(
            "a final countdown over ninety days".into(),
        ));
    }
    if let Some(c) = &set.owner_contact {
        if crate::notify::Channel::parse(c).is_none() {
            return Err(RelayError::Corrupt(format!("unusable contact {c:?}")));
        }
    }
    store::apply_settings(
        &db,
        &vault,
        set.silence_threshold,
        set.release_delay,
        set.owner_contact.as_deref(),
        set.issued_at.0,
    )?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn set_trustees(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
    Json(list): Json<zdd_core::checkin::SignedTrustees>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let identity = store::identity_of(&db, &vault)?;
    list.verify(&identity)
        .map_err(|_| RelayError::BadSignature)?;
    if list.trustees.len() > 64 {
        return Err(RelayError::Corrupt("too many trustees".into()));
    }
    for t in &list.trustees {
        if t.token.len() < 16 || !t.token.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RelayError::Corrupt("malformed trustee token".into()));
        }
        if let Some(c) = &t.contact {
            if crate::notify::Channel::parse(c).is_none() {
                return Err(RelayError::Corrupt(format!(
                    "a trustee contact must be mailto: or an https webhook, not {c:?}"
                )));
            }
        }
    }
    store::replace_trustees(&db, &vault, list.issued_at.0, &list.trustees)?;
    Ok(Json(serde_json::json!({ "trustees": list.trustees.len() })))
}

async fn tap_page(Path(token): Path<String>) -> axum::response::Html<String> {
    if !token.chars().all(|c| c.is_ascii_hexdigit()) || token.len() > 64 {
        return tap_html("This link is not valid.", None);
    }
    tap_html(
        "Tap the button to tell the relay you are here. Nothing else happens, and \
         nothing is sent to anyone.",
        Some(&token),
    )
}

async fn tap(
    State(relay): State<Shared>,
    Path(token): Path<String>,
) -> Result<axum::response::Html<String>> {
    let db = relay.db();
    let now = relay.now().0;
    match store::use_tap(&db, &token, now)? {
        Some(vault) => {
            crate::schedule::reset(&db, &vault)?;
            tracing::info!(%vault, "one-tap check-in");
            Ok(tap_html(
                "Thank you — noted. The reminders stop here. Next time you are at your \
                 computer, open ZDeadDrop and check in there too: this link only buys time.",
                None,
            ))
        }
        None => Ok(tap_html(
            "This link has already been used, or is more than a month old. Open \
             ZDeadDrop and check in there instead.",
            None,
        )),
    }
}

fn tap_html(message: &str, token: Option<&str>) -> axum::response::Html<String> {
    let form = token
        .map(|t| {
            format!(
                "<form method=\"post\" action=\"/v1/tap/{t}\">\
                 <button type=\"submit\">I'm here</button></form>"
            )
        })
        .unwrap_or_default();
    axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>ZDeadDrop</title>\
         <style>body{{font:17px/1.6 system-ui,sans-serif;max-width:32rem;margin:15vh auto;\
         padding:0 1.5rem;background:#101114;color:#e8e2d4}}button{{font:inherit;\
         font-weight:600;padding:.8rem 2rem;border:0;border-radius:7px;\
         background:#b08d57;color:#14120c;cursor:pointer}}</style></head><body><img src=\"/logo.png\" alt=\"ZDeadDrop\" width=\"72\" height=\"72\" style=\"display:block;margin-bottom:1.5rem\">\
         <p>{message}</p>{form}</body></html>"
    ))
}

async fn hold(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
    Json(notice): Json<zdd_core::checkin::SignedHold>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let identity = store::identity_of(&db, &vault)?;
    notice
        .verify(&identity)
        .map_err(|_| RelayError::BadSignature)?;

    let now = relay.now().0;

    let slack = 3600;
    if notice.issued_at.0 > now + slack {
        return Err(RelayError::Corrupt(
            "that hold is dated in the future".into(),
        ));
    }
    if notice.until.0 > now + zdd_core::checkin::MAX_HOLD_SECS + slack {
        return Err(RelayError::Corrupt(
            "a hold can last at most ninety days".into(),
        ));
    }

    store::set_hold(&db, &vault, notice.until.0, notice.issued_at.0)?;
    crate::schedule::reset(&db, &vault)?;
    Ok(Json(serde_json::json!({ "until": notice.until.0 })))
}

async fn deposit_share(
    State(relay): State<Shared>,
    Path(vault): Path<String>,
    Json(deposit): Json<zdd_core::release::ShareDeposit>,
) -> Result<Json<serde_json::Value>> {
    let db = relay.db();
    let identity = store::identity_of(&db, &vault)?;
    deposit
        .verify(&identity)
        .map_err(|_| RelayError::BadSignature)?;
    let gate = zdd_core::codec::to_hex(&deposit.gate_id.0);
    store::deposit_share(&db, &vault, &gate, &deposit.share, relay.now().0)?;
    Ok(Json(serde_json::json!({ "gate_id": gate })))
}

#[derive(serde::Serialize)]
pub struct TrusteePrompt {
    pub question: String,
    pub silence_secs: Option<u64>,
    pub already_answered: bool,
}

async fn trustee_prompt(
    State(relay): State<Shared>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;
    let prompt = trustee_prompt_data(&relay, &token)?;

    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"));
    if !wants_html {
        return Ok(Json(prompt).into_response());
    }
    if !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || token.len() > 96 {
        return Ok(tap_html("This link is not valid.", None).into_response());
    }
    let body = if prompt.already_answered {
        "<p>Thank you — your answer is recorded. You can change it below if something \
         has changed.</p>"
            .to_string()
    } else {
        String::new()
    };
    let days = prompt
        .silence_secs
        .map(|s| {
            format!(
                "<p>They have not been in touch for {} days.</p>",
                s / 86_400
            )
        })
        .unwrap_or_default();
    Ok(axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <meta name=\"robots\" content=\"noindex\"><title>ZDeadDrop — one question</title>\
         <style>body{{font:17px/1.6 system-ui,sans-serif;max-width:34rem;margin:12vh auto;\
         padding:0 1.5rem;background:#101114;color:#e8e2d4}}form{{display:flex;gap:.6rem;\
         flex-wrap:wrap;margin-top:1.5rem}}button{{font:inherit;font-weight:600;\
         padding:.7rem 1.3rem;border:1px solid #3a3b44;border-radius:7px;background:#1e1f25;\
         color:#e8e2d4;cursor:pointer}}button.gone{{background:#b08d57;color:#14120c;\
         border-color:#b08d57}}.q{{font-size:1.35rem;font-family:Georgia,serif}}</style>\
         </head><body><img src=\"/logo.png\" alt=\"ZDeadDrop\" width=\"72\" height=\"72\" style=\"display:block;margin-bottom:1.5rem\">{body}<p class=\"q\">{q}</p>{days}\
         <p>Please answer only from what you actually know. You will not be told what this \
         concerns, and you are not being asked to do anything else.</p>\
         <form method=\"post\"><button name=\"verdict\" value=\"present\">They are fine</button>\
         <button name=\"verdict\" value=\"unsure\">I don't know</button>\
         <button class=\"gone\" name=\"verdict\" value=\"gone\">I believe they are gone</button>\
         </form></body></html>",
        q = prompt.question,
    ))
    .into_response())
}

fn trustee_prompt_data(relay: &Relay, token: &str) -> Result<TrusteePrompt> {
    let db = relay.db();
    let row: Option<(String, Option<String>)> =
        rusqlite::OptionalExtension::optional(db.query_row(
            "SELECT vault, verdict FROM trustees WHERE token = ?1",
            rusqlite::params![token],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;

    let (vault, verdict) = row.ok_or_else(|| RelayError::UnknownVault("trustee".into()))?;
    let last = store::last_checkin(&db, &vault)?;
    let silence = last.map(|(_, at)| relay.now().0.saturating_sub(at));

    Ok(TrusteePrompt {
        question: "As far as you know, is the person who named you still reachable?".into(),
        silence_secs: silence,
        already_answered: verdict.is_some(),
    })
}

#[derive(serde::Deserialize)]
pub struct TrusteeAnswer {
    pub verdict: String,
}

async fn trustee_answer(
    State(relay): State<Shared>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response> {
    use axum::response::IntoResponse;

    let is_json = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/json"));
    let verdict: String = if is_json {
        serde_json::from_slice::<TrusteeAnswer>(&body)
            .map_err(|_| RelayError::Corrupt("unreadable answer".into()))?
            .verdict
    } else {
        std::str::from_utf8(&body)
            .ok()
            .and_then(|b| b.split('&').find_map(|kv| kv.strip_prefix("verdict=")))
            .unwrap_or_default()
            .to_string()
    };
    let verdict = match verdict.as_str() {
        "gone" | "present" | "unsure" => verdict,
        _ => return Err(RelayError::Corrupt("unrecognised answer".into())),
    };

    let db = relay.db();
    let vault = store::record_verdict(&db, &token, &verdict, relay.now().0)?;
    let confirmations = store::confirmations(&db, &vault)?;

    if !is_json {
        return Ok(tap_html(
            "Thank you. Your answer is recorded. If anything changes, open the same link \
             again and answer again.",
            None,
        )
        .into_response());
    }
    Ok(Json(serde_json::json!({
        "recorded": true,


        "thank_you": "Your answer has been recorded.",
        "answers_so_far": confirmations.min(1),
    }))
    .into_response())
}
