use std::sync::Arc;
use std::time::Duration;

use rusqlite::{params, OptionalExtension};

use crate::api::Relay;
use crate::notify::{self, Channel, Message, Sender};
use crate::store;

const TICK: Duration = Duration::from_secs(15 * 60);

const REMINDER_POINTS: [u64; 4] = [1, 2, 3, 4];
const REMINDER_DIVISIONS: u64 = 5;

pub async fn run(relay: Arc<Relay>, sender: Sender, base_url: String) {
    if !sender.has_email() {
        tracing::warn!(
            "no SMTP configured; only webhook contacts will be reachable from this relay"
        );
    }

    loop {
        if let Err(e) = tick(&relay, &sender, &base_url).await {
            tracing::error!(error = %e, "reminder pass failed; will retry");
        }
        tokio::time::sleep(TICK).await;
    }
}

pub async fn tick(relay: &Relay, sender: &Sender, base_url: &str) -> crate::Result<()> {
    let now = zdd_core::clock::Clock::now(&relay.clock).0;

    let due: Vec<Due> = {
        let db = relay.db();
        let mut stmt = db.prepare(
            "SELECT v.vault,
                    v.silence_threshold + MIN(
                        (SELECT COUNT(*) FROM trustees t WHERE t.vault = v.vault AND t.verdict = 'present'),
                        ?1) * ?2,
                    v.owner_contact, v.reminders_sent,
                    v.trustees_polled, COALESCE(s.release_delay, 0),
                    c.sent_at IS NOT NULL
             FROM vaults v
             LEFT JOIN vault_settings s ON s.vault = v.vault
             LEFT JOIN countdowns c ON c.vault = v.vault",
        )?;
        let ladder = zdd_core::policy::LadderConfig::default();
        let rows = stmt.query_map(
            params![ladder.max_vetoes as i64, ladder.veto_extension as i64],
            |r| {
                Ok(Pending {
                    vault: r.get(0)?,
                    threshold: r.get::<_, i64>(1)? as u64,
                    contact: r.get(2)?,
                    reminders_sent: r.get::<_, i64>(3)? as u64,
                    trustees_polled: r.get::<_, i64>(4)? != 0,
                    delay: r.get::<_, i64>(5)? as u64,
                    countdown_sent: r.get::<_, bool>(6)?,
                })
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            let pending = row?;
            if let Some(work) = assess(&db, &pending, now)? {
                out.push(work);
            }
        }
        out
    };

    for work in due {
        deliver(relay, sender, base_url, work, now).await?;
    }

    Ok(())
}

struct Pending {
    vault: String,
    threshold: u64,
    contact: Option<String>,
    reminders_sent: u64,
    trustees_polled: bool,
    delay: u64,
    countdown_sent: bool,
}

struct Due {
    vault: String,
    contact: Option<Channel>,

    reminder: Option<u64>,
    days_quiet: u64,
    poll_trustees: bool,

    countdown: Option<u64>,
}

fn assess(conn: &rusqlite::Connection, pending: &Pending, now: u64) -> crate::Result<Option<Due>> {
    let Some((_, last_at)) = store::last_checkin(conn, &pending.vault)? else {
        return Ok(None);
    };

    let silence = now.saturating_sub(last_at);
    let days_quiet = silence / 86_400;

    let window_start = pending.threshold / 4;
    let window = pending.threshold.saturating_sub(window_start);

    let mut reminder = None;
    if silence >= window_start && silence < pending.threshold && window > 0 {
        let elapsed = silence - window_start;
        let due_count = REMINDER_POINTS
            .iter()
            .filter(|point| elapsed >= window * **point / REMINDER_DIVISIONS)
            .count() as u64;

        if due_count > pending.reminders_sent {
            reminder = Some(pending.reminders_sent + 1);
        }
    }

    let poll_trustees = silence >= pending.threshold && !pending.trustees_polled;

    let release_at = pending.threshold.saturating_add(pending.delay);
    let countdown = (pending.delay > 0
        && silence >= pending.threshold
        && silence < release_at
        && !pending.countdown_sent)
        .then(|| (release_at - silence).div_ceil(3600));

    if reminder.is_none() && !poll_trustees && countdown.is_none() {
        return Ok(None);
    }

    Ok(Some(Due {
        vault: pending.vault.clone(),
        contact: pending.contact.as_deref().and_then(Channel::parse),
        reminder,
        days_quiet,
        poll_trustees,
        countdown,
    }))
}

async fn deliver(
    relay: &Relay,
    sender: &Sender,
    base_url: &str,
    work: Due,
    now: u64,
) -> crate::Result<()> {
    if let Some(number) = work.reminder {
        if let Some(channel) = &work.contact {
            let token = {
                let db = relay.db();
                store::new_tap(&db, &work.vault, now)?
            };
            let message = Message::Reminder {
                days_quiet: work.days_quiet,
                resume_url: format!("{base_url}/v1/tap/{token}"),
            };
            let outcome = sender.send(channel, &message).await;
            tracing::info!(
                vault = %work.vault,
                reminder = number,
                to = %channel.redacted(),
                sent = outcome.succeeded(),
                "reminder"
            );

            let db = relay.db();
            notify::record(&db, &work.vault, channel, "reminder", &outcome, now)?;
        }

        let db = relay.db();
        db.execute(
            "UPDATE vaults SET reminders_sent = ?1 WHERE vault = ?2",
            params![number as i64, work.vault],
        )?;
    }

    if let Some(hours_left) = work.countdown {
        if let Some(channel) = &work.contact {
            let token = {
                let db = relay.db();
                store::new_tap(&db, &work.vault, now)?
            };
            let message = Message::FinalCountdown {
                hours_left,
                cancel_url: format!("{base_url}/v1/tap/{token}"),
            };
            let outcome = sender.send(channel, &message).await;
            tracing::info!(vault = %work.vault, hours_left, sent = outcome.succeeded(), "final countdown");
            let db = relay.db();
            notify::record(&db, &work.vault, channel, "final_countdown", &outcome, now)?;
        }
        let db = relay.db();
        db.execute(
            "INSERT INTO countdowns (vault, sent_at) VALUES (?1, ?2)
             ON CONFLICT(vault) DO NOTHING",
            params![work.vault, now as i64],
        )?;
    }

    if work.poll_trustees {
        let trustees: Vec<(String, Option<String>)> = {
            let db = relay.db();
            let mut stmt = db.prepare("SELECT token, contact FROM trustees WHERE vault = ?1")?;
            let rows = stmt.query_map(params![work.vault], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<std::result::Result<_, _>>()?
        };

        for (token, contact) in trustees {
            let Some(channel) = contact.as_deref().and_then(Channel::parse) else {
                continue;
            };
            let message = Message::TrusteePrompt {
                prompt_url: format!("{base_url}/v1/trustee/{token}"),
            };
            let outcome = sender.send(&channel, &message).await;
            tracing::info!(
                vault = %work.vault,
                to = %channel.redacted(),
                sent = outcome.succeeded(),
                "trustee prompt"
            );

            let db = relay.db();
            notify::record(&db, &work.vault, &channel, "trustee_prompt", &outcome, now)?;
        }

        let db = relay.db();
        db.execute(
            "UPDATE vaults SET trustees_polled = 1 WHERE vault = ?1",
            params![work.vault],
        )?;
    }

    Ok(())
}

pub fn reset(conn: &rusqlite::Connection, vault: &str) -> crate::Result<()> {
    conn.execute(
        "UPDATE vaults SET reminders_sent = 0, trustees_polled = 0 WHERE vault = ?1",
        params![vault],
    )?;
    conn.execute("DELETE FROM countdowns WHERE vault = ?1", params![vault])?;

    conn.execute(
        "UPDATE trustees SET verdict = NULL, answered = NULL WHERE vault = ?1",
        params![vault],
    )?;
    Ok(())
}

pub fn set_contact(conn: &rusqlite::Connection, vault: &str, contact: &str) -> crate::Result<()> {
    conn.execute(
        "UPDATE vaults SET owner_contact = ?1 WHERE vault = ?2",
        params![contact, vault],
    )?;
    Ok(())
}

pub fn contact_of(conn: &rusqlite::Connection, vault: &str) -> crate::Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT owner_contact FROM vaults WHERE vault = ?1",
            params![vault],
            |r| r.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn pending(threshold_days: u64, sent: u64, polled: bool) -> Pending {
        Pending {
            vault: "v1".into(),
            threshold: threshold_days * DAY,
            contact: Some("mailto:alex@example.com".into()),
            reminders_sent: sent,
            trustees_polled: polled,
            delay: 0,
            countdown_sent: false,
        }
    }

    fn db_with_checkin(days_ago: u64, now: u64) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE checkins (vault TEXT, counter INTEGER, asserted_at INTEGER);
             CREATE TABLE holds (vault TEXT PRIMARY KEY, until INTEGER, issued_at INTEGER);
             CREATE TABLE taps (token TEXT PRIMARY KEY, vault TEXT, issued INTEGER, used_at INTEGER);
             CREATE TABLE vault_settings (vault TEXT PRIMARY KEY, release_delay INTEGER, issued_at INTEGER);
             CREATE TABLE countdowns (vault TEXT PRIMARY KEY, sent_at INTEGER);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO checkins (vault, counter, asserted_at) VALUES ('v1', 1, ?1)",
            params![(now - days_ago * DAY) as i64],
        )
        .unwrap();
        conn
    }

    #[test]
    fn nothing_happens_while_the_owner_is_recent() {
        let now = 1_800_000_000;
        let conn = db_with_checkin(5, now);
        assert!(assess(&conn, &pending(45, 0, false), now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn reminders_start_only_partway_through_the_window() {
        let now = 1_800_000_000;

        assert!(
            assess(&db_with_checkin(10, now), &pending(45, 0, false), now)
                .unwrap()
                .is_none()
        );
        assert!(
            assess(&db_with_checkin(20, now), &pending(45, 0, false), now)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn reminders_are_sent_one_at_a_time_and_in_order() {
        let now = 1_800_000_000;
        let conn = db_with_checkin(40, now);

        let first = assess(&conn, &pending(45, 0, false), now).unwrap().unwrap();
        assert_eq!(first.reminder, Some(1));

        let second = assess(&conn, &pending(45, 1, false), now).unwrap().unwrap();
        assert_eq!(second.reminder, Some(2));
    }

    #[test]
    fn a_restart_does_not_resend() {
        let now = 1_800_000_000;
        let conn = db_with_checkin(40, now);

        let work = assess(&conn, &pending(45, 4, false), now).unwrap();
        assert!(
            work.is_none(),
            "a restart re-sent reminders that had already gone out"
        );
    }

    #[test]
    fn trustees_are_polled_once_past_the_threshold() {
        let now = 1_800_000_000;
        let conn = db_with_checkin(50, now);

        let work = assess(&conn, &pending(45, 4, false), now).unwrap().unwrap();
        assert!(work.poll_trustees);

        assert_eq!(work.reminder, None);

        assert!(assess(&conn, &pending(45, 4, true), now).unwrap().is_none());
    }

    #[test]
    fn a_vault_that_never_checked_in_is_left_alone() {
        let now = 1_800_000_000;
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE checkins (vault TEXT, counter INTEGER, asserted_at INTEGER);
             CREATE TABLE holds (vault TEXT PRIMARY KEY, until INTEGER, issued_at INTEGER);
             CREATE TABLE taps (token TEXT PRIMARY KEY, vault TEXT, issued INTEGER, used_at INTEGER);
             CREATE TABLE vault_settings (vault TEXT PRIMARY KEY, release_delay INTEGER, issued_at INTEGER);
             CREATE TABLE countdowns (vault TEXT PRIMARY KEY, sent_at INTEGER);",
        )
        .unwrap();
        assert!(assess(&conn, &pending(45, 0, false), now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn the_schedule_scales_with_the_threshold() {
        let now = 1_800_000_000;

        assert!(
            assess(&db_with_checkin(2, now), &pending(14, 0, false), now)
                .unwrap()
                .is_none()
        );
        assert!(
            assess(&db_with_checkin(6, now), &pending(14, 0, false), now)
                .unwrap()
                .is_some()
        );

        assert!(
            assess(&db_with_checkin(6, now), &pending(90, 0, false), now)
                .unwrap()
                .is_none()
        );
        assert!(
            assess(&db_with_checkin(40, now), &pending(90, 0, false), now)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn checking_in_resets_the_counters() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vaults (vault TEXT PRIMARY KEY, reminders_sent INTEGER DEFAULT 0,
                                  trustees_polled INTEGER DEFAULT 0, owner_contact TEXT);
             CREATE TABLE trustees (vault TEXT, token TEXT, verdict TEXT, answered INTEGER);
             CREATE TABLE countdowns (vault TEXT PRIMARY KEY, sent_at INTEGER);
             INSERT INTO vaults (vault, reminders_sent, trustees_polled) VALUES ('v1', 4, 1);
             INSERT INTO trustees (vault, token, verdict) VALUES ('v1', 't', 'gone');",
        )
        .unwrap();

        reset(&conn, "v1").unwrap();

        let (sent, polled): (i64, i64) = conn
            .query_row(
                "SELECT reminders_sent, trustees_polled FROM vaults",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sent, 0);
        assert_eq!(polled, 0);

        let verdict: Option<String> = conn
            .query_row("SELECT verdict FROM trustees", [], |r| r.get(0))
            .unwrap();
        assert_eq!(verdict, None, "a check-in must clear the previous poll");
    }

    #[test]
    fn the_final_countdown_warns_once() {
        let now = 1_000 * DAY;
        let conn = db_with_checkin(46, now);
        let mut p = pending(45, 4, true);
        p.delay = 3 * DAY;
        let due = assess(&conn, &p, now).unwrap().expect("countdown due");
        assert_eq!(due.countdown, Some(48));

        p.countdown_sent = true;
        assert!(assess(&conn, &p, now).unwrap().is_none());

        let early = db_with_checkin(40, now);
        p.countdown_sent = false;
        let due = assess(&early, &p, now).unwrap();
        assert!(due.is_none_or(|d| d.countdown.is_none()));
    }

    #[test]
    fn a_contact_can_be_set_and_read_back() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE vaults (vault TEXT PRIMARY KEY, owner_contact TEXT);
             INSERT INTO vaults (vault) VALUES ('v1');",
        )
        .unwrap();

        assert_eq!(contact_of(&conn, "v1").unwrap(), None);
        set_contact(&conn, "v1", "https://ntfy.sh/topic").unwrap();
        assert_eq!(
            contact_of(&conn, "v1").unwrap().as_deref(),
            Some("https://ntfy.sh/topic")
        );
    }
}
