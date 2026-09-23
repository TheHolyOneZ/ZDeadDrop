use crate::clock::{Timestamp, SECONDS_PER_DAY};
use crate::error::{Error, ReleaseRefusal, Result};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LadderConfig {
    pub checkin_interval: u64,

    pub grace: u64,

    pub reminder_offsets: Vec<u64>,

    pub silence_threshold: u64,

    pub countdown: u64,

    pub max_hold: u64,

    pub veto_extension: u64,

    pub max_vetoes: u8,
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            checkin_interval: 30 * SECONDS_PER_DAY,
            grace: 7 * SECONDS_PER_DAY,

            reminder_offsets: vec![
                0,
                2 * SECONDS_PER_DAY,
                4 * SECONDS_PER_DAY,
                7 * SECONDS_PER_DAY,
            ],
            silence_threshold: 45 * SECONDS_PER_DAY,
            countdown: 3 * SECONDS_PER_DAY,
            max_hold: 90 * SECONDS_PER_DAY,
            veto_extension: 30 * SECONDS_PER_DAY,
            max_vetoes: 3,
        }
    }
}

impl LadderConfig {
    pub fn validate(&self) -> Result<()> {
        if self.checkin_interval == 0 {
            return Err(Error::format(
                "ladder",
                "check-in interval must be non-zero",
            ));
        }
        if self.silence_threshold <= self.checkin_interval + self.grace {
            return Err(Error::format(
                "ladder",
                format!(
                    "silence threshold ({}s) must exceed check-in interval plus grace ({}s), \
                     or trustees would be polled before the grace period has even ended",
                    self.silence_threshold,
                    self.checkin_interval + self.grace
                ),
            ));
        }
        if self.countdown == 0 {
            return Err(Error::format(
                "ladder",
                "final countdown must be non-zero — it is the owner's last chance to cancel",
            ));
        }
        if !self.reminder_offsets.windows(2).all(|w| w[0] < w[1]) {
            return Err(Error::format(
                "ladder",
                "reminder offsets must be strictly ascending",
            ));
        }
        if let Some(&last) = self.reminder_offsets.last() {
            let reminder_window = self
                .silence_threshold
                .saturating_sub(self.checkin_interval + self.grace);
            if last > reminder_window {
                return Err(Error::format(
                    "ladder",
                    format!(
                        "the last reminder fires {last}s after grace ends, but trustees are \
                         polled after only {reminder_window}s — the owner would never receive it"
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn next_due(&self, last_checkin: Timestamp) -> Timestamp {
        last_checkin.plus_secs(self.checkin_interval)
    }

    pub fn grace_ends(&self, last_checkin: Timestamp) -> Timestamp {
        last_checkin.plus_secs(self.checkin_interval + self.grace)
    }

    pub fn reminder_times(&self, last_checkin: Timestamp) -> Vec<Timestamp> {
        let base = self.grace_ends(last_checkin);
        self.reminder_offsets
            .iter()
            .map(|&o| base.plus_secs(o))
            .collect()
    }

    pub fn effective_silence_threshold(&self, veto_count: u8) -> u64 {
        let honoured = veto_count.min(self.max_vetoes) as u64;
        self.silence_threshold
            .saturating_add(honoured.saturating_mul(self.veto_extension))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrusteeVerdict {
    BelievesGone,

    BelievesPresent,

    NoResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrusteeResponse {
    pub trustee_index: u8,
    pub verdict: TrusteeVerdict,
    pub at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VigilState {
    pub last_checkin: Timestamp,

    pub checkin_counter: u64,

    pub hold_until: Option<Timestamp>,

    pub responses: Vec<TrusteeResponse>,

    pub quorum_met_at: Option<Timestamp>,

    pub cancelled: bool,

    pub duress_flagged: bool,

    pub released_at: Option<Timestamp>,

    pub is_rehearsal: bool,
}

impl VigilState {
    pub fn starting_at(now: Timestamp) -> Self {
        Self {
            last_checkin: now,
            checkin_counter: 1,
            hold_until: None,
            responses: Vec::new(),
            quorum_met_at: None,
            cancelled: false,
            duress_flagged: false,
            released_at: None,
            is_rehearsal: false,
        }
    }

    pub fn check_in(&mut self, now: Timestamp, under_duress: bool) {
        self.last_checkin = now;
        self.checkin_counter = self.checkin_counter.saturating_add(1);
        self.responses.clear();
        self.quorum_met_at = None;
        self.cancelled = false;
        self.duress_flagged = under_duress;
    }

    pub fn confirmations(&self) -> u8 {
        self.responses
            .iter()
            .filter(|r| r.verdict == TrusteeVerdict::BelievesGone)
            .count()
            .min(u8::MAX as usize) as u8
    }

    pub fn vetoes(&self) -> u8 {
        self.responses
            .iter()
            .filter(|r| r.verdict == TrusteeVerdict::BelievesPresent)
            .count()
            .min(u8::MAX as usize) as u8
    }

    pub fn record_response(&mut self, response: TrusteeResponse) {
        self.responses
            .retain(|r| r.trustee_index != response.trustee_index);
        self.responses.push(response);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage {
    Held {
        next_due: Timestamp,
    },

    Grace {
        grace_ends: Timestamp,
    },

    Escalating {
        reminders_due: usize,
        next_reminder: Option<Timestamp>,
        trustees_polled_at: Timestamp,
    },

    AwaitingQuorum {
        have: u8,
        need: u8,
        vetoes: u8,
    },

    Countdown {
        releases_at: Timestamp,
    },

    ReadyToRelease,

    Released {
        at: Timestamp,
    },

    Cancelled,

    OnHold {
        until: Timestamp,
    },

    Frozen,
}

impl Stage {
    pub fn is_noisy(&self) -> bool {
        matches!(
            self,
            Stage::Escalating { .. }
                | Stage::AwaitingQuorum { .. }
                | Stage::Countdown { .. }
                | Stage::ReadyToRelease
        )
    }

    pub fn summary(&self) -> &'static str {
        match self {
            Stage::Held { .. } => "vigil held",
            Stage::Grace { .. } => "check-in due",
            Stage::Escalating { .. } => "reminding you",
            Stage::AwaitingQuorum { .. } => "asking your trustees",
            Stage::Countdown { .. } => "final countdown",
            Stage::ReadyToRelease => "ready to release",
            Stage::Released { .. } => "released",
            Stage::Cancelled => "release cancelled",
            Stage::OnHold { .. } => "on hold",
            Stage::Frozen => "frozen — clock anomaly",
        }
    }
}

pub fn evaluate(
    config: &LadderConfig,
    state: &VigilState,
    quorum_needed: u8,
    now: Timestamp,
    clock_frozen: bool,
) -> Stage {
    if let Some(at) = state.released_at {
        return Stage::Released { at };
    }
    if clock_frozen {
        return Stage::Frozen;
    }
    if state.cancelled {
        return Stage::Cancelled;
    }
    if let Some(until) = state.hold_until {
        if now < until {
            return Stage::OnHold { until };
        }
    }

    let silence = now.since(state.last_checkin);
    let threshold = config.effective_silence_threshold(state.vetoes());

    if silence < config.checkin_interval {
        return Stage::Held {
            next_due: config.next_due(state.last_checkin),
        };
    }
    if silence < config.checkin_interval + config.grace {
        return Stage::Grace {
            grace_ends: config.grace_ends(state.last_checkin),
        };
    }

    if silence < threshold {
        let times = config.reminder_times(state.last_checkin);
        let due = times.iter().filter(|t| **t <= now).count();
        let next = times.iter().find(|t| **t > now).copied();
        return Stage::Escalating {
            reminders_due: due,
            next_reminder: next,
            trustees_polled_at: state.last_checkin.plus_secs(threshold),
        };
    }

    let have = state.confirmations();
    match state.quorum_met_at {
        Some(met_at) if have >= quorum_needed => {
            let releases_at = met_at.plus_secs(config.countdown);
            if now < releases_at {
                Stage::Countdown { releases_at }
            } else {
                Stage::ReadyToRelease
            }
        }

        _ if quorum_needed == 0 => {
            let releases_at = state.last_checkin.plus_secs(threshold + config.countdown);
            if now < releases_at {
                Stage::Countdown { releases_at }
            } else {
                Stage::ReadyToRelease
            }
        }
        _ => Stage::AwaitingQuorum {
            have,
            need: quorum_needed,
            vetoes: state.vetoes(),
        },
    }
}

pub fn may_release(
    config: &LadderConfig,
    state: &VigilState,
    quorum_needed: u8,
    now: Timestamp,
    clock_frozen: bool,
) -> Result<()> {
    if state.is_rehearsal {
        return Err(ReleaseRefusal::RehearsalOnly.into());
    }

    match evaluate(config, state, quorum_needed, now, clock_frozen) {
        Stage::ReadyToRelease => Ok(()),
        Stage::Released { .. } => Ok(()),
        Stage::Held { .. } | Stage::Grace { .. } | Stage::Escalating { .. } => {
            Err(ReleaseRefusal::OwnerStillPresent.into())
        }
        Stage::AwaitingQuorum { have, need, .. } => {
            Err(ReleaseRefusal::QuorumNotMet { have, need }.into())
        }
        Stage::Countdown { .. } => Err(ReleaseRefusal::CountdownRunning.into()),
        Stage::Cancelled => Err(ReleaseRefusal::CancelledByOwner.into()),
        Stage::OnHold { .. } => Err(ReleaseRefusal::HoldActive.into()),
        Stage::Frozen => Err(ReleaseRefusal::VigilFrozen.into()),
    }
}

pub fn place_hold(
    config: &LadderConfig,
    state: &mut VigilState,
    now: Timestamp,
    until: Timestamp,
) -> Result<()> {
    if until <= now {
        return Err(Error::format("hold", "a hold must end in the future"));
    }
    let requested = until.since(now);
    if requested > config.max_hold {
        return Err(Error::format(
            "hold",
            format!(
                "requested hold of {} days exceeds the {} day maximum",
                requested / SECONDS_PER_DAY,
                config.max_hold / SECONDS_PER_DAY
            ),
        ));
    }
    state.hold_until = Some(until);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Timestamp = Timestamp(1_800_000_000);

    fn cfg() -> LadderConfig {
        LadderConfig::default()
    }

    fn day(n: u64) -> Timestamp {
        T0.plus_days(n)
    }

    fn confirm(state: &mut VigilState, index: u8, at: Timestamp) {
        state.record_response(TrusteeResponse {
            trustee_index: index,
            verdict: TrusteeVerdict::BelievesGone,
            at,
        });
    }

    #[test]
    fn the_default_config_is_valid() {
        cfg().validate().unwrap();
    }

    #[test]
    fn rejects_a_threshold_inside_the_grace_period() {
        let mut c = cfg();
        c.silence_threshold = c.checkin_interval;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_a_zero_countdown() {
        let mut c = cfg();
        c.countdown = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_reminders_that_arrive_too_late() {
        let mut c = cfg();
        c.reminder_offsets = vec![0, 100 * SECONDS_PER_DAY];
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_unordered_reminders() {
        let mut c = cfg();
        c.reminder_offsets = vec![5 * SECONDS_PER_DAY, SECONDS_PER_DAY];
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_single_missed_checkin_does_nothing() {
        let c = cfg();
        let state = VigilState::starting_at(T0);

        let stage = evaluate(&c, &state, 3, day(31), false);
        assert!(matches!(stage, Stage::Grace { .. }), "got {stage:?}");
        assert!(!stage.is_noisy(), "a single missed check-in must be silent");
        assert!(may_release(&c, &state, 3, day(31), false).is_err());
    }

    #[test]
    fn walks_the_whole_ladder_in_order() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);

        assert!(matches!(
            evaluate(&c, &state, 3, day(1), false),
            Stage::Held { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(29), false),
            Stage::Held { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(31), false),
            Stage::Grace { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(36), false),
            Stage::Grace { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(38), false),
            Stage::Escalating { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(46), false),
            Stage::AwaitingQuorum {
                have: 0,
                need: 3,
                ..
            }
        ));

        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        assert!(matches!(
            evaluate(&c, &state, 3, day(46), false),
            Stage::AwaitingQuorum {
                have: 2,
                need: 3,
                ..
            }
        ));

        confirm(&mut state, 3, day(47));
        state.quorum_met_at = Some(day(47));
        assert!(matches!(
            evaluate(&c, &state, 3, day(47), false),
            Stage::Countdown { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(49), false),
            Stage::Countdown { .. }
        ));
        assert_eq!(
            evaluate(&c, &state, 3, day(50), false),
            Stage::ReadyToRelease
        );
        may_release(&c, &state, 3, day(50), false).unwrap();
    }

    #[test]
    fn nothing_releases_early_at_any_point() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        confirm(&mut state, 3, day(46));
        state.quorum_met_at = Some(day(46));

        let release_at = day(46).plus_secs(c.countdown);
        let mut t = T0;
        while t < release_at {
            assert!(
                may_release(&c, &state, 3, t, false).is_err(),
                "released early at {} ({}s before the deadline)",
                t.0,
                release_at.since(t)
            );
            t = t.plus_secs(3600);
        }
        may_release(&c, &state, 3, release_at, false).unwrap();
    }

    #[test]
    fn a_checkin_resets_everything() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        confirm(&mut state, 3, day(46));
        state.quorum_met_at = Some(day(46));
        assert!(matches!(
            evaluate(&c, &state, 3, day(47), false),
            Stage::Countdown { .. }
        ));

        state.check_in(day(47), false);

        assert!(matches!(
            evaluate(&c, &state, 3, day(47), false),
            Stage::Held { .. }
        ));
        assert_eq!(
            state.confirmations(),
            0,
            "a check-in must clear the trustee poll"
        );
        assert!(state.quorum_met_at.is_none());
        assert!(may_release(&c, &state, 3, day(47), false).is_err());
    }

    #[test]
    fn cancelling_during_the_countdown_holds() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        confirm(&mut state, 3, day(46));
        state.quorum_met_at = Some(day(46));
        state.cancelled = true;

        for d in [47, 50, 100, 1000] {
            assert_eq!(evaluate(&c, &state, 3, day(d), false), Stage::Cancelled);
            assert!(may_release(&c, &state, 3, day(d), false).is_err());
        }
    }

    #[test]
    fn one_trustee_cannot_fake_a_quorum() {
        let mut state = VigilState::starting_at(T0);
        for _ in 0..5 {
            confirm(&mut state, 1, day(46));
        }
        assert_eq!(state.confirmations(), 1);
        assert!(matches!(
            evaluate(&cfg(), &state, 3, day(46), false),
            Stage::AwaitingQuorum {
                have: 1,
                need: 3,
                ..
            }
        ));
    }

    #[test]
    fn a_trustee_may_change_their_mind() {
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        assert_eq!(state.confirmations(), 1);

        state.record_response(TrusteeResponse {
            trustee_index: 1,
            verdict: TrusteeVerdict::BelievesPresent,
            at: day(47),
        });
        assert_eq!(state.confirmations(), 0);
        assert_eq!(state.vetoes(), 1);
    }

    #[test]
    fn no_response_counts_for_neither_side() {
        let mut state = VigilState::starting_at(T0);
        state.record_response(TrusteeResponse {
            trustee_index: 1,
            verdict: TrusteeVerdict::NoResponse,
            at: day(46),
        });
        assert_eq!(state.confirmations(), 0);
        assert_eq!(state.vetoes(), 0);
    }

    #[test]
    fn a_veto_extends_the_threshold() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        state.record_response(TrusteeResponse {
            trustee_index: 1,
            verdict: TrusteeVerdict::BelievesPresent,
            at: day(46),
        });

        assert!(matches!(
            evaluate(&c, &state, 3, day(46), false),
            Stage::Escalating { .. }
        ));
        assert!(matches!(
            evaluate(&c, &state, 3, day(76), false),
            Stage::AwaitingQuorum { .. }
        ));
    }

    #[test]
    fn vetoes_run_out() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        for i in 1..=10u8 {
            state.record_response(TrusteeResponse {
                trustee_index: i,
                verdict: TrusteeVerdict::BelievesPresent,
                at: day(46),
            });
        }
        assert_eq!(state.vetoes(), 10);

        let capped = c.effective_silence_threshold(10);
        assert_eq!(capped, c.effective_silence_threshold(c.max_vetoes));
        assert_eq!(
            capped,
            c.silence_threshold + c.max_vetoes as u64 * c.veto_extension
        );

        let past_cap = T0.plus_secs(capped + 1);
        assert!(matches!(
            evaluate(&c, &state, 3, past_cap, false),
            Stage::AwaitingQuorum { .. }
        ));
    }

    #[test]
    fn a_hold_suspends_the_ladder_then_expires() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        place_hold(&c, &mut state, T0, day(60)).unwrap();

        assert!(matches!(
            evaluate(&c, &state, 3, day(50), false),
            Stage::OnHold { .. }
        ));
        assert!(may_release(&c, &state, 3, day(50), false).is_err());

        assert!(matches!(
            evaluate(&c, &state, 3, day(61), false),
            Stage::AwaitingQuorum { .. }
        ));
    }

    #[test]
    fn a_hold_cannot_exceed_the_maximum() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        assert!(place_hold(&c, &mut state, T0, day(365)).is_err());
        assert!(
            state.hold_until.is_none(),
            "a rejected hold must not be applied"
        );
        place_hold(&c, &mut state, T0, day(89)).unwrap();
    }

    #[test]
    fn a_hold_must_end_in_the_future() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        assert!(place_hold(&c, &mut state, day(10), day(5)).is_err());
        assert!(place_hold(&c, &mut state, day(10), day(10)).is_err());
    }

    #[test]
    fn a_frozen_clock_stops_the_ladder() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        confirm(&mut state, 3, day(46));
        state.quorum_met_at = Some(day(46));

        assert_eq!(evaluate(&c, &state, 3, day(1000), true), Stage::Frozen);
        let err = may_release(&c, &state, 3, day(1000), true).unwrap_err();
        assert!(matches!(
            err,
            Error::ReleaseRefused(ReleaseRefusal::VigilFrozen)
        ));
    }

    #[test]
    fn a_rehearsal_never_releases() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        state.is_rehearsal = true;
        confirm(&mut state, 1, day(46));
        confirm(&mut state, 2, day(46));
        confirm(&mut state, 3, day(46));
        state.quorum_met_at = Some(day(46));

        assert_eq!(
            evaluate(&c, &state, 3, day(100), false),
            Stage::ReadyToRelease
        );
        assert!(matches!(
            may_release(&c, &state, 3, day(100), false).unwrap_err(),
            Error::ReleaseRefused(ReleaseRefusal::RehearsalOnly)
        ));
    }

    #[test]
    fn a_gate_without_trustees_still_counts_down() {
        let c = cfg();
        let state = VigilState::starting_at(T0);

        assert!(matches!(
            evaluate(&c, &state, 0, day(46), false),
            Stage::Countdown { .. }
        ));
        assert!(may_release(&c, &state, 0, day(46), false).is_err());

        let release_at = T0.plus_secs(c.silence_threshold + c.countdown);
        assert_eq!(
            evaluate(&c, &state, 0, release_at, false),
            Stage::ReadyToRelease
        );
    }

    #[test]
    fn a_duress_checkin_behaves_exactly_like_a_normal_one() {
        let c = cfg();
        let mut normal = VigilState::starting_at(T0);
        let mut duress = VigilState::starting_at(T0);

        normal.check_in(day(10), false);
        duress.check_in(day(10), true);

        assert_eq!(
            evaluate(&c, &normal, 3, day(20), false),
            evaluate(&c, &duress, 3, day(20), false),
            "a coercer watching the screen must see no difference"
        );
        assert!(duress.duress_flagged);
        assert!(!normal.duress_flagged);
    }

    #[test]
    fn released_is_terminal() {
        let c = cfg();
        let mut state = VigilState::starting_at(T0);
        state.released_at = Some(day(50));
        assert_eq!(
            evaluate(&c, &state, 3, day(1000), false),
            Stage::Released { at: day(50) }
        );
    }

    #[test]
    fn quiet_stages_send_nothing() {
        let c = cfg();
        let state = VigilState::starting_at(T0);
        assert!(!evaluate(&c, &state, 3, day(1), false).is_noisy());
        assert!(!evaluate(&c, &state, 3, day(31), false).is_noisy());
        assert!(evaluate(&c, &state, 3, day(40), false).is_noisy());
    }

    #[test]
    fn reminders_accumulate_on_schedule() {
        let c = cfg();
        let state = VigilState::starting_at(T0);
        let grace_end = c.grace_ends(T0);

        let mut last = 0;
        for offset in [0u64, 2, 4, 7] {
            let at = grace_end.plus_days(offset);
            match evaluate(&c, &state, 3, at, false) {
                Stage::Escalating { reminders_due, .. } => {
                    assert!(
                        reminders_due > last,
                        "reminder count did not advance by day {offset}"
                    );
                    last = reminders_due;
                }
                other => panic!("expected Escalating at offset {offset}, got {other:?}"),
            }
        }
        assert_eq!(last, 4, "all four reminders should have fired");
    }

    #[test]
    fn every_stage_has_a_summary() {
        for stage in [
            Stage::Held { next_due: T0 },
            Stage::Grace { grace_ends: T0 },
            Stage::Escalating {
                reminders_due: 1,
                next_reminder: None,
                trustees_polled_at: T0,
            },
            Stage::AwaitingQuorum {
                have: 1,
                need: 3,
                vetoes: 0,
            },
            Stage::Countdown { releases_at: T0 },
            Stage::ReadyToRelease,
            Stage::Released { at: T0 },
            Stage::Cancelled,
            Stage::OnHold { until: T0 },
            Stage::Frozen,
        ] {
            assert!(!stage.summary().is_empty());
        }
    }

    #[test]
    fn state_survives_json() {
        let mut state = VigilState::starting_at(T0);
        confirm(&mut state, 1, day(46));
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<VigilState>(&json).unwrap(), state);
    }
}
