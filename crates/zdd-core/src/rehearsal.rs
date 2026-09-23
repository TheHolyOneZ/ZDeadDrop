use crate::clock::{Clock, Timestamp, VirtualClock, SECONDS_PER_DAY};
use crate::policy::{self, LadderConfig, Stage, TrusteeResponse, TrusteeVerdict, VigilState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrusteeBehaviour {
    AllConfirm,

    SomeConfirm {
        count: u8,
        after_days: u64,
    },

    SomeVeto {
        vetoes: u8,
        confirms: u8,
        after_days: u64,
    },

    Silent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Happening {
    CheckInDue,
    GraceEnded,
    ReminderSent { number: usize },
    TrusteesPolled,
    TrusteeAnswered { index: u8, verdict: TrusteeVerdict },
    QuorumReached { have: u8, need: u8 },
    CountdownStarted { releases_at: Timestamp },
    Released,
}

impl Happening {
    pub fn describe(&self) -> String {
        match self {
            Happening::CheckInDue => "Your check-in falls due. Nothing is sent.".into(),
            Happening::GraceEnded => {
                "The grace period ends. From here, you start hearing from us.".into()
            }
            Happening::ReminderSent { number } => {
                format!("Reminder {number} goes out, with a one-tap \"I'm here\" link.")
            }
            Happening::TrusteesPolled => {
                "Your trustees are asked, for the first time, whether you are reachable.".into()
            }
            Happening::TrusteeAnswered { index, verdict } => match verdict {
                TrusteeVerdict::BelievesGone => {
                    format!("Trustee {index} answers: they believe you are gone.")
                }
                TrusteeVerdict::BelievesPresent => {
                    format!("Trustee {index} answers: they believe you are fine. This postpones the release.")
                }
                TrusteeVerdict::NoResponse => format!("Trustee {index} does not reply."),
            },
            Happening::QuorumReached { have, need } => {
                format!(
                    "The quorum is met: {have} {} agree, and {need} {} needed. The final countdown begins.",
                    if *have == 1 { "trustee" } else { "trustees" },
                    if *need == 1 { "was" } else { "were" },
                )
            }
            Happening::CountdownStarted { .. } => {
                "You can still cancel from any device that holds your key.".into()
            }
            Happening::Released => "The capsule is released to its recipient.".into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Moment {
    pub day: u64,
    pub at: Timestamp,
    pub stage: Stage,
    pub happenings: Vec<Happening>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Concern {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Blocking,

    Warning,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub timeline: Vec<Moment>,

    pub released_on: Option<u64>,
    pub concerns: Vec<Concern>,

    pub days_simulated: u64,
}

impl Report {
    pub fn would_release(&self) -> bool {
        self.released_on.is_some()
    }

    pub fn is_blocked(&self) -> bool {
        self.concerns
            .iter()
            .any(|c| c.severity == Severity::Blocking)
    }

    pub fn verdict(&self) -> String {
        match self.released_on {
            Some(day) => format!(
                "This capsule would reach its recipient {day} days after your last check-in."
            ),
            None => {
                "This capsule would NEVER reach its recipient under these conditions.".to_string()
            }
        }
    }
}

pub fn run(
    config: &LadderConfig,
    quorum_needed: u8,
    trustee_total: u8,
    behaviour: &TrusteeBehaviour,
    horizon_days: u64,
) -> Report {
    let start = Timestamp(0);
    let clock = VirtualClock::starting_at(start);
    let mut state = VigilState::starting_at(start);

    let mut timeline = Vec::new();
    let mut released_on = None;
    let mut reminders_seen = 0usize;
    let mut polled = false;
    let mut counted_down = false;
    let mut answered = false;

    let reminder_times = config.reminder_times(start);

    for day in 1..=horizon_days {
        clock.advance_days(1);
        let now = clock.now();

        let mut happenings = Vec::new();
        let stage = policy::evaluate(config, &state, quorum_needed, now, false);

        let silence = now.since(state.last_checkin);
        if silence >= config.checkin_interval && silence - SECONDS_PER_DAY < config.checkin_interval
        {
            happenings.push(Happening::CheckInDue);
        }
        let grace_at = config.checkin_interval + config.grace;
        if silence >= grace_at && silence - SECONDS_PER_DAY < grace_at {
            happenings.push(Happening::GraceEnded);
        }

        let due_now = reminder_times.iter().filter(|t| **t <= now).count();
        while reminders_seen < due_now {
            reminders_seen += 1;
            happenings.push(Happening::ReminderSent {
                number: reminders_seen,
            });
        }

        if matches!(stage, Stage::AwaitingQuorum { .. }) && !polled {
            polled = true;
            happenings.push(Happening::TrusteesPolled);

            if quorum_needed == 0 {}
        }

        if polled && !answered && behaviour != &TrusteeBehaviour::Silent {
            let when =
                first_poll_day(config, quorum_needed).saturating_add(behaviour_delay(behaviour));
            if day >= when {
                answered = true;
                for (index, verdict) in answers(behaviour, trustee_total) {
                    state.record_response(TrusteeResponse {
                        trustee_index: index,
                        verdict,
                        at: now,
                    });
                    happenings.push(Happening::TrusteeAnswered { index, verdict });
                }
                if state.confirmations() >= quorum_needed && quorum_needed > 0 {
                    state.quorum_met_at = Some(now);
                    happenings.push(Happening::QuorumReached {
                        have: state.confirmations(),
                        need: quorum_needed,
                    });
                }
            }
        }

        let stage = policy::evaluate(config, &state, quorum_needed, now, false);

        if let Stage::Countdown { releases_at } = stage {
            if !counted_down {
                counted_down = true;
                happenings.push(Happening::CountdownStarted { releases_at });
            }
        }

        if stage == Stage::ReadyToRelease && released_on.is_none() {
            released_on = Some(day);
            happenings.push(Happening::Released);
        }

        if !happenings.is_empty() {
            timeline.push(Moment {
                day,
                at: now,
                stage: stage.clone(),
                happenings,
            });
        }

        if released_on.is_some() {
            break;
        }
    }

    let days_simulated = released_on.unwrap_or(horizon_days);
    let concerns = assess(
        config,
        quorum_needed,
        trustee_total,
        behaviour,
        &released_on,
        horizon_days,
    );

    Report {
        timeline,
        released_on,
        concerns,
        days_simulated,
    }
}

fn first_poll_day(config: &LadderConfig, quorum_needed: u8) -> u64 {
    if quorum_needed == 0 {
        return u64::MAX;
    }
    config.silence_threshold / SECONDS_PER_DAY
}

fn behaviour_delay(behaviour: &TrusteeBehaviour) -> u64 {
    match behaviour {
        TrusteeBehaviour::AllConfirm => 1,
        TrusteeBehaviour::SomeConfirm { after_days, .. } => *after_days,
        TrusteeBehaviour::SomeVeto { after_days, .. } => *after_days,
        TrusteeBehaviour::Silent => 0,
    }
}

fn answers(behaviour: &TrusteeBehaviour, total: u8) -> Vec<(u8, TrusteeVerdict)> {
    match behaviour {
        TrusteeBehaviour::AllConfirm => (1..=total)
            .map(|i| (i, TrusteeVerdict::BelievesGone))
            .collect(),
        TrusteeBehaviour::SomeConfirm { count, .. } => (1..=(*count).min(total))
            .map(|i| (i, TrusteeVerdict::BelievesGone))
            .collect(),
        TrusteeBehaviour::SomeVeto {
            vetoes, confirms, ..
        } => {
            let mut out: Vec<(u8, TrusteeVerdict)> = (1..=(*vetoes).min(total))
                .map(|i| (i, TrusteeVerdict::BelievesPresent))
                .collect();
            let start = vetoes.saturating_add(1);
            for i in start..=start.saturating_add(confirms.saturating_sub(1)).min(total) {
                out.push((i, TrusteeVerdict::BelievesGone));
            }
            out
        }
        TrusteeBehaviour::Silent => Vec::new(),
    }
}

fn assess(
    config: &LadderConfig,
    quorum_needed: u8,
    trustee_total: u8,
    behaviour: &TrusteeBehaviour,
    released_on: &Option<u64>,
    horizon_days: u64,
) -> Vec<Concern> {
    let mut concerns = Vec::new();

    if released_on.is_none() {
        let (title, detail) = match behaviour {
            TrusteeBehaviour::Silent => (
                "Nothing would ever be released".to_string(),
                format!(
                    "None of your {trustee_total} trustees answered, so the quorum of \
                     {quorum_needed} was never met. If your trustees are unreachable when it \
                     matters, this capsule stays sealed forever. Ping them now and see who \
                     replies."
                ),
            ),
            TrusteeBehaviour::SomeConfirm { count, .. } if *count < quorum_needed => (
                "Not enough trustees would answer".to_string(),
                format!(
                    "Only {count} of your {trustee_total} trustees replied, and this capsule \
                     needs {quorum_needed}. Either lower the quorum or add trustees you are \
                     confident will respond."
                ),
            ),
            _ => (
                "Nothing would be released within the rehearsal window".to_string(),
                format!(
                    "The simulation ran for {horizon_days} days without a release. The \
                     thresholds may be longer than you intended."
                ),
            ),
        };
        concerns.push(Concern {
            severity: Severity::Blocking,
            title,
            detail,
        });
    }

    if quorum_needed > 0 && quorum_needed == trustee_total {
        concerns.push(Concern {
            severity: Severity::Warning,
            title: "Every single trustee must answer".to_string(),
            detail: format!(
                "You need all {trustee_total} of {trustee_total}. One trustee who has moved \
                 house, changed email, or simply died before you means this capsule can never \
                 open. Leave yourself some slack."
            ),
        });
    }

    if quorum_needed == 0 {
        concerns.push(Concern {
            severity: Severity::Warning,
            title: "No trustees are involved".to_string(),
            detail: "This capsule releases on silence alone, so whoever runs the relay can \
                     open it by declaring you gone. Adding trustees means no single party \
                     can act."
                .to_string(),
        });
    }

    if let TrusteeBehaviour::SomeVeto { .. } = behaviour {
        concerns.push(Concern {
            severity: Severity::Warning,
            title: "A trustee who believes you are fine delays the release".to_string(),
            detail: format!(
                "Each veto pushes the threshold out by {} days, up to {} of them. This is \
                 deliberate — it is how a trustee says \"he is hiking, give it a month\" — \
                 but it means a mistaken trustee can add months.",
                config.veto_extension / SECONDS_PER_DAY,
                config.max_vetoes
            ),
        });
    }

    if config.countdown < SECONDS_PER_DAY {
        concerns.push(Concern {
            severity: Severity::Warning,
            title: "Your final countdown is under a day".to_string(),
            detail: "The countdown is your last chance to cancel if you are alive after all. \
                     Under a day gives you very little room to notice."
                .to_string(),
        });
    }

    concerns.sort_by_key(|c| c.severity);
    concerns
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LadderConfig {
        LadderConfig::default()
    }

    #[test]
    fn the_happy_path_releases_and_the_timeline_reads_in_order() {
        let report = run(&cfg(), 3, 5, &TrusteeBehaviour::AllConfirm, 200);

        assert!(report.would_release(), "{}", report.verdict());
        assert!(!report.is_blocked());

        let flat: Vec<&Happening> = report
            .timeline
            .iter()
            .flat_map(|m| m.happenings.iter())
            .collect();

        let position = |pred: fn(&Happening) -> bool| flat.iter().position(|h| pred(h));
        let due = position(|h| matches!(h, Happening::CheckInDue)).unwrap();
        let grace = position(|h| matches!(h, Happening::GraceEnded)).unwrap();
        let reminder = position(|h| matches!(h, Happening::ReminderSent { .. })).unwrap();
        let polled = position(|h| matches!(h, Happening::TrusteesPolled)).unwrap();
        let quorum = position(|h| matches!(h, Happening::QuorumReached { .. })).unwrap();
        let released = position(|h| matches!(h, Happening::Released)).unwrap();

        assert!(due < grace, "the check-in falls due before grace ends");
        assert!(grace <= reminder, "no reminder before grace ends");
        assert!(
            reminder < polled,
            "trustees must not be asked before the owner is"
        );
        assert!(polled < quorum);
        assert!(quorum < released);
    }

    #[test]
    fn silent_trustees_mean_nothing_is_ever_released() {
        let report = run(&cfg(), 3, 5, &TrusteeBehaviour::Silent, 400);

        assert!(!report.would_release());
        assert!(report.is_blocked());
        assert!(report.verdict().contains("NEVER"));

        let blocking = report
            .concerns
            .iter()
            .find(|c| c.severity == Severity::Blocking)
            .unwrap();
        assert!(blocking.detail.contains("stays sealed forever"));

        assert!(blocking.detail.contains("Ping them now"));
    }

    #[test]
    fn too_few_trustees_answering_is_reported_with_the_numbers() {
        let report = run(
            &cfg(),
            3,
            5,
            &TrusteeBehaviour::SomeConfirm {
                count: 2,
                after_days: 2,
            },
            400,
        );

        assert!(!report.would_release());
        let blocking = report
            .concerns
            .iter()
            .find(|c| c.severity == Severity::Blocking)
            .unwrap();
        assert!(blocking.detail.contains("Only 2"), "{}", blocking.detail);
        assert!(blocking.detail.contains("needs 3"), "{}", blocking.detail);
    }

    #[test]
    fn exactly_enough_trustees_does_release() {
        let report = run(
            &cfg(),
            3,
            5,
            &TrusteeBehaviour::SomeConfirm {
                count: 3,
                after_days: 2,
            },
            400,
        );
        assert!(report.would_release(), "{}", report.verdict());
    }

    #[test]
    fn a_veto_delays_the_release_rather_than_stopping_it() {
        let prompt = run(&cfg(), 3, 5, &TrusteeBehaviour::AllConfirm, 400);
        let vetoed = run(
            &cfg(),
            3,
            5,
            &TrusteeBehaviour::SomeVeto {
                vetoes: 1,
                confirms: 3,
                after_days: 2,
            },
            400,
        );

        assert!(
            vetoed.would_release(),
            "a single veto must not block forever"
        );
        assert!(
            vetoed.released_on.unwrap() > prompt.released_on.unwrap(),
            "a veto should push the release later"
        );
        assert!(vetoed
            .concerns
            .iter()
            .any(|c| c.title.contains("believes you are fine")));
    }

    #[test]
    fn needing_every_trustee_is_flagged() {
        let report = run(&cfg(), 5, 5, &TrusteeBehaviour::AllConfirm, 400);
        assert!(report.would_release());
        assert!(
            report
                .concerns
                .iter()
                .any(|c| c.title.contains("Every single trustee")),
            "a 5-of-5 quorum must be called out"
        );
    }

    #[test]
    fn a_capsule_with_no_trustees_releases_but_is_flagged() {
        let report = run(&cfg(), 0, 0, &TrusteeBehaviour::Silent, 400);
        assert!(
            report.would_release(),
            "a relay-only gate releases on silence alone"
        );
        assert!(report
            .concerns
            .iter()
            .any(|c| c.title.contains("No trustees")));
    }

    #[test]
    fn a_very_short_countdown_is_flagged() {
        let mut config = cfg();
        config.countdown = 3600;
        let report = run(&config, 3, 5, &TrusteeBehaviour::AllConfirm, 400);
        assert!(report
            .concerns
            .iter()
            .any(|c| c.title.contains("under a day")));
    }

    #[test]
    fn the_release_day_matches_the_configuration() {
        let config = cfg();
        let report = run(&config, 3, 5, &TrusteeBehaviour::AllConfirm, 400);

        let earliest = (config.silence_threshold + config.countdown) / SECONDS_PER_DAY;
        let released = report.released_on.unwrap();
        assert!(
            released >= earliest,
            "released on day {released}, before the configured earliest of {earliest}"
        );

        assert!(
            released <= earliest + 5,
            "released on day {released}, far later than expected"
        );
    }

    #[test]
    fn every_happening_has_a_sentence() {
        let report = run(&cfg(), 3, 5, &TrusteeBehaviour::AllConfirm, 400);
        for moment in &report.timeline {
            for happening in &moment.happenings {
                let text = happening.describe();
                assert!(!text.is_empty());

                assert!(
                    text.chars().next().unwrap().is_uppercase(),
                    "not a sentence: {text}"
                );
            }
        }
    }

    #[test]
    fn the_simulation_stops_at_the_horizon() {
        let report = run(&cfg(), 3, 5, &TrusteeBehaviour::Silent, 90);
        assert_eq!(report.days_simulated, 90);
        assert!(!report.would_release());
    }

    #[test]
    fn a_rehearsal_reports_the_same_ladder_a_real_release_would_walk() {
        let config = cfg();
        let report = run(&config, 3, 5, &TrusteeBehaviour::AllConfirm, 400);

        for moment in &report.timeline {
            assert!(!moment.stage.summary().is_empty());
        }
        assert!(report
            .timeline
            .iter()
            .any(|m| matches!(m.stage, Stage::Countdown { .. })));
    }

    #[test]
    fn concerns_are_ordered_worst_first() {
        let report = run(&cfg(), 5, 5, &TrusteeBehaviour::Silent, 400);
        assert!(report.concerns.len() >= 2);
        assert_eq!(report.concerns[0].severity, Severity::Blocking);
    }
}
