use anyhow::Result;
use clap::Args as ClapArgs;

use zdd_core::clock::SECONDS_PER_DAY;
use zdd_core::policy::LadderConfig;
use zdd_core::rehearsal::{self, Severity, TrusteeBehaviour};

use crate::term;

#[derive(ClapArgs)]
pub struct Args {
    #[doc = " How many trustees must agree."]
    #[arg(long, default_value_t = 3)]
    quorum: u8,

    #[doc = " How many trustees there are."]
    #[arg(long, default_value_t = 5)]
    trustees: u8,

    #[doc = " Days of silence before your trustees are asked."]
    #[arg(long, default_value_t = 45)]
    silence: u64,

    #[doc = " Hours of final countdown once the quorum is met."]
    #[arg(long, default_value_t = 72)]
    countdown: u64,

    #[doc = " What your trustees do."]
    #[arg(long, value_enum, default_value = "all-answer")]
    trustees_behave: Behaviour,

    #[doc = " How many trustees answer, for --trustees-behave some-answer."]
    #[arg(long, default_value_t = 2)]
    answering: u8,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Behaviour {
    #[doc = " Everyone answers, and agrees."]
    AllAnswer,
    #[doc = " Only some answer. The rest never reply."]
    SomeAnswer,
    #[doc = " One is certain you are fine; the rest agree you are gone."]
    OneVetoes,
    #[doc = " Nobody answers at all."]
    NobodyAnswers,
}

pub fn run(args: Args) -> Result<()> {
    let mut config = LadderConfig {
        silence_threshold: args.silence * SECONDS_PER_DAY,
        countdown: args.countdown * 3600,
        ..LadderConfig::default()
    };

    let window = config
        .silence_threshold
        .saturating_sub(config.checkin_interval + config.grace);
    if window > 0 {
        config.reminder_offsets = (1..=4).map(|i| window * i / 5).collect();
    } else {
        config.reminder_offsets.clear();
    }

    if let Err(e) = config.validate() {
        term::bad("Those settings do not make a workable ladder.");
        term::note(&format!("{e}"));
        anyhow::bail!("nothing was simulated");
    }

    let behaviour = match args.trustees_behave {
        Behaviour::AllAnswer => TrusteeBehaviour::AllConfirm,
        Behaviour::SomeAnswer => TrusteeBehaviour::SomeConfirm {
            count: args.answering,
            after_days: 2,
        },
        Behaviour::OneVetoes => TrusteeBehaviour::SomeVeto {
            vetoes: 1,
            confirms: args.trustees.saturating_sub(1),
            after_days: 2,
        },
        Behaviour::NobodyAnswers => TrusteeBehaviour::Silent,
    };

    term::heading("Rehearsal");
    term::note("Nothing below is real. No message is sent, no capsule is touched.");
    term::note("This is what would happen if you stopped checking in today.");

    let report = rehearsal::run(&config, args.quorum, args.trustees, &behaviour, 720);

    term::heading("What would happen");
    for moment in &report.timeline {
        for happening in &moment.happenings {
            println!(
                "  {:>4}   {}",
                format!("d{}", moment.day),
                happening.describe()
            );
        }
    }

    println!();
    if report.would_release() {
        term::good(&report.verdict());
    } else {
        term::bad(&report.verdict());
    }

    if report.concerns.is_empty() {
        println!();
        term::good("Nothing about this configuration would stop it working.");
        return Ok(());
    }

    term::heading("What to fix");
    for concern in &report.concerns {
        println!();
        match concern.severity {
            Severity::Blocking => term::bad(&concern.title),
            Severity::Warning => term::warn(&concern.title),
        }
        for line in wrap(&concern.detail, 76) {
            term::note(&format!("  {line}"));
        }
    }

    println!();
    term::note("Run this again after changing anything. It costs nothing, and it is the only");
    term::note("way to find out your setup is wrong while you can still do something about it.");

    if report.is_blocked() {
        anyhow::bail!("this configuration would not deliver");
    }
    Ok(())
}

fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_respects_the_width_and_loses_nothing() {
        let text = "The quick brown fox jumps over the lazy dog and keeps on running";
        let lines = wrap(text, 20);
        assert!(lines.iter().all(|l| l.len() <= 20), "{lines:?}");
        assert_eq!(lines.join(" "), text);
    }

    #[test]
    fn wrapping_handles_a_word_longer_than_the_width() {
        let lines = wrap("supercalifragilistic and more", 10);
        assert_eq!(lines[0], "supercalifragilistic");
        assert_eq!(lines.join(" "), "supercalifragilistic and more");
    }

    #[test]
    fn wrapping_an_empty_string_yields_nothing() {
        assert!(wrap("", 20).is_empty());
    }
}
