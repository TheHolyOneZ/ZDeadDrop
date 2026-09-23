use owo_colors::OwoColorize;
use zdd_core::secret::SecretBytes;

pub fn colour() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::IsTerminal::is_terminal(&std::io::stdout())
}

pub fn heading(text: &str) {
    if colour() {
        println!("\n{}", text.bold());
    } else {
        println!("\n{text}");
    }
}

pub fn field(label: &str, value: &str) {
    if colour() {
        println!("  {:<16} {}", label.dimmed(), value);
    } else {
        println!("  {label:<16} {value}");
    }
}

pub fn note(text: &str) {
    if colour() {
        println!("  {}", text.dimmed());
    } else {
        println!("  {text}");
    }
}

pub fn good(text: &str) {
    if colour() {
        println!("{} {}", "✓".green(), text);
    } else {
        println!("OK  {text}");
    }
}

pub fn warn(text: &str) {
    if colour() {
        eprintln!("{} {}", "!".yellow(), text);
    } else {
        eprintln!("WARN  {text}");
    }
}

pub fn bad(text: &str) {
    if colour() {
        eprintln!("{} {}", "✗".red(), text);
    } else {
        eprintln!("ERROR  {text}");
    }
}

pub fn passphrase(prompt: &str) -> anyhow::Result<SecretBytes> {
    if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let text = rpassword::prompt_password(format!("{prompt}: "))?;
        Ok(SecretBytes::from_string(text))
    } else {
        warn("reading the passphrase from stdin; it will not be hidden");
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;

        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }
        Ok(SecretBytes::from_string(line))
    }
}

pub fn confirm(question: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;

    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn duration(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 3600;
    const DAY: u64 = 86_400;

    match secs {
        s if s < MINUTE => format!("{s} seconds"),
        s if s < HOUR => plural(s / MINUTE, "minute"),
        s if s < DAY => plural(s / HOUR, "hour"),
        s => plural(s / DAY, "day"),
    }
}

fn plural(n: u64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 1;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{:.0} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(duration(30), "30 seconds");
        assert_eq!(duration(60), "1 minute");
        assert_eq!(duration(120), "2 minutes");
        assert_eq!(duration(3600), "1 hour");
        assert_eq!(duration(7200), "2 hours");
        assert_eq!(duration(86_400), "1 day");
        assert_eq!(duration(45 * 86_400), "45 days");
    }

    #[test]
    fn byte_counts_read_naturally() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(1024), "1.0 KB");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(20 * 1024), "20 KB");
        assert_eq!(bytes(412_000_000), "393 MB");
    }

    #[test]
    fn plurals_are_correct() {
        assert!(!duration(86_400).contains("days"));
        assert!(duration(2 * 86_400).contains("days"));
        assert!(!duration(3600).contains("hours"));
    }
}
