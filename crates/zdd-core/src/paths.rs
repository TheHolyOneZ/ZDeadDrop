const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub fn component(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '-',
            c => c,
        })
        .collect();

    let trimmed = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    let stem = trimmed.split('.').next().unwrap_or("").trim_end();
    let mut out: String = if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(stem)) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    };

    if out.chars().count() > 120 {
        out = out.chars().take(120).collect();
        out = out
            .trim_end_matches(|c: char| c == '.' || c.is_whitespace())
            .to_string();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_device_names_are_defused() {
        assert_eq!(component("CON").as_deref(), Some("_CON"));
        assert_eq!(component("nul.txt").as_deref(), Some("_nul.txt"));
        assert_eq!(component("com1 .log").as_deref(), Some("_com1 .log"));
        assert_eq!(component("console").as_deref(), Some("console"));
    }

    #[test]
    fn forbidden_characters_and_trailing_dots_go() {
        assert_eq!(component("a:b?c").as_deref(), Some("a-b-c"));
        assert_eq!(component("letter. ").as_deref(), Some("letter"));
        assert_eq!(component(" ..."), None);
        assert_eq!(component("..").as_deref(), None);
    }

    #[test]
    fn long_names_are_shortened() {
        let long = "x".repeat(300);
        assert_eq!(component(&long).unwrap().chars().count(), 120);
    }
}
