use std::path::Path;

use crate::error::{ImportError, Result};
use crate::secrets::{Secret, SecretKind};

#[derive(Debug)]
pub struct Import {
    pub entries: Vec<Secret>,

    pub format: &'static str,

    pub source_is_plaintext: bool,

    pub skipped: Vec<String>,
}

pub fn detect(path: &Path) -> Result<&'static str> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name.ends_with(".kdbx") {
        return Ok("keepass");
    }
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return Ok("dotenv");
    }

    let head = read_head(path, 512)?;
    let text = String::from_utf8_lossy(&head);

    if head.starts_with(&[0x03, 0xD9, 0xA2, 0x9A]) {
        return Ok("keepass");
    }
    if text.trim_start().starts_with('{') {
        if text.contains("\"encrypted\"")
            || text.contains("\"folders\"")
            || text.contains("\"items\"")
        {
            return Ok("bitwarden");
        }
        return Ok("json");
    }

    if text.starts_with("name,url,username,password") || text.starts_with("url,username,password") {
        return Ok("browser-csv");
    }
    if name.ends_with(".csv") {
        return Ok("browser-csv");
    }

    Err(ImportError::Unrecognised(path.display().to_string()))
}

fn read_head(path: &Path, n: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).map_err(|e| ImportError::io(path.display(), e))?;
    let mut buf = vec![0u8; n];
    let read = file
        .read(&mut buf)
        .map_err(|e| ImportError::io(path.display(), e))?;
    buf.truncate(read);
    Ok(buf)
}

pub fn keepass(path: &Path, password: &str) -> Result<Import> {
    use keepass::{Database, DatabaseKey};

    let mut file = std::fs::File::open(path).map_err(|e| ImportError::io(path.display(), e))?;
    let key = DatabaseKey::new().with_password(password);

    let db = Database::open(&mut file, key).map_err(|e| {
        let text = e.to_string();
        if text.to_lowercase().contains("key") || text.to_lowercase().contains("hmac") {
            ImportError::NeedsPassword(path.display().to_string())
        } else {
            ImportError::Parse(format!("could not read that KeePass database: {text}"))
        }
    })?;

    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    for entry in db.iter_all_entries() {
        let title = entry.get_title().unwrap_or("(untitled)").to_string();
        let Some(password) = entry.get_password() else {
            skipped.push(format!("{title}: no password field"));
            continue;
        };

        let mut secret = Secret::new(SecretKind::Credential, title, password.as_bytes().to_vec());
        if let Some(user) = entry.get_username() {
            secret = secret.with_context("username", user);
        }
        if let Some(url) = entry.get_url() {
            secret = secret.with_context("url", url);
        }
        entries.push(secret);
    }

    Ok(Import {
        entries,
        format: "KeePass",
        source_is_plaintext: false,
        skipped,
    })
}

pub fn bitwarden(path: &Path) -> Result<Import> {
    let text = std::fs::read_to_string(path).map_err(|e| ImportError::io(path.display(), e))?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| ImportError::Parse(e.to_string()))?;

    if doc
        .get("encrypted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(ImportError::NeedsPassword(path.display().to_string()));
    }

    let items = doc
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ImportError::Parse("that file has no items array".into()))?;

    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    for item in items {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(untitled)")
            .to_string();

        if let Some(login) = item.get("login") {
            let password = login.get("password").and_then(|v| v.as_str());
            let totp = login.get("totp").and_then(|v| v.as_str());

            if let Some(password) = password {
                let mut secret = Secret::new(
                    SecretKind::Credential,
                    name.clone(),
                    password.as_bytes().to_vec(),
                );
                if let Some(user) = login.get("username").and_then(|v| v.as_str()) {
                    secret = secret.with_context("username", user);
                }
                entries.push(secret);
            }

            if let Some(totp) = totp.filter(|t| !t.is_empty()) {
                match crate::secrets::totp(totp) {
                    Ok(seed) => entries.push(seed),
                    Err(_) => skipped.push(format!("{name}: its 2FA seed could not be read")),
                }
            }

            if password.is_none() && totp.is_none() {
                skipped.push(format!("{name}: no password or 2FA seed"));
            }
        } else if let Some(note) = item.get("notes").and_then(|v| v.as_str()) {
            entries.push(Secret::new(
                SecretKind::Note,
                name,
                note.as_bytes().to_vec(),
            ));
        } else {
            skipped.push(format!("{name}: nothing importable"));
        }
    }

    Ok(Import {
        entries,
        format: "Bitwarden",
        source_is_plaintext: true,
        skipped,
    })
}

pub fn browser_csv(path: &Path) -> Result<Import> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .map_err(|e| ImportError::Parse(e.to_string()))?;

    let headers = reader
        .headers()
        .map_err(|e| ImportError::Parse(e.to_string()))?
        .clone();

    let column = |names: &[&str]| -> Option<usize> {
        headers.iter().position(|h| {
            let h = h.trim().to_lowercase();
            names.iter().any(|n| h == *n)
        })
    };

    let name_col = column(&["name", "title"]);
    let url_col = column(&["url", "origin_url", "website"]);
    let user_col = column(&["username", "login", "user"]);
    let pass_col = column(&["password"]).ok_or_else(|| {
        ImportError::Parse("that CSV has no password column, so there is nothing to import".into())
    })?;

    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    for (row_number, record) in reader.records().enumerate() {
        let record = match record {
            Ok(r) => r,
            Err(e) => {
                skipped.push(format!("row {}: {e}", row_number + 2));
                continue;
            }
        };

        let Some(password) = record.get(pass_col).filter(|p| !p.is_empty()) else {
            skipped.push(format!("row {}: no password", row_number + 2));
            continue;
        };

        let label = name_col
            .and_then(|i| record.get(i))
            .filter(|s| !s.is_empty())
            .or_else(|| url_col.and_then(|i| record.get(i)))
            .unwrap_or("(untitled)")
            .to_string();

        let mut secret = Secret::new(SecretKind::Credential, label, password.as_bytes().to_vec());
        if let Some(user) = user_col
            .and_then(|i| record.get(i))
            .filter(|s| !s.is_empty())
        {
            secret = secret.with_context("username", user);
        }
        if let Some(url) = url_col
            .and_then(|i| record.get(i))
            .filter(|s| !s.is_empty())
        {
            secret = secret.with_context("url", url);
        }
        entries.push(secret);
    }

    Ok(Import {
        entries,
        format: "browser export",
        source_is_plaintext: true,
        skipped,
    })
}

pub fn dotenv(path: &Path) -> Result<Import> {
    let text = std::fs::read_to_string(path).map_err(|e| ImportError::io(path.display(), e))?;

    let mut entries = Vec::new();
    let mut skipped = Vec::new();

    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            skipped.push(format!("line {}: not a KEY=value pair", number + 1));
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);

        if value.is_empty() {
            skipped.push(format!("{key}: empty"));
            continue;
        }

        entries.push(Secret::new(
            SecretKind::Credential,
            key,
            value.as_bytes().to_vec(),
        ));
    }

    Ok(Import {
        entries,
        format: ".env file",
        source_is_plaintext: true,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p
    }

    #[test]
    fn formats_are_detected_by_content_not_just_extension() {
        let dir = tempfile::tempdir().unwrap();

        let bw = write(&dir, "export.txt", br#"{"encrypted":false,"items":[]}"#);
        assert_eq!(detect(&bw).unwrap(), "bitwarden");

        let csv = write(&dir, "passwords.txt", b"name,url,username,password\n");
        assert_eq!(detect(&csv).unwrap(), "browser-csv");

        let kdbx = write(&dir, "notes.txt", &[0x03, 0xD9, 0xA2, 0x9A, 0, 0]);
        assert_eq!(detect(&kdbx).unwrap(), "keepass");

        let env = write(&dir, ".env", b"KEY=value\n");
        assert_eq!(detect(&env).unwrap(), "dotenv");
        let env_prod = write(&dir, ".env.production", b"KEY=value\n");
        assert_eq!(detect(&env_prod).unwrap(), "dotenv");
    }

    #[test]
    fn an_unrecognisable_file_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let junk = write(&dir, "holiday.jpg", &[0xFF, 0xD8, 0xFF, 0xE0]);
        assert!(matches!(detect(&junk), Err(ImportError::Unrecognised(_))));
    }

    #[test]
    fn a_bitwarden_export_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "bw.json",
            br#"{"encrypted":false,"items":[
                {"name":"GitHub","login":{"username":"alex","password":"hunter2",
                 "totp":"otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXPJBSWY3DP"}},
                {"name":"A note","notes":"the safe combination"},
                {"name":"Nothing useful"}
            ]}"#,
        );

        let import = bitwarden(&path).unwrap();
        assert_eq!(import.format, "Bitwarden");
        assert!(
            import.source_is_plaintext,
            "a plaintext export must be flagged"
        );

        assert_eq!(import.entries.len(), 3);
        assert!(import
            .entries
            .iter()
            .any(|e| e.kind == SecretKind::Credential));
        assert!(import
            .entries
            .iter()
            .any(|e| e.kind == SecretKind::TotpSeed));
        assert!(import.entries.iter().any(|e| e.kind == SecretKind::Note));

        assert_eq!(import.skipped.len(), 1);
        assert!(import.skipped[0].contains("Nothing useful"));
    }

    #[test]
    fn an_encrypted_bitwarden_export_asks_for_a_plain_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "bw.json", br#"{"encrypted":true,"items":[]}"#);
        assert!(matches!(
            bitwarden(&path),
            Err(ImportError::NeedsPassword(_))
        ));
    }

    #[test]
    fn a_browser_csv_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "p.csv",
            b"name,url,username,password\nGitHub,https://github.com,alex,hunter2\n\
              Bank,https://bank.example,alex,correcthorse\n",
        );

        let import = browser_csv(&path).unwrap();
        assert_eq!(import.entries.len(), 2);
        assert_eq!(import.entries[0].label, "GitHub");
        assert!(import.entries[0]
            .context
            .iter()
            .any(|(k, v)| k == "username" && v == "alex"));
        assert!(import.source_is_plaintext);
    }

    #[test]
    fn csv_columns_are_found_by_name_not_position() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            "p.csv",
            b"password,login,website,title\nhunter2,alex,https://x,GitHub\n",
        );
        let import = browser_csv(&path).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.entries[0].body(), b"hunter2");
        assert_eq!(import.entries[0].label, "GitHub");
    }

    #[test]
    fn a_csv_with_no_password_column_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "p.csv", b"name,url\nGitHub,https://x\n");
        let err = browser_csv(&path).unwrap_err();
        assert!(format!("{err}").contains("no password column"));
    }

    #[test]
    fn rows_without_passwords_are_reported_not_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "p.csv", b"name,username,password\nA,alex,x\nB,sam,\n");
        let import = browser_csv(&path).unwrap();
        assert_eq!(import.entries.len(), 1);
        assert_eq!(import.skipped.len(), 1, "a dropped row must be reported");
        assert!(import.skipped[0].contains("row 3"), "with its line number");
    }

    #[test]
    fn a_dotenv_reads_including_the_shapes_people_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            ".env",
            b"# a comment\n\nDATABASE_URL=postgres://localhost\n\
              export API_KEY=\"sk-secret\"\n\
              QUOTED='single'\n\
              EMPTY=\n\
              not a pair\n",
        );

        let import = dotenv(&path).unwrap();
        let by_label = |name: &str| {
            import
                .entries
                .iter()
                .find(|e| e.label == name)
                .map(|e| e.body().to_vec())
        };

        assert_eq!(
            by_label("DATABASE_URL"),
            Some(b"postgres://localhost".to_vec())
        );
        assert_eq!(
            by_label("API_KEY"),
            Some(b"sk-secret".to_vec()),
            "export and quotes stripped"
        );
        assert_eq!(by_label("QUOTED"), Some(b"single".to_vec()));
        assert_eq!(by_label("EMPTY"), None);

        assert_eq!(
            import.skipped.len(),
            2,
            "empty and malformed lines are reported"
        );
        assert!(import.source_is_plaintext);
    }

    #[test]
    fn plaintext_sources_are_all_flagged() {
        let dir = tempfile::tempdir().unwrap();

        let bw = write(&dir, "bw.json", br#"{"encrypted":false,"items":[]}"#);
        assert!(bitwarden(&bw).unwrap().source_is_plaintext);

        let csv = write(&dir, "p.csv", b"name,password\nA,x\n");
        assert!(browser_csv(&csv).unwrap().source_is_plaintext);

        let env = write(&dir, ".env", b"A=b\n");
        assert!(dotenv(&env).unwrap().source_is_plaintext);
    }
}
