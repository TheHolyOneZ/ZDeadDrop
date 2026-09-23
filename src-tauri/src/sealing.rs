use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use zdd_core::capsule::{EntryKind, ManifestEntry, RecipientSlot};
use zdd_core::identity::RecipientPublicKey;

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ItemSpec {
    Path {
        path: String,
    },

    Note {
        label: String,
        text: String,
    },

    SeedPhrase {
        label: String,
        words: String,
    },

    Totp {
        uri: String,
    },

    RecoveryCodes {
        label: String,
        text: String,
    },

    Import {
        path: String,

        password: Option<String>,
    },

    Credential {
        label: String,
        username: String,
        password: String,
        url: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientSpec {
    pub label: String,
    pub public_key: String,
    pub tier: u8,
    pub claim_window_days: u32,

    pub verified: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrusteeSpec {
    pub name: String,

    pub contact: Option<String>,
}

pub fn normalise_contact(raw: &str) -> Result<Option<String>, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Ok(None);
    }
    if t.starts_with("https://") || t.starts_with("mailto:") {
        return Ok(Some(t.to_string()));
    }
    if t.contains('@') && !t.contains(' ') && !t.contains('/') {
        return Ok(Some(format!("mailto:{t}")));
    }
    Err(format!(
        "“{t}” is not an email address or an https:// link the relay could use."
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapsuleSpec {
    pub name: String,
    pub note: Option<String>,
    pub items: Vec<ItemSpec>,
    pub recipients: Vec<RecipientSpec>,
    pub trustees: Vec<TrusteeSpec>,
    pub quorum: u8,
    pub silence_days: u32,
    pub countdown_days: u32,
}

pub enum Data {
    File(PathBuf),
    Bytes(Zeroizing<Vec<u8>>),
}

pub struct Source {
    pub path: String,
    pub kind: EntryKind,
    pub size: u64,
    pub data: Data,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemPreview {
    pub title: String,
    pub detail: String,
    pub kind: &'static str,
    pub files: usize,
    pub bytes: u64,

    pub skipped: Vec<String>,
}

pub fn expand(item: &ItemSpec) -> Result<(Vec<Source>, ItemPreview), String> {
    match item {
        ItemSpec::Path { path } => expand_path(&PathBuf::from(path)),
        ItemSpec::Note { label, text } => {
            if text.trim().is_empty() {
                return Err("The note is empty.".into());
            }
            let label = non_empty(label, "Note");
            let secret = zdd_import::Secret::new(
                zdd_import::SecretKind::Note,
                label.clone(),
                text.as_bytes().to_vec(),
            );
            Ok(inline(secret, "Notes", "note", "A note"))
        }
        ItemSpec::SeedPhrase { label, words } => {
            let secret = zdd_import::secrets::seed_phrase(&non_empty(label, "Seed phrase"), words)
                .map_err(|e| e.to_string())?;
            Ok(inline(secret, "Seed phrases", "seed", "Checksum verified"))
        }
        ItemSpec::Totp { uri } => {
            let secret = zdd_import::secrets::totp(uri.trim()).map_err(|e| e.to_string())?;
            Ok(inline(secret, "Two-factor", "totp", "Secret verified"))
        }
        ItemSpec::RecoveryCodes { label, text } => {
            let secret =
                zdd_import::secrets::recovery_codes(&non_empty(label, "Recovery codes"), text)
                    .map_err(|e| e.to_string())?;
            Ok(inline(secret, "Recovery codes", "codes", "Recovery codes"))
        }
        ItemSpec::Import { path, password } => expand_import(path, password.as_deref()),
        ItemSpec::Credential {
            label,
            username,
            password,
            url,
        } => {
            if password.is_empty() && username.is_empty() {
                return Err("A login needs at least a username or a password.".into());
            }
            let label = non_empty(label, if url.is_empty() { "Login" } else { url });
            let secret = zdd_import::Secret::new(
                zdd_import::SecretKind::Credential,
                label,
                password.as_bytes().to_vec(),
            )
            .with_context("username", username.clone())
            .with_context("url", url.clone());
            Ok(inline(secret, "Logins", "login", "A login"))
        }
    }
}

fn non_empty(s: &str, fallback: &str) -> String {
    let t = s.trim();
    if t.is_empty() {
        fallback.to_string()
    } else {
        t.to_string()
    }
}

fn expand_import(path: &str, password: Option<&str>) -> Result<(Vec<Source>, ItemPreview), String> {
    use zdd_import::managers;
    let p = PathBuf::from(path);
    let format = managers::detect(&p).map_err(|e| e.to_string())?;
    let (import, title) = match format {
        "keepass" => {
            let pw = password
                .filter(|p| !p.is_empty())
                .ok_or("This is a KeePass database. Enter its master password to read it.")?;
            (managers::keepass(&p, pw), "KeePass")
        }
        "bitwarden" => (managers::bitwarden(&p), "Bitwarden"),
        "browser-csv" => (managers::browser_csv(&p), "Browser passwords"),
        "dotenv" => (managers::dotenv(&p), "Environment file"),
        _ => {
            return Err(
                "That file is not an export this app can read. It understands KeePass, \
                        Bitwarden JSON, browser password CSVs and .env files."
                    .into(),
            )
        }
    };
    let import = import.map_err(|e| e.to_string())?;
    if import.entries.is_empty() {
        return Err(format!("{title}: nothing in that file could be read."));
    }
    let count = import.entries.len();
    let sources: Vec<Source> = import
        .entries
        .into_iter()
        .map(|secret| render_secret(secret, title))
        .collect();
    let bytes = sources.iter().map(|s| s.size).sum();
    let detail = if import.source_is_plaintext {
        format!("{count} entries · the export is unencrypted — delete it once this is sealed")
    } else {
        format!("{count} entries")
    };
    Ok((
        sources,
        ItemPreview {
            title: format!("{title} export"),
            detail,
            kind: "login",
            files: count,
            bytes,
            skipped: import.skipped,
        },
    ))
}

fn render_secret(secret: zdd_import::Secret, folder: &str) -> Source {
    inline(secret, folder, "login", "").0.remove(0)
}

fn inline(
    secret: zdd_import::Secret,
    folder: &str,
    kind: &'static str,
    detail: &str,
) -> (Vec<Source>, ItemPreview) {
    let mut text = Zeroizing::new(String::new());
    text.push_str(&format!("{}\n", secret.label));
    text.push_str(&"=".repeat(secret.label.chars().count().max(3)));
    text.push_str("\n\n");
    for (k, v) in &secret.context {
        if !v.is_empty() {
            text.push_str(&format!("{k}: {v}\n"));
        }
    }
    if !secret.context.is_empty() {
        text.push('\n');
    }
    text.push_str(&String::from_utf8_lossy(secret.body()));
    text.push('\n');

    let entry_kind = match secret.kind {
        zdd_import::SecretKind::Credential => EntryKind::Credential,
        zdd_import::SecretKind::TotpSeed => EntryKind::TotpSeed,
        zdd_import::SecretKind::SshKey => EntryKind::SshKey,
        zdd_import::SecretKind::GpgKey => EntryKind::GpgKey,
        zdd_import::SecretKind::SeedPhrase => EntryKind::SeedPhrase,
        zdd_import::SecretKind::RecoveryCodes => EntryKind::RecoveryCodes,
        zdd_import::SecretKind::Certificate => EntryKind::Certificate,
        zdd_import::SecretKind::Note => EntryKind::Note,
    };

    let bytes = Zeroizing::new(text.as_bytes().to_vec());
    let size = bytes.len() as u64;
    let title = secret.label.clone();
    (
        vec![Source {
            path: format!(
                "{folder}/{}.txt",
                crate::session::safe_file_name(&secret.label)
            ),
            kind: entry_kind,
            size,
            data: Data::Bytes(bytes),
        }],
        ItemPreview {
            title,
            detail: detail.to_string(),
            kind,
            files: 1,
            bytes: size,
            skipped: Vec::new(),
        },
    )
}

fn expand_path(path: &std::path::Path) -> Result<(Vec<Source>, ItemPreview), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| format!("{} could not be read.", path.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".into());

    if meta.file_type().is_symlink() {
        return Err(format!(
            "{name} is a link. Links are not followed — seal the file it points to instead."
        ));
    }

    if meta.is_file() {
        return Ok((
            vec![Source {
                path: name.clone(),
                kind: EntryKind::File,
                size: meta.len(),
                data: Data::File(path.to_path_buf()),
            }],
            ItemPreview {
                title: name,
                detail: path.display().to_string(),
                kind: "file",
                files: 1,
                bytes: meta.len(),
                skipped: Vec::new(),
            },
        ));
    }

    let walk = zdd_import::folder::walk(path, &[], true).map_err(|e| e.to_string())?;
    if walk.is_empty() {
        return Err(format!("{name} has nothing in it to seal."));
    }
    let sources = walk
        .files
        .iter()
        .map(|f| Source {
            path: format!("{name}/{}", f.path),
            kind: EntryKind::File,
            size: f.size,
            data: Data::File(f.source.clone()),
        })
        .collect::<Vec<_>>();
    Ok((
        sources,
        ItemPreview {
            title: name,
            detail: path.display().to_string(),
            kind: "folder",
            files: walk.files.len(),
            bytes: walk.total_bytes,
            skipped: walk
                .skipped
                .iter()
                .map(|(p, why)| format!("{p} — {why}"))
                .collect(),
        },
    ))
}

pub fn dedupe(sources: &mut [Source]) {
    let mut seen = HashSet::new();
    for s in sources.iter_mut() {
        if seen.insert(s.path.clone()) {
            continue;
        }
        let (stem, ext) = match s.path.rsplit_once('.') {
            Some((a, b)) if !a.is_empty() && !b.contains('/') => (a.to_string(), format!(".{b}")),
            _ => (s.path.clone(), String::new()),
        };
        let mut n = 2;
        loop {
            let candidate = format!("{stem} ({n}){ext}");
            if seen.insert(candidate.clone()) {
                s.path = candidate;
                break;
            }
            n += 1;
        }
    }
}

pub fn parse_public_key(input: &str) -> Result<RecipientPublicKey, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err("Paste their public key, or open the key file they sent you.".into());
    }
    if t.starts_with('{') {
        let doc: serde_json::Value = serde_json::from_str(t)
            .map_err(|_| "That does not look like a key file.".to_string())?;
        let public = doc
            .get("public")
            .ok_or("That file has no public key in it.")?;
        return serde_json::from_value(public.clone())
            .map_err(|_| "That key file's public key is damaged.".to_string());
    }
    let cleaned: String = t
        .trim_matches('"')
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if cleaned.len() == 64 {
        if let Some(bytes) = zdd_core::codec::from_hex(&cleaned) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                return Ok(RecipientPublicKey(arr));
            }
        }
    }
    serde_json::from_value(serde_json::Value::String(cleaned))
        .map_err(|_| "That is not a ZDeadDrop public key.".to_string())
}

pub fn recipient_slots(
    specs: &[RecipientSpec],
    now: zdd_core::clock::Timestamp,
) -> Result<Vec<RecipientSlot>, String> {
    let mut seen = HashSet::new();
    specs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let key = parse_public_key(&r.public_key)
                .map_err(|e| format!("{}: {e}", non_empty(&r.label, "A recipient")))?;
            if !seen.insert(key.0) {
                return Err(format!(
                    "{} has the same key as someone else on this capsule.",
                    non_empty(&r.label, "A recipient")
                ));
            }
            Ok(RecipientSlot {
                id: i as u8,
                public_key: key,
                tier: r.tier,
                claim_window: r.claim_window_days as u64 * zdd_core::clock::SECONDS_PER_DAY,
                key_verified_at: r.verified.then_some(now),
                key_rotated_at: None,
            })
        })
        .collect()
}

pub struct Payload<'a> {
    sources: &'a [Source],
    index: usize,
    current: Option<Box<dyn Read + 'a>>,
    remaining: u64,
    hasher: blake3::Hasher,
    pub hashes: Vec<[u8; 32]>,
}

impl<'a> Payload<'a> {
    pub fn new(sources: &'a [Source]) -> Self {
        Self {
            sources,
            index: 0,
            current: None,
            remaining: 0,
            hasher: blake3::Hasher::new(),
            hashes: Vec::with_capacity(sources.len()),
        }
    }

    fn open_next(&mut self) -> std::io::Result<bool> {
        let Some(src) = self.sources.get(self.index) else {
            return Ok(false);
        };
        self.current = Some(match &src.data {
            Data::File(p) => Box::new(std::fs::File::open(p)?),
            Data::Bytes(b) => Box::new(std::io::Cursor::new(b.as_slice())),
        });
        self.remaining = src.size;
        self.hasher = blake3::Hasher::new();
        Ok(true)
    }

    fn finish_current(&mut self) -> std::io::Result<()> {
        if let Some(mut r) = self.current.take() {
            let mut probe = [0u8; 1];
            if r.read(&mut probe)? != 0 {
                return Err(changed(&self.sources[self.index].path));
            }
        }
        self.hashes.push(*self.hasher.finalize().as_bytes());
        self.index += 1;
        Ok(())
    }
}

fn changed(path: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "{path} changed while it was being sealed. Nothing was saved — close whatever \
         is writing to it and try again."
    ))
}

impl Read for Payload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.current.is_none() && !self.open_next()? {
                return Ok(0);
            }
            if self.remaining == 0 {
                self.finish_current()?;
                continue;
            }
            let want = (buf.len() as u64).min(self.remaining) as usize;
            let reader = self.current.as_mut().expect("opened above");
            let n = reader.read(&mut buf[..want])?;
            if n == 0 {
                return Err(changed(&self.sources[self.index].path));
            }
            self.hasher.update(&buf[..n]);
            self.remaining -= n as u64;
            return Ok(n);
        }
    }
}

pub fn entries(sources: &[Source], hashes: &[[u8; 32]]) -> Vec<ManifestEntry> {
    let mut offset = 0;
    sources
        .iter()
        .zip(hashes)
        .map(|(s, h)| {
            let e = ManifestEntry {
                path: s.path.clone(),
                size: s.size,
                kind: s.kind,
                content_hash: *h,
                offset,
            };
            offset += s.size;
            e
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(path: &str, b: &[u8]) -> Source {
        Source {
            path: path.into(),
            kind: EntryKind::Note,
            size: b.len() as u64,
            data: Data::Bytes(Zeroizing::new(b.to_vec())),
        }
    }

    #[test]
    fn the_payload_is_every_source_in_order_and_hashed() {
        let sources = vec![bytes("a", b"one"), bytes("b", b""), bytes("c", b"three")];
        let mut p = Payload::new(&sources);
        let mut out = Vec::new();
        p.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"onethree");
        assert_eq!(p.hashes.len(), 3);
        assert_eq!(p.hashes[0], *blake3::hash(b"one").as_bytes());
        assert_eq!(p.hashes[2], *blake3::hash(b"three").as_bytes());

        let e = entries(&sources, &p.hashes);
        assert_eq!(e[2].offset, 3);
    }

    #[test]
    fn a_file_that_grew_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"longer than listed").unwrap();
        let sources = vec![Source {
            path: "f".into(),
            kind: EntryKind::File,
            size: 4,
            data: Data::File(f),
        }];
        let mut out = Vec::new();
        assert!(Payload::new(&sources).read_to_end(&mut out).is_err());
    }

    #[test]
    fn a_file_that_shrank_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"ab").unwrap();
        let sources = vec![Source {
            path: "f".into(),
            kind: EntryKind::File,
            size: 10,
            data: Data::File(f),
        }];
        let mut out = Vec::new();
        assert!(Payload::new(&sources).read_to_end(&mut out).is_err());
    }

    #[test]
    fn duplicate_names_are_kept_apart() {
        let mut s = vec![
            bytes("x.txt", b"1"),
            bytes("x.txt", b"2"),
            bytes("x.txt", b"3"),
        ];
        dedupe(&mut s);
        let names: Vec<_> = s.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(names, ["x.txt", "x (2).txt", "x (3).txt"]);
    }

    #[test]
    fn contacts_are_normalised() {
        assert_eq!(normalise_contact("").unwrap(), None);
        assert_eq!(
            normalise_contact("sam@example.org").unwrap().as_deref(),
            Some("mailto:sam@example.org")
        );
        assert!(normalise_contact("https://ntfy.sh/x").is_ok());
        assert!(normalise_contact("call me maybe").is_err());
        assert!(normalise_contact("http://plain.example").is_err());
    }

    #[test]
    fn public_keys_parse_in_every_shape() {
        let id = zdd_core::identity::RecipientIdentity::generate();
        let pk = id.public();
        let json = serde_json::to_string(&pk).unwrap();
        let file = serde_json::json!({ "kind": "zdd-recipient-key", "public": pk }).to_string();
        assert_eq!(parse_public_key(&json).unwrap(), pk);
        assert_eq!(parse_public_key(json.trim_matches('"')).unwrap(), pk);
        assert_eq!(parse_public_key(&file).unwrap(), pk);
        assert_eq!(
            parse_public_key(&zdd_core::codec::to_hex(&pk.0)).unwrap(),
            pk
        );
        assert!(parse_public_key("nonsense").is_err());
    }

    #[test]
    fn a_folder_expands_with_its_name_as_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("Photos");
        std::fs::create_dir_all(root.join("2019")).unwrap();
        std::fs::write(root.join("2019/a.jpg"), b"jpg").unwrap();
        std::fs::create_dir_all(root.join("node_modules/x")).unwrap();
        std::fs::write(root.join("node_modules/x/i.js"), b"js").unwrap();
        let (sources, preview) = expand(&ItemSpec::Path {
            path: root.display().to_string(),
        })
        .unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path, "Photos/2019/a.jpg");
        assert_eq!(preview.kind, "folder");
    }

    #[test]
    fn a_browser_export_becomes_one_file_per_login() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("passwords.csv");
        std::fs::write(
            &csv,
            "name,url,username,password\nbank,https://bank.example,alex,s3cret\n\
             mail,https://mail.example,alex@x,hunter2\n",
        )
        .unwrap();
        let (sources, preview) = expand(&ItemSpec::Import {
            path: csv.display().to_string(),
            password: None,
        })
        .unwrap();
        assert_eq!(sources.len(), 2);
        assert!(preview.detail.contains("delete it"), "{}", preview.detail);
        assert!(sources
            .iter()
            .all(|s| s.path.starts_with("Browser passwords/")));
    }

    #[test]
    fn a_keepass_file_asks_for_its_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.kdbx");
        std::fs::write(&db, [0x03, 0xD9, 0xA2, 0x9A, 0, 0]).unwrap();
        let err = expand(&ItemSpec::Import {
            path: db.display().to_string(),
            password: None,
        })
        .err()
        .unwrap();
        assert!(err.contains("master password"), "{err}");
    }

    #[test]
    fn an_invalid_seed_phrase_never_gets_in() {
        let bad = ItemSpec::SeedPhrase {
            label: "wallet".into(),
            words: "abandon abandon abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon"
                .into(),
        };
        assert!(expand(&bad).is_err());
    }
}
