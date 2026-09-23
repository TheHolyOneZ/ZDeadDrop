use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use zdd_core::capsule::Capsule;
use zdd_core::identity::RecipientIdentity;
use zdd_core::release;
use zdd_core::secret::Key32;
use zdd_core::shamir::Share;
use zdd_core::stream;

use crate::term;

#[derive(ClapArgs)]
pub struct Args {
    #[doc = " The capsule file you were sent."]
    capsule: PathBuf,

    #[doc = " Your private key file, from `zdd keygen`."]
    #[arg(long)]
    key: PathBuf,

    #[doc = " The release key, if you were given one directly."]
    #[arg(long, conflicts_with_all = ["relay_share", "trustee_share"])]
    release_key: Option<String>,

    #[doc = " The relay's share: its file, the share itself, or the relay's address"]
    #[doc = " for this vault, from which it is fetched."]
    #[arg(long)]
    relay_share: Option<String>,

    #[doc = " A trustee's share: the file they sent you, or the share itself."]
    #[doc = " Repeat this once per trustee who sent you one."]
    #[arg(long = "trustee-share", value_name = "SHARE")]
    trustee_share: Vec<String>,

    #[doc = " Where to write what is inside. Defaults to a folder beside the capsule."]
    #[arg(long)]
    out: Option<PathBuf>,

    #[doc = " Describe the capsule and stop, without extracting anything."]
    #[arg(long)]
    inspect: bool,
}

pub fn run(args: Args) -> Result<()> {
    let capsule = load_capsule(&args.capsule)?;

    describe(&capsule);

    if args.inspect {
        println!();
        term::note("Nothing was extracted. Run the same command without --inspect to open it.");
        return Ok(());
    }

    let recipient = load_key(&args.key)?;

    let slot = capsule
        .recipients
        .iter()
        .find(|r| r.public_key == recipient.public())
        .map(|r| r.id);

    let Some(slot) = slot else {
        term::bad("This capsule was not left to the key you gave me.");
        println!();
        term::note("The key you used has fingerprint:");
        term::note(&format!("    {}", recipient.public().fingerprint().short()));
        term::note("but this capsule is addressed to:");
        for r in &capsule.recipients {
            term::note(&format!("    {}", r.public_key.fingerprint().short()));
        }
        println!();
        term::note("If you have more than one key file, try another. If you only have one,");
        term::note("the person who sealed this may have used an old copy of your public key.");
        anyhow::bail!("no slot in this capsule is addressed to that key");
    };

    let release_key = assemble_release_key(&capsule, &args)?;

    let cdk = capsule
        .open_as_recipient(&recipient, slot, &release_key)
        .map_err(|_| unlock_failure())?;

    let manifest = capsule
        .read_manifest(&cdk)
        .context("the capsule opened, but its contents list is damaged")?;

    println!();
    term::good("Opened.");
    if let Some(name) = manifest.recipient_labels.get(&slot) {
        term::field("Left to", name);
    }
    term::field("Called", &manifest.name);
    term::field(
        "Holds",
        &format!(
            "{} in {} {}",
            term::bytes(manifest.total_bytes),
            manifest.entries.len(),
            if manifest.entries.len() == 1 {
                "item"
            } else {
                "items"
            }
        ),
    );

    if let Some(note) = &manifest.note {
        println!();
        term::heading("They left you a message");
        println!();
        for line in note.lines() {
            println!("  {line}");
        }
        println!();
    }

    let out = args.out.unwrap_or_else(|| {
        args.capsule.with_extension("").with_file_name(format!(
            "{}-contents",
            args.capsule
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
        ))
    });

    extract(&capsule, &cdk, &args.capsule, &out, &manifest)?;

    println!();
    term::good(&format!("Everything was written to {}", out.display()));
    term::note("Nothing was deleted, and the capsule file is unchanged.");
    Ok(())
}

fn load_capsule(path: &Path) -> Result<Capsule> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;

    let capsule: Capsule = serde_json::from_str(&text).map_err(|_| {
        anyhow::anyhow!("{} does not look like a ZDeadDrop capsule", path.display())
    })?;

    capsule.validate().context("this capsule file is damaged")?;
    Ok(capsule)
}

fn load_key(path: &Path) -> Result<RecipientIdentity> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read your key file at {}", path.display()))?;

    let doc: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("{} does not look like a key file", path.display()))?;

    let hex = doc["secret"]
        .as_str()
        .context("that key file has no secret key in it")?;
    let bytes = zdd_core::codec::from_hex(hex).context("that key file is damaged")?;

    RecipientIdentity::from_secret_bytes(&bytes).context("that key file is damaged")
}

fn describe(capsule: &Capsule) {
    let seal = capsule.seal();

    term::heading("This capsule");
    term::field("Seal", &seal.short());
    term::field("Picture", &zdd_seal::describe(seal.seal_seed()));
    term::field("Sealed on", &format_date(capsule.created_at.0));
    term::field(
        "Left to",
        &format!(
            "{} {}",
            capsule.recipients.len(),
            if capsule.recipients.len() == 1 {
                "person"
            } else {
                "people"
            }
        ),
    );

    if let Some(payload) = &capsule.payload {
        term::field("Size", &term::bytes(payload.plaintext_len));
    }

    println!();
    term::note("If you were told what this seal should look like, check it now.");
    term::note("A different picture means this is not the capsule they sealed.");

    if capsule.is_rehearsal {
        println!();
        term::warn("This is a rehearsal capsule. It holds practice content, not the real thing.");
    }
}

fn share_text(arg: &str, kind: &str) -> Result<String> {
    let text = match std::fs::read_to_string(arg) {
        Ok(t) => t,
        Err(_) => arg.to_string(),
    };
    if let Ok(doc) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        if doc.get("kind").and_then(|k| k.as_str()) == Some(kind) {
            let share = doc.get("share").context("that file holds no share")?;
            return Ok(match share {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        }
    }
    Ok(text)
}

fn fetch_relay_share(url: &str, gate: &zdd_core::release::GateId) -> Result<String> {
    let url = format!("{}/release-share", url.trim_end_matches('/'));
    let res = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?
        .post(&url)
        .send()
        .context("could not reach the relay")?;
    if res.status() == reqwest::StatusCode::FORBIDDEN {
        anyhow::bail!(
            "the relay says the person who sealed this is still checking in, so it will not \
             release its piece yet"
        );
    }
    let body: serde_json::Value = res
        .error_for_status()
        .context("the relay refused")?
        .json()
        .context("the relay's answer could not be read")?;
    let gate_hex = zdd_core::codec::to_hex(&gate.0);
    body["shares"][&gate_hex]
        .as_str()
        .or_else(|| body["relay_share"].as_str())
        .map(str::to_string)
        .context("the relay holds no piece for this capsule")
}

fn assemble_release_key(capsule: &Capsule, args: &Args) -> Result<Key32> {
    if let Some(hex) = &args.release_key {
        let bytes = zdd_core::codec::from_hex(hex)
            .context("that release key is not in the expected form")?;
        return Key32::from_slice(&bytes).context("that release key is the wrong length");
    }

    if args.trustee_share.is_empty() && args.relay_share.is_none() {
        println!();
        term::bad("I need the release key before I can open this.");
        println!();
        term::note("The notice you were sent should contain either:");
        term::note("  · a single release key       → pass it with --release-key");
        term::note("  · a relay share and shares from the people they trusted");
        term::note("                               → pass --relay-share and one");
        term::note("                                 --trustee-share for each");
        println!();
        term::note("If you have not been sent one, the release has not completed yet.");
        anyhow::bail!("no release key or shares were given");
    }

    let mut shares = Vec::with_capacity(args.trustee_share.len());
    for (i, arg) in args.trustee_share.iter().enumerate() {
        let text = share_text(arg, "zdd-trustee-share")
            .with_context(|| format!("trustee share #{} could not be read", i + 1))?;
        let share = Share::from_json(&text)
            .with_context(|| format!("trustee share #{} is damaged", i + 1))?;
        shares.push(share);
    }

    let relay = args
        .relay_share
        .as_ref()
        .map(|arg| -> Result<Key32> {
            let hex = if arg.starts_with("http://") || arg.starts_with("https://") {
                fetch_relay_share(arg, &capsule.gate.gate_id)?
            } else {
                share_text(arg, "zdd-relay-share")?
            };
            let bytes = zdd_core::codec::from_hex(hex.trim().trim_matches('"'))
                .context("that relay share is not in the expected form")?;
            Key32::from_slice(&bytes).context("that relay share is the wrong length")
        })
        .transpose()?;

    release::assemble(&capsule.gate, relay.as_ref(), &shares).map_err(|e| match e {
        zdd_core::Error::ReleaseRefused(zdd_core::ReleaseRefusal::QuorumNotMet { have, need }) => {
            anyhow::anyhow!(
                "you have {have} of the {need} shares needed. Ask the others to send theirs."
            )
        }
        zdd_core::Error::ReleaseRefused(zdd_core::ReleaseRefusal::NoRelayProof) => {
            anyhow::anyhow!(
                "this capsule also needs the relay's share. It is in the release notice."
            )
        }
        other => anyhow::anyhow!("the shares did not fit together: {other}"),
    })
}

fn unlock_failure() -> anyhow::Error {
    anyhow::anyhow!(
        "the key and the release information do not open this capsule.\n      \
         The most likely reasons are a share from a different capsule, or a share that was \
         replaced after this capsule was sealed. Ask whoever sent the release notice to \
         check it is the current one."
    )
}

fn extract(
    capsule: &Capsule,
    cdk: &Key32,
    capsule_path: &Path,
    out: &Path,
    manifest: &zdd_core::capsule::Manifest,
) -> Result<()> {
    let Some(payload) = &capsule.payload else {
        term::note("This capsule holds no files — only the message above.");
        return Ok(());
    };

    if out.exists() {
        anyhow::bail!(
            "{} already exists. Move it aside, or pass --out to choose somewhere else.\n      \
             Nothing has been changed.",
            out.display()
        );
    }
    std::fs::create_dir_all(out)?;

    let blob = capsule_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(format!(
            "{}.payload",
            zdd_core::codec::to_hex(&payload.blob_id)
        ));

    let mut source = std::fs::File::open(&blob).with_context(|| {
        format!(
            "the capsule's contents file is missing.\n      \
             It should be at {}, beside the capsule you were sent.",
            blob.display()
        )
    })?;

    let paths = plan_paths(&manifest.entries);
    let plan: Vec<(PathBuf, u64)> = manifest
        .entries
        .iter()
        .zip(&paths)
        .map(|(entry, path)| (out.join(path), entry.size))
        .collect();

    let mut writer = crate::seal::SplitWriter::new(plan)?;
    let total = payload.plaintext_len;

    stream::open_reader(
        &Capsule::payload_key(cdk),
        payload.prefix,
        &capsule.id.0,
        &mut source,
        &mut writer,
        |done| {
            if let Some(pct) = (done * 100).checked_div(total) {
                print!("\r  extracting… {}%", pct.min(100));
                let _ = std::io::stdout().flush();
            }
        },
    )
    .map_err(|_| {
        anyhow::anyhow!(
            "the contents file is damaged or incomplete, so it could not be opened safely.\n      \
             Ask for a fresh copy — a partial file is not usable, and ZDeadDrop will not \
             pretend otherwise."
        )
    })?;

    writer.finish()?;
    println!("\r  extracting… done   ");

    for (entry, path) in manifest.entries.iter().zip(&paths) {
        term::note(&format!(
            "  {}  ({})",
            path.display(),
            term::bytes(entry.size)
        ));
    }
    Ok(())
}

fn sanitise(path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.split(['/', '\\']) {
        let part = part.trim();
        if part == "." || part == ".." {
            continue;
        }
        if let Some(clean) = zdd_core::paths::component(part) {
            out.push(clean);
        }
    }
    if out.as_os_str().is_empty() {
        out.push("file");
    }
    out
}

fn plan_paths(entries: &[zdd_core::capsule::ManifestEntry]) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    entries
        .iter()
        .map(|e| {
            let base = sanitise(&e.path);
            if seen.insert(base.clone()) {
                return base;
            }
            let stem = base
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into());
            let ext = base
                .extension()
                .map(|x| format!(".{}", x.to_string_lossy()))
                .unwrap_or_default();
            (2..)
                .map(|n| base.with_file_name(format!("{stem} ({n}){ext}")))
                .find(|p| seen.insert(p.clone()))
                .expect("an unbounded range always finds a free name")
        })
        .collect()
}

fn format_date(unix: u64) -> String {
    const DAY: u64 = 86_400;
    let days = unix / DAY;

    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_correct() {
        assert_eq!(format_date(0), "1970-01-01");
        assert_eq!(format_date(86_400), "1970-01-02");

        assert_eq!(format_date(1_790_000_000), "2026-09-21");

        assert_eq!(format_date(1_709_164_800), "2024-02-29");
    }

    #[test]
    fn names_windows_refuses_are_made_safe() {
        assert_eq!(
            sanitise("Letters/CON/aux.txt"),
            PathBuf::from("Letters/_CON/_aux.txt")
        );
        assert_eq!(sanitise("notes./draft. "), PathBuf::from("notes/draft"));
    }

    #[test]
    fn folders_survive_extraction() {
        assert_eq!(
            sanitise("Letters/2019/photo.jpg"),
            PathBuf::from("Letters/2019/photo.jpg")
        );
    }

    #[test]
    fn nothing_climbs_out_of_the_output_folder() {
        for evil in [
            "../../.ssh/authorized_keys",
            "/etc/passwd",
            "C:\\Windows\\system32\\x.dll",
            "\\\\server\\share\\x",
            "a/../../b",
            "..",
            "",
        ] {
            let p = sanitise(evil);
            assert!(p.is_relative(), "{evil} → {p:?}");
            assert!(
                !p.components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "{evil} → {p:?}"
            );
            assert!(!p.to_string_lossy().contains(':'), "{evil} → {p:?}");
        }
    }

    #[test]
    fn same_named_files_do_not_collide() {
        use zdd_core::capsule::{EntryKind, ManifestEntry};
        let e = |p: &str| ManifestEntry {
            path: p.into(),
            size: 0,
            kind: EntryKind::File,
            content_hash: [0; 32],
            offset: 0,
        };
        let paths = plan_paths(&[e("a/notes.txt"), e("a/notes.txt"), e("b/notes.txt")]);
        assert_eq!(
            paths,
            [
                PathBuf::from("a/notes.txt"),
                PathBuf::from("a/notes (2).txt"),
                PathBuf::from("b/notes.txt"),
            ]
        );
    }
}
