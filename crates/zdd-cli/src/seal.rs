use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use zdd_core::capsule::{
    simple_recipient, Capsule, EntryKind, Manifest, ManifestEntry, PayloadRef,
};
use zdd_core::clock::{Clock, SystemClock};
use zdd_core::identity::{RecipientPublicKey, VaultIdentity};
use zdd_core::release::GatePolicy;
use zdd_core::secret::Key32;
use zdd_core::stream;

use crate::term;

#[derive(ClapArgs)]
pub struct Args {
    #[doc = " Files to seal."]
    #[arg(required = true)]
    files: Vec<PathBuf>,

    #[doc = " What to call this capsule."]
    #[arg(long)]
    name: String,

    #[doc = " A message shown to the recipient before anything is extracted."]
    #[arg(long)]
    note: Option<String>,

    #[doc = " The recipient's key file or public key fingerprint file, from `zdd keygen`."]
    #[arg(long, required = true)]
    to: PathBuf,

    #[doc = " How many trustees must agree before this can be released."]
    #[arg(long, default_value_t = 3)]
    quorum: u8,

    #[doc = " How many trustees to split the quorum across."]
    #[arg(long, default_value_t = 5)]
    trustees: u8,

    #[doc = " Where to write the capsule."]
    #[arg(long)]
    out: PathBuf,
}

pub fn run(args: Args) -> Result<()> {
    let recipient = load_public_key(&args.to)?;
    let now = SystemClock.now();

    let owner = VaultIdentity::derive(&Key32::random());

    let mut entries = Vec::with_capacity(args.files.len());
    let mut offset = 0u64;
    for path in &args.files {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("could not read {}", path.display()))?;
        if meta.is_dir() {
            anyhow::bail!(
                "{} is a directory. Sealing whole folders is not supported yet; \
                 pass the files individually.",
                path.display()
            );
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".to_string());

        entries.push(ManifestEntry {
            path: name,
            size: meta.len(),
            kind: EntryKind::File,
            content_hash: hash_file(path)?,
            offset,
        });
        offset += meta.len();
    }

    let manifest = Manifest {
        name: args.name.clone(),
        note: args.note.clone(),
        total_bytes: offset,
        entries,
        recipient_labels: Default::default(),
    };

    let policy = if args.trustees == 0 {
        term::warn("This capsule has no trustees, so the relay alone can release it.");
        GatePolicy::RelayOnly
    } else {
        GatePolicy::RelayAndQuorum {
            threshold: args.quorum,
            total: args.trustees,
        }
    };

    let mut draft = Capsule::create(
        &owner,
        vec![simple_recipient(0, recipient)],
        policy,
        &manifest,
        now,
    )
    .context("could not create the capsule")?;

    let blob_path = args.out.parent().unwrap_or(Path::new(".")).to_path_buf();
    std::fs::create_dir_all(&blob_path)?;

    let temp = blob_path.join(".sealing.payload");
    let mut sink = std::fs::File::create(&temp)?;
    let mut source = Concatenated::new(&args.files)?;

    let (prefix, written) = stream::seal_reader(
        &Capsule::payload_key(&draft.cdk),
        &draft.capsule.id.0,
        &mut source,
        &mut sink,
        |done| {
            if let Some(pct) = (done * 100).checked_div(offset) {
                print!("\r  sealing… {}%", pct.min(100));
                let _ = std::io::stdout().flush();
            }
        },
    )
    .context("could not encrypt the payload")?;
    sink.sync_all()?;
    println!("\r  sealing… done   ");

    let ciphertext_len = std::fs::metadata(&temp)?.len();
    let blob_id = hash_file(&temp)?;
    let final_blob = blob_path.join(format!("{}.payload", zdd_core::codec::to_hex(&blob_id)));
    std::fs::rename(&temp, &final_blob)?;

    draft.capsule.attach_payload(PayloadRef {
        prefix,
        plaintext_len: written,
        ciphertext_len,
        blob_id,
    });
    draft.capsule.validate()?;

    std::fs::write(&args.out, serde_json::to_string_pretty(&draft.capsule)?)?;

    let seal = draft.capsule.seal();
    println!();
    term::good(&format!(
        "sealed {} into {}",
        term::bytes(written),
        args.out.display()
    ));
    term::field("Seal", &seal.short());
    term::field("Picture", &zdd_seal::describe(seal.seal_seed()));
    term::field("Contents", &final_blob.display().to_string());

    println!();
    term::heading("Send these separately");
    term::note("Both files above go to the recipient. These shares do NOT —");
    term::note("they are what stops the capsule being opened early.");
    println!();

    if let Some(relay) = &draft.gate_material.relay_share {
        term::field("Relay share", &zdd_core::codec::to_hex(relay.expose()));
        term::note("  → to your relay");
    }
    for (i, share) in draft.gate_material.trustee_shares.iter().enumerate() {
        println!();
        term::field(&format!("Trustee {}", i + 1), &share.to_json()?);
    }

    println!();
    term::warn("Keep none of these yourself.");
    term::note("Holding every share means you are the single point of failure this design");
    term::note("exists to remove — and anyone who takes your machine inherits that.");

    println!();
    term::note("Tell the recipient what the seal looks like:");
    term::note(&format!(
        "    {}  ({})",
        seal.short(),
        zdd_seal::describe(seal.seal_seed())
    ));
    term::note("It is how they check nobody swapped the capsule.");

    Ok(())
}

fn load_public_key(path: &Path) -> Result<RecipientPublicKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("{} does not look like a key file", path.display()))?;

    let public = doc
        .get("public")
        .context("that key file has no public key in it")?;
    serde_json::from_value(public.clone()).context("that key file's public key is damaged")
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("could not read {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

struct Concatenated {
    remaining: std::collections::VecDeque<PathBuf>,
    current: Option<std::fs::File>,
}

impl Concatenated {
    fn new(paths: &[PathBuf]) -> Result<Self> {
        let mut this = Self {
            remaining: paths.iter().cloned().collect(),
            current: None,
        };
        this.advance()?;
        Ok(this)
    }

    fn advance(&mut self) -> Result<()> {
        self.current = match self.remaining.pop_front() {
            Some(path) => Some(
                std::fs::File::open(&path)
                    .with_context(|| format!("could not read {}", path.display()))?,
            ),
            None => None,
        };
        Ok(())
    }
}

impl Read for Concatenated {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let Some(file) = self.current.as_mut() else {
                return Ok(0);
            };
            let n = file.read(buf)?;
            if n > 0 {
                return Ok(n);
            }

            self.advance().map_err(std::io::Error::other)?;
        }
    }
}

pub struct SplitWriter {
    plan: std::vec::IntoIter<(PathBuf, u64)>,
    current: Option<(std::fs::File, u64)>,
}

impl SplitWriter {
    pub fn new(plan: Vec<(PathBuf, u64)>) -> Result<Self> {
        let mut this = Self {
            plan: plan.into_iter(),
            current: None,
        };
        this.advance()?;
        Ok(this)
    }

    fn advance(&mut self) -> Result<()> {
        self.current = match self.plan.next() {
            Some((path, len)) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                Some((
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)?,
                    len,
                ))
            }
            None => None,
        };
        Ok(())
    }

    pub fn finish(mut self) -> Result<()> {
        if let Some((file, remaining)) = self.current.take() {
            file.sync_all()?;
            if remaining > 0 {
                anyhow::bail!("the payload ended {remaining} bytes early");
            }
        }
        Ok(())
    }
}

impl Write for SplitWriter {
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let total = buf.len();

        while !buf.is_empty() {
            let Some((file, remaining)) = self.current.as_mut() else {
                return Err(std::io::Error::other(
                    "the payload is longer than the contents list says",
                ));
            };

            let take = (*remaining).min(buf.len() as u64) as usize;
            if take > 0 {
                file.write_all(&buf[..take])?;
                *remaining -= take as u64;
                buf = &buf[take..];
            }

            if *remaining == 0 {
                file.sync_all()?;
                self.advance().map_err(std::io::Error::other)?;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some((file, _)) = self.current.as_mut() {
            file.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concatenation_reads_every_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<PathBuf> = ["one", "two", "three"]
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let p = dir.path().join(format!("{i}.txt"));
                std::fs::write(&p, name.as_bytes()).unwrap();
                p
            })
            .collect();

        let mut src = Concatenated::new(&paths).unwrap();
        let mut out = Vec::new();
        src.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"onetwothree");
    }

    #[test]
    fn concatenation_survives_empty_files_in_the_middle() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let empty = dir.path().join("empty");
        let b = dir.path().join("b");
        std::fs::write(&a, b"aaa").unwrap();
        std::fs::write(&empty, b"").unwrap();
        std::fs::write(&b, b"bbb").unwrap();

        let mut src = Concatenated::new(&[a, empty, b]).unwrap();
        let mut out = Vec::new();
        src.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"aaabbb");
    }

    #[test]
    fn splitting_writes_each_file_its_own_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let plan = vec![
            (dir.path().join("a.txt"), 3u64),
            (dir.path().join("b.txt"), 5u64),
            (dir.path().join("c.txt"), 2u64),
        ];

        let mut w = SplitWriter::new(plan).unwrap();

        w.write_all(b"aaab").unwrap();
        w.write_all(b"bbbbc").unwrap();
        w.write_all(b"c").unwrap();
        w.finish().unwrap();

        assert_eq!(std::fs::read(dir.path().join("a.txt")).unwrap(), b"aaa");
        assert_eq!(std::fs::read(dir.path().join("b.txt")).unwrap(), b"bbbbb");
        assert_eq!(std::fs::read(dir.path().join("c.txt")).unwrap(), b"cc");
    }

    #[test]
    fn splitting_rejects_a_payload_longer_than_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SplitWriter::new(vec![(dir.path().join("a"), 2)]).unwrap();
        assert!(w.write_all(b"toolong").is_err());
    }

    #[test]
    fn splitting_reports_a_payload_that_ends_early() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = SplitWriter::new(vec![(dir.path().join("a"), 10)]).unwrap();
        w.write_all(b"short").unwrap();
        assert!(
            w.finish().is_err(),
            "a truncated payload must not look complete"
        );
    }

    #[test]
    fn splitting_handles_zero_length_entries() {
        let dir = tempfile::tempdir().unwrap();
        let plan = vec![
            (dir.path().join("empty"), 0u64),
            (dir.path().join("full"), 4u64),
        ];
        let mut w = SplitWriter::new(plan).unwrap();
        w.write_all(b"data").unwrap();
        w.finish().unwrap();
        assert_eq!(std::fs::read(dir.path().join("full")).unwrap(), b"data");
    }
}
