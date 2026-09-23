mod claim;
mod rehearse;
mod seal;
mod term;
mod trustee;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use zdd_core::clock::{Clock, SystemClock};
use zdd_core::kdf::Argon2Params;
use zdd_core::policy::{self, LadderConfig, VigilState};
use zdd_core::vault::{CredentialKind, RecoveryPolicy};
use zdd_store::{LockedVault, OpenVault};

#[derive(Parser)]
#[command(
    name = "zdd",
    version,
    about = "A local-first digital dead-man's switch and encrypted legacy vault.",
    long_about = "ZDeadDrop encrypts something, defines who receives it and under what \
                  condition, and lets that condition be checked without trusting a server \
                  with the plaintext.\n\n\
                  Were you asked to run this to receive something someone left you?\n\
                  Then the command you want is:\n\n    \
                  zdd claim --key YOUR-KEY-FILE THE-CAPSULE-FILE"
)]
struct Cli {
    #[doc = " The vault directory. Defaults to $ZDD_VAULT, then a platform data directory."]
    #[arg(long, global = true, env = "ZDD_VAULT")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[doc = " Create a new vault."]
    Init {
        #[doc = " How hard the passphrase is to attack offline."]
        #[arg(long, value_enum, default_value = "moderate")]
        strength: Strength,

        #[doc = " Refuse to add any recovery path later, permanently."]
        #[doc = ""]
        #[doc = " A forgotten passphrase then means you can never open this vault"]
        #[doc = " again — though your capsules still reach their recipients on"]
        #[doc = " schedule, because releasing does not depend on your passphrase."]
        #[arg(long)]
        unrecoverable: bool,
    },

    #[doc = " Show the vigil and every capsule's state."]
    Status {
        #[doc = " Machine-readable output, for scripts and monitoring."]
        #[arg(long)]
        json: bool,
    },

    #[doc = " Prove you are still here."]
    Checkin,

    #[doc = " Verify the vault has not been interfered with."]
    Verify,

    #[doc = " Generate a recipient keypair, for someone who will receive a capsule."]
    Keygen {
        #[doc = " Where to write the private key. It is not encrypted; keep it safe."]
        #[arg(long)]
        out: PathBuf,
    },

    #[doc = " Seal files into a capsule for someone."]
    Seal(seal::Args),

    #[doc = " Walk the whole release, end to end, without any of it being real."]
    #[doc = ""]
    #[doc = " The only way to find out your setup is wrong while you can still fix it."]
    Rehearse(rehearse::Args),

    #[doc = " For trustees: check whether the owner's latest check-in was made freely."]
    TrusteeCheck(trustee::Args),

    #[doc = " Open a capsule that has been released to you."]
    #[doc = ""]
    #[doc = " This is the command to run if someone left you something."]
    Claim(claim::Args),
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Strength {
    #[doc = " About half a second to unlock. For a strong passphrase you type often."]
    Interactive,
    #[doc = " About two seconds. The right answer for most people."]
    Moderate,
    #[doc = " About eight seconds. For a vault opened rarely that must survive a"]
    #[doc = " well-funded attack on a weak passphrase."]
    Paranoid,
}

impl From<Strength> for Argon2Params {
    fn from(s: Strength) -> Self {
        match s {
            Strength::Interactive => Argon2Params::INTERACTIVE,
            Strength::Moderate => Argon2Params::MODERATE,
            Strength::Paranoid => Argon2Params::PARANOID,
        }
    }
}

fn main() {
    if !zdd_core::harden_process() {
        term::warn("could not disable core dumps; a crash could write key material to disk");
    }

    if let Err(e) = run() {
        term::bad(&format!("{e}"));

        for cause in e.chain().skip(1) {
            eprintln!("      {cause}");
        }
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let clock = SystemClock;

    match cli.command {
        Command::Init {
            strength,
            unrecoverable,
        } => {
            let path = vault_path(cli.vault)?;
            init(&path, strength.into(), unrecoverable, clock.now())
        }
        Command::Status { json } => status(&vault_path(cli.vault)?, json),
        Command::Checkin => checkin(&vault_path(cli.vault)?),
        Command::Verify => verify(&vault_path(cli.vault)?),
        Command::Keygen { out } => keygen(&out),
        Command::Seal(args) => seal::run(args),
        Command::Rehearse(args) => rehearse::run(args),
        Command::Claim(args) => claim::run(args),
        Command::TrusteeCheck(args) => trustee::run(args),
    }
}

fn vault_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    zdd_store::default_vault_path()
        .context("could not work out where to keep the vault; pass --vault")
}

fn open(path: &std::path::Path) -> Result<OpenVault> {
    let locked =
        LockedVault::open(path).with_context(|| format!("no vault at {}", path.display()))?;

    term::note(&format!("vault {}", locked.short_id()));
    let passphrase = term::passphrase("Passphrase")?;

    let vault = locked
        .unlock(CredentialKind::Passphrase, &passphrase)
        .context("that did not unlock the vault")?;

    if let Err(e) = vault.verify_chain() {
        term::bad("THIS VAULT HAS BEEN INTERFERED WITH");
        term::note(&format!("{e}"));
        term::note("Someone with access to the vault directory has edited its history.");
        term::note("Do not trust what it shows until you understand why.");
        anyhow::bail!("refusing to continue with a broken event chain");
    }

    Ok(vault)
}

fn init(
    path: &std::path::Path,
    argon: Argon2Params,
    unrecoverable: bool,
    now: zdd_core::clock::Timestamp,
) -> Result<()> {
    if path.join("header.json").exists() {
        anyhow::bail!("a vault already exists at {}", path.display());
    }

    term::heading("Create a vault");
    term::note("Your passphrase is the only thing protecting everything you put in here.");
    term::note("Long and memorable beats short and clever: four or five unrelated words.");
    println!();

    let passphrase = term::passphrase("Choose a passphrase")?;
    let again = term::passphrase("Type it again")?;
    if passphrase != again {
        anyhow::bail!("those did not match; nothing was created");
    }
    if passphrase.len() < 8 {
        anyhow::bail!("that passphrase is too short to protect anything");
    }

    let policy = if unrecoverable {
        term::warn("This vault will have no recovery path, ever.");
        term::note("If you forget the passphrase, you will never open it again.");
        term::note("Your capsules will still reach their recipients on schedule.");
        if !term::confirm("Create an unrecoverable vault?")? {
            anyhow::bail!("nothing was created");
        }
        RecoveryPolicy::Unrecoverable
    } else {
        RecoveryPolicy::Standard
    };

    let vault = OpenVault::create(path, &passphrase, argon, policy, now)?;

    term::good(&format!(
        "vault {} created at {}",
        vault.header().short_id(),
        path.display()
    ));
    println!();
    term::note("Next:");
    term::note("  zdd status     see where things stand");
    term::note("  zdd checkin    prove you are still here");

    if !unrecoverable {
        println!();
        term::warn("You have no recovery sheet yet.");
        term::note("Until you print one, a forgotten passphrase means permanent loss.");
    }
    Ok(())
}

fn status(path: &std::path::Path, json: bool) -> Result<()> {
    let vault = open(path)?;
    let clock = SystemClock;
    let now = clock.now();

    let vigil = vault
        .load_vigil()?
        .unwrap_or_else(|| VigilState::starting_at(now));
    let config = LadderConfig::default();
    let capsules = vault.list_capsules()?;

    let stage = policy::evaluate(&config, &vigil, 3, now, false);
    let silence = now.since(vigil.last_checkin);

    if json {
        let out = serde_json::json!({
            "vault": vault.header().short_id(),
            "stage": stage.summary(),
            "silence_secs": silence,
            "checkin_counter": vigil.checkin_counter,
            "capsules": capsules.iter().map(|c| serde_json::json!({
                "id": c.id.short(),
                "seal": c.seal().short(),
                "recipients": c.recipients.len(),
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    term::heading("Vigil");
    term::field("State", stage.summary());
    term::field("Quiet for", &term::duration(silence));
    term::field("Check-in", &format!("#{}", vigil.checkin_counter));

    let due = config.next_due(vigil.last_checkin);
    if now < due {
        term::field("Next due in", &term::duration(due.since(now)));
    } else {
        term::field("Overdue by", &term::duration(now.since(due)));
    }

    term::heading(&format!("Capsules ({})", capsules.len()));
    if capsules.is_empty() {
        term::note("None yet.");
    }
    for capsule in &capsules {
        println!();
        term::field("Seal", &capsule.seal().short());
        term::field("Id", &capsule.id.short());
        term::field("Recipients", &capsule.recipients.len().to_string());
        term::field("Figure", &zdd_seal::describe(capsule.seal().seal_seed()));
    }
    Ok(())
}

fn checkin(path: &std::path::Path) -> Result<()> {
    let mut vault = open(path)?;
    let now = SystemClock.now();

    let mut vigil = vault
        .load_vigil()?
        .unwrap_or_else(|| VigilState::starting_at(now));
    vigil.check_in(now, false);
    vault.save_vigil(&vigil, now)?;

    term::good(&format!("checked in — #{}", vigil.checkin_counter));
    let config = LadderConfig::default();
    term::note(&format!(
        "next check-in due in {}",
        term::duration(config.checkin_interval)
    ));
    Ok(())
}

fn verify(path: &std::path::Path) -> Result<()> {
    let vault = open(path)?;
    let events = vault.events()?;
    term::good(&format!(
        "event chain verified across {} entries",
        events.len()
    ));

    let mut missing = 0;
    for capsule in vault.list_capsules()? {
        if let Some(payload) = &capsule.payload {
            let id = zdd_store::BlobId(payload.blob_id);
            if !vault.blobs().exists(id) {
                term::warn(&format!(
                    "capsule {} is missing its payload",
                    capsule.id.short()
                ));
                missing += 1;
            }
        }
    }

    if missing == 0 {
        term::good("every capsule's payload is present");
    } else {
        anyhow::bail!("{missing} capsules are missing their payload");
    }
    Ok(())
}

fn keygen(out: &std::path::Path) -> Result<()> {
    use zdd_core::identity::RecipientIdentity;

    if out.exists() {
        anyhow::bail!(
            "{} already exists; refusing to overwrite a key",
            out.display()
        );
    }

    let identity = RecipientIdentity::generate();
    let secret = identity.export_secret();

    let doc = serde_json::json!({
        "kind": "zdd-recipient-key",
        "version": 1,
        "public": identity.public(),
        "secret": zdd_core::codec::to_hex(secret.expose()),
    });
    std::fs::write(out, serde_json::to_string_pretty(&doc)?)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(out, std::fs::Permissions::from_mode(0o600));
    }

    term::good(&format!("key written to {}", out.display()));
    term::field("Fingerprint", &identity.public().fingerprint().short());
    println!();
    term::note("Give the FINGERPRINT and the public key to whoever is sealing a capsule for you.");
    term::warn("The file itself is your private key. It is not encrypted.");
    term::note("Anyone who copies it can open anything sealed to you. Back it up somewhere safe,");
    term::note("and do not send it to the person sealing the capsule — they do not need it.");
    Ok(())
}
