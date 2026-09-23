use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use zdd_core::checkin::{find_gaps, read_envelope, SignedCheckIn};
use zdd_core::clock::{Clock, SystemClock};
use zdd_core::identity::VaultPublicIdentity;
use zdd_core::secret::Key32;

use crate::term;

#[derive(ClapArgs)]
pub struct Args {
    #[doc = " The share file you were given."]
    share: PathBuf,

    #[doc = " The relay's address, if the share file does not name one."]
    #[arg(long)]
    relay: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let text = std::fs::read_to_string(&args.share)
        .with_context(|| format!("could not read {}", args.share.display()))?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).context("that does not look like a share file")?;
    if doc["kind"] != "zdd-trustee-share" {
        anyhow::bail!("that is not a trustee share file");
    }

    let vault = doc["vault"]
        .as_str()
        .context("the share file names no vault")?;
    let identity: VaultPublicIdentity = serde_json::from_value(doc["identity"].clone())
        .context("the share file's identity is damaged")?;
    let key = doc["duress_key"]
        .as_str()
        .and_then(zdd_core::codec::from_hex)
        .and_then(|b| Key32::from_slice(&b).ok())
        .context("the share file has no duress key")?;
    let relay = args
        .relay
        .or_else(|| doc["relay"].as_str().map(str::to_string))
        .context("no relay is named; pass --relay with its address")?;
    let relay = relay.trim_end_matches('/');

    if identity.vigil_fingerprint().short() != vault {
        anyhow::bail!(
            "the share file's identity does not match its vault; it may have been edited"
        );
    }

    let who = doc["capsule"].as_str().unwrap_or("this capsule");
    term::heading(&format!("Checking on the owner of “{who}”"));

    let body: serde_json::Value = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?
        .get(format!("{relay}/v1/vault/{vault}/log"))
        .send()
        .context("could not reach the relay")?
        .error_for_status()
        .context("the relay refused")?
        .json()
        .context("the relay's answer could not be read")?;

    let records: Vec<SignedCheckIn> = serde_json::from_value(body["records"].clone())
        .context("the relay's log could not be read")?;

    for r in &records {
        if r.verify(&identity).is_err() {
            term::bad("The relay's log contains a check-in the owner did not sign.");
            term::note("Do not trust this relay. Tell the other trustees.");
            anyhow::bail!("forged check-in in the relay's log");
        }
    }

    let Some(latest) = records.iter().max_by_key(|r| r.checkin.counter) else {
        term::warn("The owner has never checked in at this relay.");
        return Ok(());
    };

    let gaps = find_gaps(&records);
    let duress = read_envelope(
        &key,
        &latest.checkin.duress_envelope,
        &latest.checkin.vault,
        latest.checkin.counter,
    )
    .context("the duress key in your share file does not fit this vault")?;

    let now = SystemClock.now();
    term::field("Check-ins", &records.len().to_string());
    term::field(
        "Latest",
        &format!(
            "#{} — {} ago",
            latest.checkin.counter,
            term::duration(now.since(latest.checkin.asserted_at))
        ),
    );
    println!();

    if duress {
        term::bad("THE LATEST CHECK-IN WAS MADE UNDER DURESS.");
        term::note("The owner signalled that someone was forcing them. Do not treat it as a");
        term::note("sign they are safe. Contact the other trustees, and anyone who can help.");
    } else {
        term::good("The latest check-in was made freely.");
    }

    if !gaps.is_empty() {
        println!();
        term::warn(&format!(
            "{} check-in{} missing from the relay's log.",
            gaps.len(),
            if gaps.len() == 1 { " is" } else { "s are" }
        ));
        term::note("The relay may be hiding check-ins. Tell the other trustees.");
    }
    Ok(())
}
