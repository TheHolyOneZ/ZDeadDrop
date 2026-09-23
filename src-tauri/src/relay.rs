use std::time::Duration;

use zdd_core::checkin::{Receipt, SignedCheckIn};
use zdd_core::identity::VaultPublicIdentity;

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("zdeaddrop/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

pub fn normalise(url: &str) -> Result<String, String> {
    let t = url.trim().trim_end_matches('/');
    if t.is_empty() {
        return Err("Enter the relay's address.".into());
    }
    let with_scheme = if t.starts_with("http://") || t.starts_with("https://") {
        t.to_string()
    } else {
        format!("https://{t}")
    };
    let parsed = reqwest::Url::parse(&with_scheme).map_err(|_| "That is not a web address.")?;

    if parsed.scheme() == "http" {
        let host = parsed.host_str().unwrap_or_default();
        let local = host == "localhost"
            || host.starts_with("127.")
            || host.starts_with("192.168.")
            || host.starts_with("10.")
            || host.ends_with(".local");
        if !local {
            return Err(
                "A relay on the internet must use https — check-ins sent in the clear can be \
                 dropped by anyone on the path."
                    .into(),
            );
        }
    }
    Ok(with_scheme)
}

fn describe(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "The relay did not answer in time.".into()
    } else if e.is_connect() {
        "Could not reach the relay.".into()
    } else {
        "The relay gave an answer this app could not read.".into()
    }
}

pub async fn fetch_key(base: &str) -> Result<String, String> {
    let res = client()?
        .get(format!("{base}/v1/key"))
        .send()
        .await
        .map_err(describe)?;
    if !res.status().is_success() {
        return Err(format!("The relay refused: {}", res.status()));
    }
    let body: serde_json::Value = res.json().await.map_err(describe)?;
    let key = body["verifying_key"]
        .as_str()
        .ok_or("That server does not look like a ZDeadDrop relay.")?;
    let bytes = zdd_core::codec::from_hex(key).ok_or("The relay's key is malformed.")?;
    if bytes.len() != 32 {
        return Err("The relay's key is malformed.".into());
    }
    Ok(key.to_string())
}

pub async fn enroll(
    base: &str,
    vault: &str,
    identity: &VaultPublicIdentity,
    silence_threshold: u64,
    contact: Option<&str>,
) -> Result<(), String> {
    let body = serde_json::json!({
        "vault": vault,
        "identity": identity,
        "relay_share": null,
        "silence_threshold": silence_threshold,
        "owner_contact": contact,
        "trustees": [],
    });
    let res = client()?
        .post(format!("{base}/v1/vault"))
        .json(&body)
        .send()
        .await
        .map_err(describe)?;

    if res.status().is_success() || res.status() == reqwest::StatusCode::CONFLICT {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!(
            "The relay refused to enrol this vault: {}",
            text.trim()
        ))
    }
}

pub async fn last_counter(base: &str, vault: &str) -> Result<u64, String> {
    let res = client()?
        .get(format!("{base}/v1/vault/{vault}/status"))
        .send()
        .await
        .map_err(describe)?;
    if !res.status().is_success() {
        return Ok(0);
    }
    let body: serde_json::Value = res.json().await.map_err(describe)?;
    Ok(body["last_counter"].as_u64().unwrap_or(0))
}

pub async fn settings(
    base: &str,
    vault: &str,
    set: &zdd_core::checkin::SignedSettings,
) -> Result<(), String> {
    let res = client()?
        .post(format!("{base}/v1/vault/{vault}/settings"))
        .json(set)
        .send()
        .await
        .map_err(describe)?;
    if res.status().is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!("The relay refused your settings: {}", text.trim()))
    }
}

pub async fn deposit_share(
    base: &str,
    vault: &str,
    deposit: &zdd_core::release::ShareDeposit,
) -> Result<(), String> {
    let res = client()?
        .post(format!("{base}/v1/vault/{vault}/shares"))
        .json(deposit)
        .send()
        .await
        .map_err(describe)?;
    if res.status().is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!("The relay refused the piece: {}", text.trim()))
    }
}

pub async fn hold(
    base: &str,
    vault: &str,
    notice: &zdd_core::checkin::SignedHold,
) -> Result<(), String> {
    let res = client()?
        .post(format!("{base}/v1/vault/{vault}/hold"))
        .json(notice)
        .send()
        .await
        .map_err(describe)?;
    if res.status().is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!("The relay refused the hold: {}", text.trim()))
    }
}

pub async fn trustees(
    base: &str,
    vault: &str,
    list: &zdd_core::checkin::SignedTrustees,
) -> Result<(), String> {
    let res = client()?
        .post(format!("{base}/v1/vault/{vault}/trustees"))
        .json(list)
        .send()
        .await
        .map_err(describe)?;
    if res.status().is_success() {
        Ok(())
    } else {
        let text = res.text().await.unwrap_or_default();
        Err(format!(
            "The relay refused the trustee list: {}",
            text.trim()
        ))
    }
}

pub async fn check_in(
    base: &str,
    vault: &str,
    record: &SignedCheckIn,
    pinned_key: &str,
) -> Result<(), String> {
    let key: [u8; 32] = zdd_core::codec::from_hex(pinned_key)
        .and_then(|b| b.try_into().ok())
        .ok_or("The pinned relay key is damaged; reconnect the relay.")?;

    let res = client()?
        .post(format!("{base}/v1/vault/{vault}/checkin"))
        .json(record)
        .send()
        .await
        .map_err(describe)?;
    if !res.status().is_success() {
        let text = res.text().await.unwrap_or_default();
        return Err(format!("The relay refused the check-in: {}", text.trim()));
    }
    let receipt: Receipt = res.json().await.map_err(describe)?;
    if !receipt.verify(record, &key) {
        return Err(
            "The relay's receipt does not verify. It may be dropping or rewriting \
                    check-ins — do not rely on it until you know why."
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hosts_get_https() {
        assert_eq!(
            normalise("relay.example.org/").unwrap(),
            "https://relay.example.org"
        );
    }

    #[test]
    fn plain_http_is_only_for_local_relays() {
        assert!(normalise("http://127.0.0.1:8787").is_ok());
        assert!(normalise("http://pi.local").is_ok());
        assert!(normalise("http://relay.example.org").is_err());
    }
}
