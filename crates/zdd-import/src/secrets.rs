use zeroize::Zeroize;

use crate::error::{ImportError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Credential,
    TotpSeed,
    SshKey,
    GpgKey,
    SeedPhrase,
    RecoveryCodes,
    Certificate,
    Note,
}

#[derive(zeroize::ZeroizeOnDrop)]
pub struct Secret {
    #[zeroize(skip)]
    pub kind: SecretKind,
    #[zeroize(skip)]
    pub label: String,

    #[zeroize(skip)]
    pub context: Vec<(String, String)>,
    body: Vec<u8>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secret")
            .field("kind", &self.kind)
            .field("label", &self.label)
            .field("body", &format_args!("{} bytes, redacted", self.body.len()))
            .finish()
    }
}

impl Secret {
    pub fn new(kind: SecretKind, label: impl Into<String>, body: Vec<u8>) -> Self {
        Self {
            kind,
            label: label.into(),
            context: Vec::new(),
            body,
        }
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn len(&self) -> usize {
        self.body.len()
    }

    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }
}

pub fn seed_phrase(label: &str, words: &str) -> Result<Secret> {
    use std::str::FromStr;

    let normalised = words
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let count = normalised.split_whitespace().count();

    if !matches!(count, 12 | 15 | 18 | 21 | 24) {
        return Err(ImportError::Invalid {
            what: "seed phrase",
            detail: format!("a BIP39 phrase has 12, 15, 18, 21 or 24 words; this has {count}"),
        });
    }

    let mnemonic = bip39::Mnemonic::from_str(&normalised).map_err(|e| {
        let detail = match e {
            bip39::Error::UnknownWord(index) => {
                let word = normalised.split_whitespace().nth(index).unwrap_or("?");
                format!(
                    "word {} (\"{word}\") is not in the BIP39 word list",
                    index + 1
                )
            }
            bip39::Error::InvalidChecksum => {
                "the checksum does not match — one of these words is wrong, \
                 or two are swapped"
                    .to_string()
            }
            other => other.to_string(),
        };
        ImportError::Invalid {
            what: "seed phrase",
            detail,
        }
    })?;

    let mut text = mnemonic.to_string();
    let secret = Secret::new(SecretKind::SeedPhrase, label, text.as_bytes().to_vec())
        .with_context("words", count.to_string());
    text.zeroize();
    Ok(secret)
}

pub fn totp(uri: &str) -> Result<Secret> {
    let rest = uri
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| ImportError::Invalid {
            what: "2FA seed",
            detail: "expected a URI starting with otpauth://totp/".into(),
        })?;

    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode(path);

    let mut secret_b32 = None;
    let mut issuer = None;
    let mut digits = "6".to_string();
    let mut period = "30".to_string();

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "secret" => secret_b32 = Some(value.to_string()),
            "issuer" => issuer = Some(percent_decode(value)),
            "digits" => digits = value.to_string(),
            "period" => period = value.to_string(),
            _ => {}
        }
    }

    let b32 = secret_b32.ok_or_else(|| ImportError::Invalid {
        what: "2FA seed",
        detail: "the URI has no secret= parameter".into(),
    })?;

    let decoded = base32_decode(&b32).ok_or_else(|| ImportError::Invalid {
        what: "2FA seed",
        detail: "the secret is not valid base32; it may have been copied incompletely".into(),
    })?;

    if decoded.len() < 10 {
        return Err(ImportError::Invalid {
            what: "2FA seed",
            detail: format!(
                "the secret decodes to only {} bytes, which is too short to be a real \
                 2FA seed",
                decoded.len()
            ),
        });
    }

    let mut secret = Secret::new(SecretKind::TotpSeed, label, uri.as_bytes().to_vec())
        .with_context("digits", digits)
        .with_context("period", period);
    if let Some(issuer) = issuer {
        secret = secret.with_context("issuer", issuer);
    }
    Ok(secret)
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();

    for ch in input.chars() {
        if ch == '=' || ch.is_whitespace() || ch == '-' {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let value = ALPHABET.iter().position(|&a| a == upper)? as u32;

        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }

    if bits >= 5 || (buffer & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn ssh_key(label: &str, contents: &str) -> Result<Secret> {
    let trimmed = contents.trim();

    if trimmed.starts_with("ssh-") || trimmed.starts_with("ecdsa-") {
        return Err(ImportError::Invalid {
            what: "SSH key",
            detail: "this is a public key. The private key is the file without .pub, \
                     and it begins with -----BEGIN"
                .into(),
        });
    }

    if !trimmed.starts_with("-----BEGIN") {
        return Err(ImportError::Invalid {
            what: "SSH key",
            detail: "expected a file beginning with -----BEGIN".into(),
        });
    }

    if !trimmed.ends_with("-----") {
        return Err(ImportError::Invalid {
            what: "SSH key",
            detail: "the key is missing its closing -----END line; it may have been \
                     copied incompletely"
                .into(),
        });
    }

    let encrypted = trimmed.contains("ENCRYPTED") || trimmed.contains("Proc-Type: 4,ENCRYPTED");

    Ok(
        Secret::new(SecretKind::SshKey, label, trimmed.as_bytes().to_vec())
            .with_context("encrypted", encrypted.to_string()),
    )
}

pub fn recovery_codes(label: &str, text: &str) -> Result<Secret> {
    let codes: Vec<&str> = text
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    if codes.is_empty() {
        return Err(ImportError::Invalid {
            what: "recovery codes",
            detail: "no codes were found in that text".into(),
        });
    }

    Ok(Secret::new(
        SecretKind::RecoveryCodes,
        label,
        codes.join("\n").into_bytes(),
    )
    .with_context("count", codes.len().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn a_valid_seed_phrase_is_accepted() {
        let s = seed_phrase("Cold wallet", VALID).unwrap();
        assert_eq!(s.kind, SecretKind::SeedPhrase);
        assert!(s.context.iter().any(|(k, v)| k == "words" && v == "12"));
    }

    #[test]
    fn a_mistyped_word_is_caught_by_the_checksum() {
        let broken = VALID.replace("about", "abandon");
        let err = seed_phrase("Cold wallet", &broken).unwrap_err();
        assert!(
            format!("{err}").contains("checksum"),
            "the checksum must catch a swapped word: {err}"
        );
    }

    #[test]
    fn a_word_outside_the_list_is_named() {
        let broken = VALID.replace("about", "qwertyx");
        let err = seed_phrase("w", &broken).unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("qwertyx"),
            "the bad word should be named: {text}"
        );
        assert!(text.contains("12"), "its position should be named: {text}");
    }

    #[test]
    fn the_wrong_word_count_is_rejected() {
        let err = seed_phrase("w", "abandon abandon abandon").unwrap_err();
        assert!(format!("{err}").contains("12, 15, 18, 21 or 24"));
    }

    #[test]
    fn extra_whitespace_and_case_are_tolerated() {
        let messy = format!("  {}  ", VALID.to_uppercase().replace(' ', "   "));
        assert!(seed_phrase("w", &messy).is_ok(), "people paste untidily");
    }

    #[test]
    fn a_real_totp_uri_parses() {
        let uri = "otpauth://totp/GitHub:alex?secret=JBSWY3DPEHPK3PXPJBSWY3DP&issuer=GitHub&digits=6&period=30";
        let s = totp(uri).unwrap();
        assert_eq!(s.kind, SecretKind::TotpSeed);
        assert_eq!(s.label, "GitHub:alex");
        assert!(s
            .context
            .iter()
            .any(|(k, v)| k == "issuer" && v == "GitHub"));
    }

    #[test]
    fn a_totp_secret_that_is_not_base32_is_refused() {
        let uri = "otpauth://totp/x?secret=not!valid!base32!!!";
        let err = totp(uri).unwrap_err();
        assert!(format!("{err}").contains("base32"));
    }

    #[test]
    fn a_truncated_totp_secret_is_refused() {
        let short = totp("otpauth://totp/x?secret=JBSWY3DP").unwrap_err();
        assert!(format!("{short}").contains("too short"), "got {short}");

        let ragged = totp("otpauth://totp/x?secret=JBSW").unwrap_err();
        assert!(
            format!("{ragged}").contains("incompletely"),
            "a ragged truncation should still say it looks incomplete: {ragged}"
        );
    }

    #[test]
    fn a_totp_uri_without_a_secret_is_refused() {
        assert!(totp("otpauth://totp/x?issuer=y").is_err());
        assert!(totp("https://example.com").is_err());
    }

    #[test]
    fn totp_labels_are_percent_decoded() {
        let s = totp("otpauth://totp/Big%20Bank%3Aalex?secret=JBSWY3DPEHPK3PXPJBSWY3DP").unwrap();
        assert_eq!(s.label, "Big Bank:alex");
    }

    #[test]
    fn base32_tolerates_the_shapes_authenticators_actually_emit() {
        assert_eq!(base32_decode("JBSWY3DP"), Some(b"Hello".to_vec()));
        assert_eq!(base32_decode("jbswy3dp"), Some(b"Hello".to_vec()));
        assert_eq!(base32_decode("JBSW-Y3DP"), Some(b"Hello".to_vec()));
        assert_eq!(base32_decode("MZXW6==="), Some(b"foo".to_vec()));
        assert_eq!(base32_decode("!!!"), None);
    }

    #[test]
    fn an_ssh_private_key_is_accepted() {
        let key =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza\n-----END OPENSSH PRIVATE KEY-----";
        let s = ssh_key("server", key).unwrap();
        assert_eq!(s.kind, SecretKind::SshKey);
    }

    #[test]
    fn pasting_the_public_key_is_explained() {
        let err = ssh_key("server", "ssh-ed25519 AAAAC3Nza alex@laptop").unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("public key"), "got {text}");
        assert!(
            text.contains(".pub"),
            "the message must say where the private key is: {text}"
        );
    }

    #[test]
    fn a_truncated_key_is_refused() {
        let err = ssh_key("server", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb").unwrap_err();
        assert!(format!("{err}").contains("incompletely"));
    }

    #[test]
    fn an_encrypted_key_is_noted() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nx\n-----END RSA PRIVATE KEY-----";
        let s = ssh_key("server", key).unwrap();
        assert!(s
            .context
            .iter()
            .any(|(k, v)| k == "encrypted" && v == "true"));
    }

    #[test]
    fn recovery_codes_split_on_anything_reasonable() {
        let s = recovery_codes("GitHub", "abcd-1234\nefgh-5678, ijkl-9012").unwrap();
        assert!(s.context.iter().any(|(k, v)| k == "count" && v == "3"));
        assert_eq!(s.body(), b"abcd-1234\nefgh-5678\nijkl-9012");
    }

    #[test]
    fn empty_recovery_codes_are_refused() {
        assert!(recovery_codes("x", "   \n  ").is_err());
    }

    #[test]
    fn debug_never_reveals_a_secret_body() {
        let s = seed_phrase("Cold wallet", VALID).unwrap();
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"));
        assert!(!rendered.contains("abandon"));
    }
}
