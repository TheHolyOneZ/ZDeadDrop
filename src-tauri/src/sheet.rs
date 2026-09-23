use std::str::FromStr;

use zdd_core::secret::SecretBytes;

pub struct Sheet {
    pub words: Vec<String>,
    pub credential: SecretBytes,
}

pub fn generate() -> Sheet {
    let entropy = zdd_core::secret::Key32::random();
    let mnemonic = bip39::Mnemonic::from_entropy(entropy.expose())
        .expect("32 bytes is a valid BIP39 entropy length");
    Sheet {
        words: mnemonic.words().map(str::to_string).collect(),
        credential: SecretBytes::from_slice(entropy.expose()),
    }
}

pub fn read(typed: &str) -> Result<SecretBytes, String> {
    let checked = zdd_import::secrets::seed_phrase("recovery sheet", typed)
        .map_err(|e| e.to_string().replace("seed phrase", "recovery sheet"))?;
    let text = std::str::from_utf8(checked.body()).map_err(|_| "unreadable words".to_string())?;
    let mnemonic = bip39::Mnemonic::from_str(text).map_err(|e| e.to_string())?;
    if mnemonic.word_count() != 24 {
        return Err(format!(
            "a recovery sheet has 24 words; this has {}",
            mnemonic.word_count()
        ));
    }
    Ok(SecretBytes::new(mnemonic.to_entropy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sheet_reads_back_to_the_same_credential() {
        let sheet = generate();
        assert_eq!(sheet.words.len(), 24);
        let typed = sheet.words.join(" ");
        assert_eq!(read(&typed).unwrap(), sheet.credential);
    }

    #[test]
    fn spacing_and_case_do_not_matter() {
        let sheet = generate();
        let messy = format!("  {}\n", sheet.words.join("   ").to_uppercase());
        assert_eq!(read(&messy).unwrap(), sheet.credential);
    }

    #[test]
    fn a_wrong_word_is_named() {
        let sheet = generate();
        let mut words = sheet.words.clone();
        words[6] = "notaword".into();
        let err = read(&words.join(" ")).unwrap_err();
        assert!(err.contains("word 7"), "{err}");
    }

    #[test]
    fn a_short_phrase_is_refused() {
        let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon about";
        assert!(read(twelve).unwrap_err().contains("24"));
    }
}
