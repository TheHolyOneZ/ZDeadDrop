pub mod base64_bytes {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        STANDARD.decode(&encoded).map_err(serde::de::Error::custom)
    }
}

pub mod base64_array {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let encoded = String::deserialize(d)?;
        let decoded = STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        decoded.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected {N} bytes, found {}", v.len()))
        })
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn fingerprint_string(bytes: &[u8], groups: usize) -> String {
    let hex = to_hex(bytes);
    hex.as_bytes()
        .chunks(4)
        .take(groups)
        .map(|c| core::str::from_utf8(c).unwrap_or("????").to_string())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = vec![0x00, 0x0f, 0xf0, 0xff, 0xab];
        assert_eq!(to_hex(&data), "000ff0ffab");
        assert_eq!(from_hex("000ff0ffab").unwrap(), data);
    }

    #[test]
    fn hex_rejects_malformed() {
        assert!(from_hex("abc").is_none(), "odd length must be rejected");
        assert!(from_hex("zz").is_none(), "non-hex digits must be rejected");
        assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn fingerprint_is_grouped_and_capped() {
        let bytes = [0x9f, 0x2a, 0xc4, 0x1d, 0x88, 0xbe, 0x01, 0x73, 0xde, 0xad];
        assert_eq!(fingerprint_string(&bytes, 4), "9f2a-c41d-88be-0173");
        assert_eq!(fingerprint_string(&bytes, 2), "9f2a-c41d");
        assert_eq!(fingerprint_string(&bytes, 99), "9f2a-c41d-88be-0173-dead");
    }

    #[test]
    fn base64_field_round_trips() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "super::base64_bytes")]
            v: Vec<u8>,
        }
        let t = T {
            v: vec![0, 1, 2, 250, 255],
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains('"'), "binary field should be a JSON string");
        assert_eq!(serde_json::from_str::<T>(&json).unwrap(), t);
    }

    #[test]
    fn base64_array_rejects_wrong_length() {
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct T {
            #[serde(with = "super::base64_array")]
            v: [u8; 4],
        }
        let good = serde_json::to_string(&T { v: [1, 2, 3, 4] }).unwrap();
        assert!(serde_json::from_str::<T>(&good).is_ok());
        assert!(
            serde_json::from_str::<T>(r#"{"v":"AQID"}"#).is_err(),
            "3 bytes into [u8;4]"
        );
    }
}
