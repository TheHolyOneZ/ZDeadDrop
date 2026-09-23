use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Result, SharingError};
use crate::secret::{Key32, SecretBytes};

#[inline]
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut result: u8 = 0;
    let mut a = a;
    let mut b = b;

    for _ in 0..8 {
        let mask = (b & 1).wrapping_neg();
        result ^= a & mask;

        let overflow = ((a >> 7) & 1).wrapping_neg();
        a = (a << 1) ^ (0x1B & overflow);

        b >>= 1;
    }
    result
}

#[inline]
fn gf_inv(a: u8) -> u8 {
    let mut result: u8 = 1;
    let mut base = a;
    let mut exp: u32 = 254;

    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    result
}

#[inline]
fn gf_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc: u8 = 0;
    for &c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SplitId(#[serde(with = "crate::codec::base64_array")] pub [u8; 16]);

impl SplitId {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        Self(id)
    }

    pub fn short(&self) -> String {
        crate::codec::fingerprint_string(&self.0, 2)
    }
}

const COMMITMENT_LEN: usize = 8;

fn commit(split_id: &SplitId, secret: &[u8]) -> [u8; COMMITMENT_LEN] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"zdd/v1/shamir-commitment");
    hasher.update(&split_id.0);
    hasher.update(secret);
    let hash = hasher.finalize();
    let mut out = [0u8; COMMITMENT_LEN];
    out.copy_from_slice(&hash.as_bytes()[..COMMITMENT_LEN]);
    out
}

#[derive(ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct Share {
    #[zeroize(skip)]
    pub index: u8,

    #[zeroize(skip)]
    pub threshold: u8,

    #[zeroize(skip)]
    pub split_id: SplitId,

    #[zeroize(skip)]
    #[serde(with = "crate::codec::base64_array")]
    pub commitment: [u8; COMMITMENT_LEN],

    #[serde(with = "crate::codec::base64_bytes")]
    data: Vec<u8>,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("threshold", &self.threshold)
            .field("split_id", &self.split_id.short())
            .field("data", &format_args!("{} bytes, redacted", self.data.len()))
            .finish()
    }
}

impl Share {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| crate::Error::Encoding(e.to_string()))
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| crate::Error::Encoding(e.to_string()))
    }
}

pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>> {
    use rand::RngCore;

    if threshold < 2 {
        return Err(SharingError::ThresholdTooLow(threshold).into());
    }
    if total < 2 {
        return Err(SharingError::ShareCountOutOfRange(total as u16).into());
    }
    if threshold > total {
        return Err(SharingError::ThresholdTooHigh { threshold, total }.into());
    }
    if secret.is_empty() {
        return Err(SharingError::MismatchedLength.into());
    }

    let split_id = SplitId::random();
    let commitment = commit(&split_id, secret);

    let mut coeffs = vec![0u8; threshold as usize];
    let mut shares: Vec<Share> = (1..=total)
        .map(|index| Share {
            index,
            threshold,
            split_id,
            commitment,
            data: vec![0u8; secret.len()],
        })
        .collect();

    for (byte_pos, &secret_byte) in secret.iter().enumerate() {
        coeffs[0] = secret_byte;
        rand::rngs::OsRng.fill_bytes(&mut coeffs[1..]);

        while coeffs[threshold as usize - 1] == 0 {
            rand::rngs::OsRng.fill_bytes(&mut coeffs[threshold as usize - 1..]);
        }

        for share in &mut shares {
            share.data[byte_pos] = gf_eval(&coeffs, share.index);
        }
    }

    coeffs.zeroize();
    Ok(shares)
}

pub fn split_key(key: &Key32, threshold: u8, total: u8) -> Result<Vec<Share>> {
    split(key.expose(), threshold, total)
}

pub fn combine(shares: &[Share]) -> Result<SecretBytes> {
    if shares.is_empty() {
        return Err(SharingError::InsufficientShares {
            needed: 2,
            supplied: 0,
        }
        .into());
    }

    let threshold = shares[0].threshold;
    let split_id = shares[0].split_id;
    let commitment = shares[0].commitment;
    let len = shares[0].data.len();

    if shares.len() < threshold as usize {
        return Err(SharingError::InsufficientShares {
            needed: threshold,
            supplied: shares.len(),
        }
        .into());
    }

    for s in shares {
        if s.split_id != split_id {
            return Err(SharingError::MismatchedLength.into());
        }
        if s.data.len() != len {
            return Err(SharingError::MismatchedLength.into());
        }
        if s.index == 0 {
            return Err(SharingError::ZeroIndex.into());
        }
    }

    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.index == b.index {
                return Err(SharingError::DuplicateIndex(a.index).into());
            }
        }
    }

    let used = &shares[..threshold as usize];

    let mut secret = SecretBytes::zeroed(len);
    for (j, share_j) in used.iter().enumerate() {
        let mut numerator: u8 = 1;
        let mut denominator: u8 = 1;
        for (m, share_m) in used.iter().enumerate() {
            if m == j {
                continue;
            }
            numerator = gf_mul(numerator, share_m.index);
            denominator = gf_mul(denominator, share_m.index ^ share_j.index);
        }
        let basis = gf_mul(numerator, gf_inv(denominator));

        for (pos, out) in secret.expose_mut().iter_mut().enumerate() {
            *out ^= gf_mul(share_j.data[pos], basis);
        }
    }

    let actual = commit(&split_id, secret.expose());
    if !bool::from(actual.ct_eq(&commitment)) {
        return Err(SharingError::MismatchedLength.into());
    }

    Ok(secret)
}

pub fn combine_key(shares: &[Share]) -> Result<Key32> {
    let secret = combine(shares)?;
    Key32::from_slice(secret.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_identities() {
        for a in 0..=255u8 {
            assert_eq!(gf_mul(a, 0), 0);
            assert_eq!(gf_mul(0, a), 0);
            assert_eq!(gf_mul(a, 1), a);
            assert_eq!(gf_mul(1, a), a);
        }
    }

    #[test]
    fn gf_mul_is_commutative_and_associative() {
        for a in (0..=255u8).step_by(17) {
            for b in (0..=255u8).step_by(13) {
                assert_eq!(gf_mul(a, b), gf_mul(b, a));
                for c in (0..=255u8).step_by(29) {
                    assert_eq!(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
                }
            }
        }
    }

    #[test]
    fn gf_mul_known_answers() {
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x57, 0x13), 0xFE);
        assert_eq!(gf_mul(0x02, 0x87), 0x15);
        assert_eq!(gf_mul(0x03, 0x6E), 0xB2);
        assert_eq!(gf_mul(0xD4, 0x02), 0xB3);
    }

    #[test]
    fn gf_inv_is_a_true_inverse() {
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse failed for {a}");
        }
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn gf_eval_matches_manual_expansion() {
        let coeffs = [3u8, 5, 7];
        for x in 0..=255u8 {
            let expected = 3 ^ gf_mul(5, x) ^ gf_mul(7, gf_mul(x, x));
            assert_eq!(gf_eval(&coeffs, x), expected);
        }
    }

    #[test]
    fn round_trips_with_exact_threshold() {
        let secret = b"a 32-byte capsule release key!!!";
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        let recovered = combine(&shares[..3]).unwrap();
        assert_eq!(recovered.expose(), secret);
    }

    #[test]
    fn every_threshold_subset_reconstructs() {
        let secret = b"another secret value ----------!";
        let shares = split(secret, 3, 5).unwrap();

        for i in 0..5 {
            for j in (i + 1)..5 {
                for k in (j + 1)..5 {
                    let subset = [
                        clone_share(&shares[i]),
                        clone_share(&shares[j]),
                        clone_share(&shares[k]),
                    ];
                    let recovered = combine(&subset).unwrap();
                    assert_eq!(recovered.expose(), secret, "subset {i},{j},{k} failed");
                }
            }
        }
    }

    #[test]
    fn extra_shares_are_accepted() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 2, 5).unwrap();
        assert_eq!(combine(&shares).unwrap().expose(), secret);
    }

    #[test]
    fn too_few_shares_are_refused() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 4, 6).unwrap();
        for n in 0..4 {
            assert!(
                combine(&shares[..n]).is_err(),
                "{n} shares must not reconstruct a 4-of-6 split"
            );
        }
        assert!(combine(&shares[..4]).is_ok());
    }

    #[test]
    fn duplicate_shares_cannot_fake_a_quorum() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 2, 3).unwrap();
        let doubled = [clone_share(&shares[0]), clone_share(&shares[0])];
        let err = combine(&doubled).unwrap_err();
        assert!(matches!(
            err,
            crate::Error::Sharing(SharingError::DuplicateIndex(_))
        ));
    }

    #[test]
    fn shares_from_different_splits_are_refused() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let a = split(secret, 2, 3).unwrap();
        let b = split(secret, 2, 3).unwrap();
        let mixed = [clone_share(&a[0]), clone_share(&b[1])];
        assert!(combine(&mixed).is_err());
    }

    #[test]
    fn a_corrupted_share_is_detected() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 3, 5).unwrap();

        let mut bad = clone_share(&shares[0]);
        bad.data[5] ^= 0x01;

        let attempt = [bad, clone_share(&shares[1]), clone_share(&shares[2])];
        assert!(
            combine(&attempt).is_err(),
            "a single flipped bit in one share must not yield a silently wrong secret"
        );
    }

    #[test]
    fn a_share_with_index_zero_is_refused() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 2, 3).unwrap();
        let mut bad = clone_share(&shares[0]);
        bad.index = 0;
        let attempt = [bad, clone_share(&shares[1])];
        assert!(matches!(
            combine(&attempt).unwrap_err(),
            crate::Error::Sharing(SharingError::ZeroIndex)
        ));
    }

    #[test]
    fn rejects_invalid_parameters() {
        let s = b"0123456789abcdef0123456789abcdef";
        assert!(split(s, 1, 5).is_err(), "1-of-N is not secret sharing");
        assert!(split(s, 0, 5).is_err());
        assert!(split(s, 6, 5).is_err(), "threshold above total");
        assert!(split(s, 2, 1).is_err());
        assert!(split(b"", 2, 3).is_err(), "empty secret");
    }

    #[test]
    fn supports_the_maximum_share_count() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let shares = split(secret, 200, 255).unwrap();
        assert_eq!(shares.len(), 255);
        assert_eq!(shares[254].index, 255);
        assert_eq!(combine(&shares[..200]).unwrap().expose(), secret);
    }

    #[test]
    fn key_helpers_round_trip() {
        let key = Key32::random();
        let shares = split_key(&key, 3, 5).unwrap();
        assert_eq!(combine_key(&shares[..3]).unwrap(), key);
    }

    #[test]
    fn shares_survive_json_transport() {
        let key = Key32::random();
        let shares = split_key(&key, 2, 3).unwrap();
        let wire: Vec<String> = shares.iter().map(|s| s.to_json().unwrap()).collect();
        let back: Vec<Share> = wire.iter().map(|j| Share::from_json(j).unwrap()).collect();
        assert_eq!(combine_key(&back[..2]).unwrap(), key);
    }

    #[test]
    fn debug_never_reveals_share_data() {
        let key = Key32::random();
        let shares = split_key(&key, 2, 3).unwrap();
        let rendered = format!("{:?}", shares[0]);
        assert!(rendered.contains("redacted"));
        let leaked = crate::codec::to_hex(&shares[0].data);
        assert!(
            !rendered.contains(&leaked[..8]),
            "debug output leaked share bytes"
        );
    }

    #[test]
    fn shares_differ_from_each_other() {
        let secret = [0u8; 32];
        let shares = split(&secret, 3, 5).unwrap();
        for i in 0..shares.len() {
            for j in (i + 1)..shares.len() {
                assert_ne!(shares[i].data, shares[j].data);
            }
            assert_ne!(shares[i].data, vec![0u8; 32], "share is the bare secret");
        }
        assert_eq!(combine(&shares[..3]).unwrap().expose(), &secret);
    }

    #[test]
    fn splits_are_randomised() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let a = split(secret, 3, 5).unwrap();
        let b = split(secret, 3, 5).unwrap();
        assert_ne!(a[0].data, b[0].data);
        assert_ne!(a[0].split_id, b[0].split_id);
    }

    #[test]
    fn handles_secrets_of_many_lengths() {
        for len in [1usize, 16, 32, 64, 1000] {
            let secret: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let shares = split(&secret, 3, 5).unwrap();
            assert_eq!(combine(&shares[..3]).unwrap().expose(), &secret[..]);
        }
    }

    fn clone_share(s: &Share) -> Share {
        Share {
            index: s.index,
            threshold: s.threshold,
            split_id: s.split_id,
            commitment: s.commitment,
            data: s.data.clone(),
        }
    }
}
