use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::aead::TAG_LEN;
use crate::error::{Error, Result};
use crate::secret::{Key32, SecretBytes};

pub const PREFIX_LEN: usize = 19;

pub const CHUNK_LEN: usize = 1024 * 1024;

pub const CHUNK_CT_LEN: usize = CHUNK_LEN + TAG_LEN;

pub const MAX_STREAM_LEN: u64 = (u32::MAX as u64) * (CHUNK_LEN as u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StreamPrefix(#[serde(with = "crate::codec::base64_array")] pub [u8; PREFIX_LEN]);

impl StreamPrefix {
    pub fn random() -> Self {
        let mut p = [0u8; PREFIX_LEN];
        rand::rngs::OsRng.fill_bytes(&mut p);
        Self(p)
    }

    fn nonce(&self, counter: u32, final_chunk: bool) -> XNonce {
        let mut n = [0u8; 24];
        n[..PREFIX_LEN].copy_from_slice(&self.0);
        n[PREFIX_LEN..PREFIX_LEN + 4].copy_from_slice(&counter.to_be_bytes());
        n[23] = u8::from(final_chunk);
        *XNonce::from_slice(&n)
    }
}

pub struct StreamSealer {
    cipher: XChaCha20Poly1305,
    prefix: StreamPrefix,
    counter: u32,
    aad: Vec<u8>,
}

impl core::fmt::Debug for StreamSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamSealer")
            .field("chunks_written", &self.counter)
            .field("key", &"redacted")
            .finish()
    }
}

impl StreamSealer {
    pub fn new(key: &Key32, aad: &[u8]) -> (Self, StreamPrefix) {
        let prefix = StreamPrefix::random();
        (
            Self {
                cipher: XChaCha20Poly1305::new(key.expose().into()),
                prefix,
                counter: 0,
                aad: aad.to_vec(),
            },
            prefix,
        )
    }

    pub fn seal_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() != CHUNK_LEN {
            return Err(Error::length(
                "non-final stream chunk",
                CHUNK_LEN,
                plaintext.len(),
            ));
        }
        if self.counter == u32::MAX {
            return Err(Error::Io(format!(
                "stream exceeds the maximum of {MAX_STREAM_LEN} bytes"
            )));
        }

        let nonce = self.prefix.nonce(self.counter, false);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        self.counter += 1;
        Ok(ct)
    }

    pub fn seal_final(mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > CHUNK_LEN {
            return Err(Error::length(
                "final stream chunk",
                CHUNK_LEN,
                plaintext.len(),
            ));
        }
        let nonce = self.prefix.nonce(self.counter, true);
        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        self.counter = self.counter.saturating_add(1);
        Ok(ct)
    }

    pub fn chunks_written(&self) -> u32 {
        self.counter
    }
}

pub struct StreamOpener {
    cipher: XChaCha20Poly1305,
    prefix: StreamPrefix,
    counter: u32,
    aad: Vec<u8>,
}

impl core::fmt::Debug for StreamOpener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamOpener")
            .field("chunks_read", &self.counter)
            .field("key", &"redacted")
            .finish()
    }
}

impl StreamOpener {
    pub fn new(key: &Key32, prefix: StreamPrefix, aad: &[u8]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(key.expose().into()),
            prefix,
            counter: 0,
            aad: aad.to_vec(),
        }
    }

    pub fn open_chunk(&mut self, ciphertext: &[u8]) -> Result<SecretBytes> {
        if ciphertext.len() != CHUNK_CT_LEN {
            return Err(Error::length(
                "non-final stream chunk",
                CHUNK_CT_LEN,
                ciphertext.len(),
            ));
        }
        if self.counter == u32::MAX {
            return Err(Error::Authentication);
        }

        let nonce = self.prefix.nonce(self.counter, false);
        let pt = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        self.counter += 1;
        Ok(SecretBytes::new(pt))
    }

    pub fn open_final(self, ciphertext: &[u8]) -> Result<SecretBytes> {
        if ciphertext.len() < TAG_LEN || ciphertext.len() > CHUNK_CT_LEN {
            return Err(Error::Authentication);
        }
        let nonce = self.prefix.nonce(self.counter, true);
        let pt = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| Error::Authentication)?;
        Ok(SecretBytes::new(pt))
    }

    pub fn chunks_read(&self) -> u32 {
        self.counter
    }
}

pub fn ciphertext_len(plaintext_len: u64) -> u64 {
    if plaintext_len == 0 {
        return TAG_LEN as u64;
    }
    let chunks = plaintext_len.div_ceil(CHUNK_LEN as u64);
    plaintext_len + chunks * TAG_LEN as u64
}

pub fn seal_reader<R, W, P>(
    key: &Key32,
    aad: &[u8],
    src: &mut R,
    dst: &mut W,
    mut progress: P,
) -> Result<(StreamPrefix, u64)>
where
    R: std::io::Read,
    W: std::io::Write,
    P: FnMut(u64),
{
    let (mut sealer, prefix) = StreamSealer::new(key, aad);
    let mut buf = SecretBytes::zeroed(CHUNK_LEN);
    let mut total: u64 = 0;

    let mut pending: Option<SecretBytes> = None;

    loop {
        let n = read_full(src, buf.expose_mut())?;

        if let Some(prev) = pending.take() {
            if n == 0 {
                pending = Some(prev);
                break;
            }
            let ct = sealer.seal_chunk(prev.expose())?;
            dst.write_all(&ct).map_err(|e| Error::Io(e.to_string()))?;
            progress(total);
        }

        if n == 0 {
            break;
        }

        total += n as u64;
        if total > MAX_STREAM_LEN {
            return Err(Error::Io(format!(
                "payload exceeds the maximum of {MAX_STREAM_LEN} bytes"
            )));
        }
        pending = Some(SecretBytes::from_slice(&buf.expose()[..n]));

        if n < CHUNK_LEN {
            break;
        }
    }

    let final_plain = pending.unwrap_or_else(|| SecretBytes::zeroed(0));
    let ct = sealer.seal_final(final_plain.expose())?;
    dst.write_all(&ct).map_err(|e| Error::Io(e.to_string()))?;
    dst.flush().map_err(|e| Error::Io(e.to_string()))?;
    progress(total);

    Ok((prefix, total))
}

pub fn open_reader<R, W, P>(
    key: &Key32,
    prefix: StreamPrefix,
    aad: &[u8],
    src: &mut R,
    dst: &mut W,
    mut progress: P,
) -> Result<u64>
where
    R: std::io::Read,
    W: std::io::Write,
    P: FnMut(u64),
{
    let mut opener = StreamOpener::new(key, prefix, aad);
    let mut buf = vec![0u8; CHUNK_CT_LEN];
    let mut total: u64 = 0;
    let mut pending: Option<Vec<u8>> = None;

    loop {
        let n = read_full(src, &mut buf)?;

        if let Some(prev) = pending.take() {
            if n == 0 {
                pending = Some(prev);
                break;
            }
            let pt = opener.open_chunk(&prev)?;
            dst.write_all(pt.expose())
                .map_err(|e| Error::Io(e.to_string()))?;
            total += pt.len() as u64;
            progress(total);
        }

        if n == 0 {
            break;
        }

        pending = Some(buf[..n].to_vec());

        if n < CHUNK_CT_LEN {
            break;
        }
    }

    let final_ct = pending.ok_or(Error::Authentication)?;
    let pt = opener.open_final(&final_ct)?;
    dst.write_all(pt.expose())
        .map_err(|e| Error::Io(e.to_string()))?;
    dst.flush().map_err(|e| Error::Io(e.to_string()))?;
    total += pt.len() as u64;
    progress(total);

    Ok(total)
}

fn read_full<R: std::io::Read>(src: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::Io(e.to_string())),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(len: usize) {
        let key = Key32::random();
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        let mut ct = Vec::new();
        let (prefix, written) =
            seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |_| {}).unwrap();
        assert_eq!(written, len as u64);
        assert_eq!(
            ct.len() as u64,
            ciphertext_len(len as u64),
            "len mismatch at {len}"
        );

        let mut out = Vec::new();
        let read = open_reader(&key, prefix, b"cap", &mut ct.as_slice(), &mut out, |_| {}).unwrap();
        assert_eq!(read, len as u64);
        assert_eq!(out, plaintext, "payload mismatch at {len}");
    }

    #[test]
    fn round_trips_across_sizes() {
        for len in [
            0,
            1,
            1023,
            CHUNK_LEN - 1,
            CHUNK_LEN,
            CHUNK_LEN + 1,
            3 * CHUNK_LEN + 17,
        ] {
            round_trip(len);
        }
    }

    #[test]
    fn chunk_aligned_payloads_round_trip() {
        round_trip(CHUNK_LEN);
        round_trip(2 * CHUNK_LEN);
        round_trip(3 * CHUNK_LEN);
    }

    #[test]
    fn truncation_is_always_detected() {
        let key = Key32::random();
        let plaintext = vec![0xABu8; 3 * CHUNK_LEN + 500];
        let mut ct = Vec::new();
        let (prefix, _) =
            seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |_| {}).unwrap();

        let mut cuts: Vec<usize> = (1..4).map(|i| i * CHUNK_CT_LEN).collect();
        cuts.extend([1, CHUNK_CT_LEN / 2, ct.len() - 1]);

        for cut in cuts {
            let mut out = Vec::new();
            let r = open_reader(&key, prefix, b"cap", &mut &ct[..cut], &mut out, |_| {});
            assert!(
                r.is_err(),
                "truncation to {cut} of {} went undetected",
                ct.len()
            );
        }
    }

    #[test]
    fn dropping_the_final_chunk_is_detected() {
        let key = Key32::random();
        let plaintext = vec![0x11u8; 2 * CHUNK_LEN];
        let mut ct = Vec::new();
        let (prefix, _) =
            seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |_| {}).unwrap();

        assert_eq!(ct.len(), 2 * CHUNK_CT_LEN);
        let without_final = &ct[..CHUNK_CT_LEN];
        let mut out = Vec::new();
        assert!(
            open_reader(
                &key,
                prefix,
                b"cap",
                &mut &without_final[..],
                &mut out,
                |_| {}
            )
            .is_err(),
            "a stream missing its terminator must not verify"
        );
    }

    #[test]
    fn chunk_reordering_is_detected() {
        let key = Key32::random();
        let plaintext = vec![0x22u8; 3 * CHUNK_LEN];
        let mut ct = Vec::new();
        let (prefix, _) =
            seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |_| {}).unwrap();

        let mut swapped = ct.clone();
        let (a, b) = (0, CHUNK_CT_LEN);
        for i in 0..CHUNK_CT_LEN {
            swapped.swap(a + i, b + i);
        }

        let mut out = Vec::new();
        assert!(open_reader(
            &key,
            prefix,
            b"cap",
            &mut swapped.as_slice(),
            &mut out,
            |_| {}
        )
        .is_err());
    }

    #[test]
    fn chunks_cannot_be_spliced_between_streams() {
        let key = Key32::random();
        let a: Vec<u8> = vec![0xAA; 2 * CHUNK_LEN];
        let b: Vec<u8> = vec![0xBB; 2 * CHUNK_LEN];

        let (mut ct_a, mut ct_b) = (Vec::new(), Vec::new());
        let (prefix_a, _) =
            seal_reader(&key, b"cap", &mut a.as_slice(), &mut ct_a, |_| {}).unwrap();
        let (_, _) = seal_reader(&key, b"cap", &mut b.as_slice(), &mut ct_b, |_| {}).unwrap();

        let mut spliced = ct_a.clone();
        spliced[..CHUNK_CT_LEN].copy_from_slice(&ct_b[..CHUNK_CT_LEN]);

        let mut out = Vec::new();
        assert!(open_reader(
            &key,
            prefix_a,
            b"cap",
            &mut spliced.as_slice(),
            &mut out,
            |_| {}
        )
        .is_err());
    }

    #[test]
    fn wrong_prefix_fails() {
        let key = Key32::random();
        let plaintext = vec![1u8; 100];
        let mut ct = Vec::new();
        let (_, _) = seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |_| {}).unwrap();

        let mut out = Vec::new();
        assert!(open_reader(
            &key,
            StreamPrefix::random(),
            b"cap",
            &mut ct.as_slice(),
            &mut out,
            |_| {}
        )
        .is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = Key32::random();
        let plaintext = vec![1u8; 100];
        let mut ct = Vec::new();
        let (prefix, _) = seal_reader(
            &key,
            b"capsule-1",
            &mut plaintext.as_slice(),
            &mut ct,
            |_| {},
        )
        .unwrap();

        let mut out = Vec::new();
        assert!(open_reader(
            &key,
            prefix,
            b"capsule-2",
            &mut ct.as_slice(),
            &mut out,
            |_| {}
        )
        .is_err());
    }

    #[test]
    fn a_middle_chunk_cannot_be_promoted_to_final() {
        let key = Key32::random();
        let (mut sealer, prefix) = StreamSealer::new(&key, b"cap");
        let chunk = vec![7u8; CHUNK_LEN];
        let ct0 = sealer.seal_chunk(&chunk).unwrap();

        let opener = StreamOpener::new(&key, prefix, b"cap");
        assert!(opener.open_final(&ct0).is_err());
    }

    #[test]
    fn non_final_chunks_must_be_exactly_chunk_len() {
        let key = Key32::random();
        let (mut sealer, _) = StreamSealer::new(&key, b"cap");
        assert!(sealer.seal_chunk(&vec![0u8; CHUNK_LEN - 1]).is_err());
        assert!(sealer.seal_chunk(&vec![0u8; CHUNK_LEN + 1]).is_err());
    }

    #[test]
    fn final_chunk_may_not_exceed_chunk_len() {
        let key = Key32::random();
        let (sealer, _) = StreamSealer::new(&key, b"cap");
        assert!(sealer.seal_final(&vec![0u8; CHUNK_LEN + 1]).is_err());
    }

    #[test]
    fn ciphertext_len_matches_reality() {
        for len in [
            0u64,
            1,
            100,
            CHUNK_LEN as u64 - 1,
            CHUNK_LEN as u64,
            CHUNK_LEN as u64 + 1,
        ] {
            let key = Key32::random();
            let pt = vec![0u8; len as usize];
            let mut ct = Vec::new();
            seal_reader(&key, b"", &mut pt.as_slice(), &mut ct, |_| {}).unwrap();
            assert_eq!(
                ct.len() as u64,
                ciphertext_len(len),
                "mismatch for len {len}"
            );
        }
    }

    #[test]
    fn handles_short_reads() {
        struct Dribble<'a>(&'a [u8]);
        impl std::io::Read for Dribble<'_> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.len().min(buf.len()).min(7);
                buf[..n].copy_from_slice(&self.0[..n]);
                self.0 = &self.0[n..];
                Ok(n)
            }
        }

        let key = Key32::random();
        let plaintext: Vec<u8> = (0..CHUNK_LEN + 2000).map(|i| (i % 251) as u8).collect();
        let mut ct = Vec::new();
        let (prefix, written) =
            seal_reader(&key, b"cap", &mut Dribble(&plaintext), &mut ct, |_| {}).unwrap();
        assert_eq!(written, plaintext.len() as u64);

        let mut out = Vec::new();
        open_reader(&key, prefix, b"cap", &mut ct.as_slice(), &mut out, |_| {}).unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn progress_is_monotonic_and_ends_at_total() {
        let key = Key32::random();
        let plaintext = vec![3u8; 3 * CHUNK_LEN + 11];
        let mut seen = Vec::new();
        let mut ct = Vec::new();
        seal_reader(&key, b"cap", &mut plaintext.as_slice(), &mut ct, |n| {
            seen.push(n)
        })
        .unwrap();

        assert!(
            seen.windows(2).all(|w| w[0] <= w[1]),
            "progress went backwards: {seen:?}"
        );
        assert_eq!(*seen.last().unwrap(), plaintext.len() as u64);
    }
}
