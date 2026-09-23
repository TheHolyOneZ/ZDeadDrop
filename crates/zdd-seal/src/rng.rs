pub struct Bits {
    reader: blake3::OutputReader,
    buf: [u8; 64],
    pos: usize,
}

impl Bits {
    pub fn new(seed: &[u8; 32], domain: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"zdd/v1/seal-art");
        hasher.update(&(domain.len() as u32).to_be_bytes());
        hasher.update(domain);
        hasher.update(seed);
        Self {
            reader: hasher.finalize_xof(),
            buf: [0u8; 64],
            pos: 64,
        }
    }

    fn byte(&mut self) -> u8 {
        if self.pos >= self.buf.len() {
            self.reader.fill(&mut self.buf);
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_be_bytes([self.byte(), self.byte(), self.byte(), self.byte()])
    }

    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n > 0, "below(0) is undefined");
        let zone = u32::MAX - (u32::MAX % n) - 1;
        loop {
            let v = self.u32();
            if v <= zone {
                return v % n;
            }
        }
    }

    pub fn range(&mut self, lo: u32, hi: u32) -> u32 {
        debug_assert!(lo <= hi);
        lo + self.below(hi - lo + 1)
    }

    pub fn bit(&mut self) -> bool {
        self.byte() & 1 == 1
    }

    pub fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
        self.below(denominator) < numerator
    }

    pub fn unit(&mut self) -> f64 {
        f64::from(u16::from_be_bytes([self.byte(), self.byte()])) / 65536.0
    }

    pub fn signed_unit(&mut self) -> f64 {
        self.unit() * 2.0 - 1.0
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u32) as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_stream() {
        let seed = [7u8; 32];
        let mut a = Bits::new(&seed, b"wax");
        let mut b = Bits::new(&seed, b"wax");
        for _ in 0..500 {
            assert_eq!(a.u32(), b.u32());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Bits::new(&[1u8; 32], b"wax");
        let mut b = Bits::new(&[2u8; 32], b"wax");
        let (x, y): (Vec<u32>, Vec<u32>) = (
            (0..64).map(|_| a.u32()).collect(),
            (0..64).map(|_| b.u32()).collect(),
        );
        assert_ne!(x, y);
    }

    #[test]
    fn domains_are_independent() {
        let seed = [3u8; 32];
        let mut a = Bits::new(&seed, b"wax");
        let mut b = Bits::new(&seed, b"sigil");
        let (x, y): (Vec<u32>, Vec<u32>) = (
            (0..64).map(|_| a.u32()).collect(),
            (0..64).map(|_| b.u32()).collect(),
        );
        assert_ne!(x, y);
    }

    #[test]
    fn below_stays_in_range_and_covers_it() {
        let mut bits = Bits::new(&[9u8; 32], b"t");
        let mut seen = [false; 7];
        for _ in 0..2000 {
            let v = bits.below(7);
            assert!(v < 7);
            seen[v as usize] = true;
        }
        assert!(
            seen.iter().all(|&s| s),
            "below() never produced some values"
        );
    }

    #[test]
    fn range_is_inclusive_at_both_ends() {
        let mut bits = Bits::new(&[11u8; 32], b"t");
        let mut lo = false;
        let mut hi = false;
        for _ in 0..2000 {
            let v = bits.range(5, 9);
            assert!((5..=9).contains(&v));
            lo |= v == 5;
            hi |= v == 9;
        }
        assert!(lo && hi);
    }

    #[test]
    fn below_one_is_always_zero() {
        let mut bits = Bits::new(&[0u8; 32], b"t");
        for _ in 0..50 {
            assert_eq!(bits.below(1), 0);
        }
    }

    #[test]
    fn below_is_not_visibly_biased() {
        let mut bits = Bits::new(&[13u8; 32], b"t");
        let n = 7usize;
        let draws = 70_000;
        let mut counts = vec![0usize; n];
        for _ in 0..draws {
            counts[bits.below(n as u32) as usize] += 1;
        }
        let expected = draws / n;
        for (v, &c) in counts.iter().enumerate() {
            let drift = (c as f64 - expected as f64).abs() / expected as f64;
            assert!(
                drift < 0.05,
                "value {v} drifted {:.1}% from uniform",
                drift * 100.0
            );
        }
    }

    #[test]
    fn unit_stays_in_bounds() {
        let mut bits = Bits::new(&[17u8; 32], b"t");
        for _ in 0..5000 {
            let u = bits.unit();
            assert!((0.0..1.0).contains(&u), "unit() produced {u}");
            let s = bits.signed_unit();
            assert!((-1.0..1.0).contains(&s), "signed_unit() produced {s}");
        }
    }
}
