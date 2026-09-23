pub fn empty_root() -> [u8; 32] {
    *blake3::hash(b"").as_bytes()
}

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x00]);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[0x01]);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

pub fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub index: u64,

    pub tree_size: u64,

    pub path: Vec<[u8; 32]>,
}

pub fn inclusion_proof(leaves: &[[u8; 32]], index: usize) -> Option<InclusionProof> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    build_path(leaves, index, &mut path);
    Some(InclusionProof {
        index: index as u64,
        tree_size: leaves.len() as u64,
        path,
    })
}

fn build_path(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split_point(leaves.len());
    if index < k {
        build_path(&leaves[..k], index, out);
        out.push(root_of(&leaves[k..]));
    } else {
        build_path(&leaves[k..], index - k, out);
        out.push(root_of(&leaves[..k]));
    }
}

pub fn verify_inclusion(
    leaf: &[u8; 32],
    proof: &InclusionProof,
    expected_root: &[u8; 32],
    expected_size: u64,
) -> bool {
    if proof.tree_size != expected_size {
        return false;
    }
    if proof.tree_size == 0 || proof.index >= proof.tree_size {
        return false;
    }
    let Ok(size) = usize::try_from(proof.tree_size) else {
        return false;
    };
    let Ok(index) = usize::try_from(proof.index) else {
        return false;
    };

    if proof.path.len() != expected_path_len(index, size) {
        return false;
    }

    let computed = recompute(index, size, &proof.path, *leaf);
    match computed {
        Some(root) => {
            use subtle::ConstantTimeEq;
            bool::from(root.ct_eq(expected_root))
        }
        None => false,
    }
}

fn expected_path_len(index: usize, size: usize) -> usize {
    if size <= 1 {
        return 0;
    }
    let k = split_point(size);
    1 + if index < k {
        expected_path_len(index, k)
    } else {
        expected_path_len(index - k, size - k)
    }
}

fn recompute(index: usize, size: usize, path: &[[u8; 32]], leaf: [u8; 32]) -> Option<[u8; 32]> {
    if size <= 1 {
        return if path.is_empty() { Some(leaf) } else { None };
    }
    let k = split_point(size);
    let (sibling, rest) = path.split_last()?;

    if index < k {
        let left = recompute(index, k, rest, leaf)?;
        Some(node_hash(&left, sibling))
    } else {
        let right = recompute(index - k, size - k, rest, leaf)?;
        Some(node_hash(sibling, &right))
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MerkleLog {
    leaves: Vec<[u8; 32]>,
}

impl MerkleLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, data: &[u8]) -> u64 {
        let index = self.leaves.len() as u64;
        self.leaves.push(leaf_hash(data));
        index
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn root(&self) -> [u8; 32] {
        root_of(&self.leaves)
    }

    pub fn prove(&self, index: u64) -> Option<InclusionProof> {
        inclusion_proof(&self.leaves, usize::try_from(index).ok()?)
    }

    pub fn root_at(&self, size: u64) -> Option<[u8; 32]> {
        let size = usize::try_from(size).ok()?;
        if size > self.leaves.len() {
            return None;
        }
        Some(root_of(&self.leaves[..size]))
    }

    pub fn extends(&self, earlier_size: u64, earlier_root: &[u8; 32]) -> bool {
        match self.root_at(earlier_size) {
            Some(root) => {
                use subtle::ConstantTimeEq;
                bool::from(root.ct_eq(earlier_root))
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_of(n: usize) -> MerkleLog {
        let mut log = MerkleLog::new();
        for i in 0..n {
            log.append(format!("check-in {i}").as_bytes());
        }
        log
    }

    #[test]
    fn empty_and_single_trees() {
        let log = MerkleLog::new();
        assert_eq!(log.root(), empty_root());
        assert!(log.prove(0).is_none());

        let mut log = MerkleLog::new();
        log.append(b"only");
        assert_eq!(log.root(), leaf_hash(b"only"));
    }

    #[test]
    fn leaf_and_node_hashes_are_domain_separated() {
        let a = leaf_hash(b"x");
        let b = node_hash(&[0u8; 32], &[0u8; 32]);
        assert_ne!(a, b);

        let mut log = MerkleLog::new();
        log.append(b"a");
        log.append(b"b");
        assert_ne!(log.root(), leaf_hash(b"ab"));
    }

    #[test]
    fn proofs_verify_for_every_leaf_at_every_size() {
        for n in 1..=33usize {
            let log = log_of(n);
            let root = log.root();
            for i in 0..n {
                let proof = log.prove(i as u64).expect("proof should exist");
                let leaf = leaf_hash(format!("check-in {i}").as_bytes());
                assert!(
                    verify_inclusion(&leaf, &proof, &root, log.len()),
                    "leaf {i} of {n} failed to verify"
                );
            }
        }
    }

    #[test]
    fn a_proof_for_the_wrong_leaf_fails() {
        let log = log_of(8);
        let root = log.root();
        let proof = log.prove(3).unwrap();
        let wrong = leaf_hash(b"check-in 4");
        assert!(!verify_inclusion(&wrong, &proof, &root, log.len()));
    }

    #[test]
    fn a_tampered_path_fails() {
        let log = log_of(8);
        let root = log.root();
        let leaf = leaf_hash(b"check-in 3");

        for i in 0..log.prove(3).unwrap().path.len() {
            let mut proof = log.prove(3).unwrap();
            proof.path[i][0] ^= 0x01;
            assert!(
                !verify_inclusion(&leaf, &proof, &root, log.len()),
                "tampered path element {i} accepted"
            );
        }
    }

    #[test]
    fn a_truncated_path_fails() {
        let log = log_of(8);
        let root = log.root();
        let leaf = leaf_hash(b"check-in 3");

        let mut proof = log.prove(3).unwrap();
        proof.path.pop();
        assert!(!verify_inclusion(&leaf, &proof, &root, log.len()));

        let mut proof = log.prove(3).unwrap();
        proof.path.push([0u8; 32]);
        assert!(!verify_inclusion(&leaf, &proof, &root, log.len()));
    }

    #[test]
    fn a_proof_against_the_wrong_size_fails() {
        let log = log_of(8);
        let root = log.root();
        let leaf = leaf_hash(b"check-in 3");

        let mut proof = log.prove(3).unwrap();
        proof.tree_size = 7;
        assert!(
            !verify_inclusion(&leaf, &proof, &root, 8),
            "a proof claiming a different size than the signed head must be refused"
        );

        assert!(
            verify_inclusion(&leaf, &proof, &root, 7),
            "sanity: the path itself is size-ambiguous here"
        );

        let mut proof = log.prove(3).unwrap();
        proof.index = 4;
        assert!(!verify_inclusion(&leaf, &proof, &root, 8));
    }

    #[test]
    fn out_of_range_proofs_are_rejected() {
        let leaf = leaf_hash(b"x");
        let root = leaf;
        assert!(!verify_inclusion(
            &leaf,
            &InclusionProof {
                index: 0,
                tree_size: 0,
                path: vec![]
            },
            &root,
            0
        ));
        assert!(!verify_inclusion(
            &leaf,
            &InclusionProof {
                index: 5,
                tree_size: 3,
                path: vec![]
            },
            &root,
            3
        ));
    }

    #[test]
    fn appending_changes_the_root() {
        let mut log = MerkleLog::new();
        let mut roots = std::collections::HashSet::new();
        roots.insert(log.root());
        for i in 0..40 {
            log.append(format!("entry {i}").as_bytes());
            assert!(
                roots.insert(log.root()),
                "root repeated after appending entry {i}"
            );
        }
    }

    #[test]
    fn removing_a_leaf_breaks_a_published_head() {
        let log = log_of(10);
        let published_size = log.len();
        let published_root = log.root();

        let mut tampered = MerkleLog::new();
        for i in 0..10 {
            if i == 4 {
                continue;
            }
            tampered.append(format!("check-in {i}").as_bytes());
        }

        assert!(
            !tampered.extends(published_size, &published_root),
            "a rollback must not satisfy a previously published tree head"
        );
    }

    #[test]
    fn rewriting_history_is_caught() {
        let log = log_of(10);
        let size = log.len();
        let root = log.root();

        let mut tampered = MerkleLog::new();
        for i in 0..10 {
            if i == 4 {
                tampered.append(b"forged check-in");
            } else {
                tampered.append(format!("check-in {i}").as_bytes());
            }
        }
        assert!(!tampered.extends(size, &root));
    }

    #[test]
    fn honest_growth_satisfies_every_earlier_head() {
        let mut log = MerkleLog::new();
        let mut heads = Vec::new();
        for i in 0..25 {
            heads.push((log.len(), log.root()));
            log.append(format!("check-in {i}").as_bytes());
        }
        for (size, root) in heads {
            assert!(
                log.extends(size, &root),
                "honest log failed an earlier head at size {size}"
            );
        }
    }

    #[test]
    fn root_at_rejects_a_future_size() {
        let log = log_of(5);
        assert!(log.root_at(5).is_some());
        assert!(log.root_at(6).is_none());
        assert!(!log.extends(6, &[0u8; 32]));
    }

    #[test]
    fn split_point_is_the_largest_power_of_two_below_n() {
        assert_eq!(split_point(2), 1);
        assert_eq!(split_point(3), 2);
        assert_eq!(split_point(4), 2);
        assert_eq!(split_point(5), 4);
        assert_eq!(split_point(8), 4);
        assert_eq!(split_point(9), 8);
        assert_eq!(split_point(1000), 512);
    }

    #[test]
    fn proofs_survive_json() {
        let log = log_of(12);
        let proof = log.prove(7).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let back: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back, proof);
        assert!(verify_inclusion(
            &leaf_hash(b"check-in 7"),
            &back,
            &log.root(),
            log.len()
        ));
    }
}
