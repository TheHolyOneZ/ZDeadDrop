use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{Result, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobId(pub [u8; 32]);

impl BlobId {
    pub fn hex(&self) -> String {
        zdd_core::codec::to_hex(&self.0)
    }

    pub fn parse(s: &str) -> Option<Self> {
        let bytes = zdd_core::codec::from_hex(s)?;
        Some(Self(bytes.try_into().ok()?))
    }

    fn path_in(&self, root: &Path) -> PathBuf {
        let hex = self.hex();
        root.join(&hex[0..2]).join(&hex[2..4]).join(&hex[4..])
    }
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put<R: Read>(&self, src: &mut R) -> Result<(BlobId, u64)> {
        fs::create_dir_all(&self.root)?;

        let temp = self.staging_path();

        let mut hasher = blake3::Hasher::new();
        let mut written = 0u64;

        {
            let mut out = fs::File::create(&temp)?;
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = src.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])?;
                written += n as u64;
            }

            out.sync_all()?;
        }

        let id = BlobId(*hasher.finalize().as_bytes());
        let dest = id.path_in(&self.root);

        if dest.exists() {
            fs::remove_file(&temp)?;
            return Ok((id, written));
        }

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&temp, &dest)?;
        Ok((id, written))
    }

    pub fn adopt(&self, file: &Path) -> Result<(BlobId, u64)> {
        let mut hasher = blake3::Hasher::new();
        let mut src = fs::File::open(file)?;
        let mut buf = vec![0u8; 1024 * 1024];
        let mut len = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            len += n as u64;
        }
        drop(src);

        let id = BlobId(*hasher.finalize().as_bytes());
        let dest = id.path_in(&self.root);
        if dest.exists() {
            fs::remove_file(file)?;
            return Ok((id, len));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(file, &dest)?;
        Ok((id, len))
    }

    pub fn staging_path(&self) -> PathBuf {
        use rand::RngCore;
        let mut tag = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut tag);
        self.root
            .join(format!(".incoming-{}", zdd_core::codec::to_hex(&tag)))
    }

    pub fn path_of(&self, id: BlobId) -> PathBuf {
        id.path_in(&self.root)
    }

    pub fn get<W: Write>(&self, id: BlobId, dst: &mut W) -> Result<u64> {
        let path = id.path_in(&self.root);
        let mut file = fs::File::open(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StoreError::BlobMissing { id: id.hex() },
            _ => StoreError::Io(e),
        })?;

        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total = 0u64;

        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            dst.write_all(&buf[..n])?;
            total += n as u64;
        }

        if *hasher.finalize().as_bytes() != id.0 {
            return Err(StoreError::BlobCorrupt { id: id.hex() });
        }
        Ok(total)
    }

    pub fn exists(&self, id: BlobId) -> bool {
        id.path_in(&self.root).exists()
    }

    pub fn len(&self, id: BlobId) -> Result<u64> {
        let meta = fs::metadata(id.path_in(&self.root)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => StoreError::BlobMissing { id: id.hex() },
            _ => StoreError::Io(e),
        })?;
        Ok(meta.len())
    }

    pub fn remove(&self, id: BlobId) -> Result<()> {
        let path = id.path_in(&self.root);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),

            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    pub fn sweep(&self) -> Result<usize> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".incoming-")
            {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    #[test]
    fn round_trips() {
        let (_d, store) = store();
        let data = b"some encrypted capsule payload".to_vec();

        let (id, len) = store.put(&mut data.as_slice()).unwrap();
        assert_eq!(len, data.len() as u64);
        assert!(store.exists(id));
        assert_eq!(store.len(id).unwrap(), data.len() as u64);

        let mut out = Vec::new();
        assert_eq!(store.get(id, &mut out).unwrap(), data.len() as u64);
        assert_eq!(out, data);
    }

    #[test]
    fn round_trips_across_sizes() {
        let (_d, store) = store();

        for len in [
            0usize,
            1,
            1023,
            1024 * 1024 - 1,
            1024 * 1024,
            1024 * 1024 + 7,
        ] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let (id, written) = store.put(&mut data.as_slice()).unwrap();
            assert_eq!(written, len as u64);
            let mut out = Vec::new();
            store.get(id, &mut out).unwrap();
            assert_eq!(out, data, "mismatch at {len} bytes");
        }
    }

    #[test]
    fn identical_content_dedupes() {
        let (_d, store) = store();
        let data = vec![7u8; 5000];
        let (a, _) = store.put(&mut data.as_slice()).unwrap();
        let (b, _) = store.put(&mut data.as_slice()).unwrap();
        assert_eq!(a, b);

        let count = walk(store.root());
        assert_eq!(count, 1, "dedupe left {count} files");
    }

    #[test]
    fn different_content_gets_different_addresses() {
        let (_d, store) = store();
        let (a, _) = store.put(&mut b"one".as_slice()).unwrap();
        let (b, _) = store.put(&mut b"two".as_slice()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_corrupted_blob_is_detected() {
        let (_d, store) = store();
        let data = vec![3u8; 4096];
        let (id, _) = store.put(&mut data.as_slice()).unwrap();

        let path = id.path_in(store.root());
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 0x01;
        fs::write(&path, &bytes).unwrap();

        let mut out = Vec::new();
        let err = store.get(id, &mut out).unwrap_err();
        assert!(matches!(err, StoreError::BlobCorrupt { .. }), "got {err:?}");
        assert!(err.is_tampering());
    }

    #[test]
    fn a_truncated_blob_is_detected() {
        let (_d, store) = store();
        let data = vec![9u8; 8192];
        let (id, _) = store.put(&mut data.as_slice()).unwrap();

        let path = id.path_in(store.root());
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..4000]).unwrap();

        let mut out = Vec::new();
        assert!(matches!(
            store.get(id, &mut out),
            Err(StoreError::BlobCorrupt { .. })
        ));
    }

    #[test]
    fn a_missing_blob_says_so() {
        let (_d, store) = store();
        let ghost = BlobId([0xAB; 32]);
        assert!(!store.exists(ghost));

        let mut out = Vec::new();
        assert!(matches!(
            store.get(ghost, &mut out),
            Err(StoreError::BlobMissing { .. })
        ));
        assert!(matches!(
            store.len(ghost),
            Err(StoreError::BlobMissing { .. })
        ));
    }

    #[test]
    fn removing_is_idempotent() {
        let (_d, store) = store();
        let (id, _) = store.put(&mut b"gone soon".as_slice()).unwrap();
        store.remove(id).unwrap();
        assert!(!store.exists(id));

        store.remove(id).unwrap();
    }

    #[test]
    fn an_interrupted_write_leaves_nothing_addressable() {
        let (_d, store) = store();

        struct Failing;
        impl Read for Failing {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                buf[..10].fill(1);
                Err(std::io::Error::other("disk full"))
            }
        }

        assert!(store.put(&mut Failing).is_err());

        assert_eq!(walk(store.root()), 0, "a partial write became addressable");
        assert_eq!(store.sweep().unwrap(), 1);
        assert_eq!(store.sweep().unwrap(), 0);
    }

    #[test]
    fn ids_round_trip_through_hex() {
        let id = BlobId([0x9f; 32]);
        assert_eq!(BlobId::parse(&id.hex()), Some(id));
        assert_eq!(BlobId::parse("not hex"), None);
        assert_eq!(BlobId::parse("ab"), None);
    }

    #[test]
    fn paths_fan_out() {
        let root = Path::new("/vault/blobs");
        let id = BlobId::parse(&"ab".repeat(32)).unwrap();
        let path = id.path_in(root);
        assert!(path.starts_with("/vault/blobs/ab/ab/"));
    }

    fn walk(root: &Path) -> usize {
        fn rec(dir: &Path, count: &mut usize) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    rec(&path, count);
                } else if !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".incoming-")
                {
                    *count += 1;
                }
            }
        }
        let mut count = 0;
        rec(root, &mut count);
        count
    }
}
