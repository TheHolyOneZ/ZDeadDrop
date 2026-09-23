use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("vault at {path} is corrupt or was written by a newer version: {detail}")]
    Corrupt { path: PathBuf, detail: String },

    #[error("the vault's event log has been tampered with at sequence {seq}")]
    ChainBroken { seq: i64 },

    #[error("blob {id} is missing from the store")]
    BlobMissing { id: String },

    #[error("blob {id} does not match its content hash")]
    BlobCorrupt { id: String },

    #[error("no vault at {0}")]
    NotFound(PathBuf),

    #[error("a vault already exists at {0}")]
    AlreadyExists(PathBuf),

    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("filesystem: {0}")]
    Io(#[from] std::io::Error),

    #[error("encoding: {0}")]
    Encoding(String),

    #[error(transparent)]
    Core(#[from] zdd_core::Error),
}

impl StoreError {
    pub fn is_tampering(&self) -> bool {
        matches!(
            self,
            StoreError::ChainBroken { .. } | StoreError::BlobCorrupt { .. }
        )
    }
}
