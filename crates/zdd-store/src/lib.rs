#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod blobs;
pub mod chain;
pub mod error;
pub mod vault;

pub use blobs::{BlobId, BlobStore};
pub use chain::{Event, EventKind};
pub use error::{Result, StoreError};
pub use vault::{LockedVault, OpenVault};

pub fn default_vault_path() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(p) = std::env::var_os("ZDD_VAULT").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(|a| PathBuf::from(a).join("ZDeadDrop"))
            .or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join("ZDeadDrop")))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library/Application Support/ZDeadDrop"))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        std::env::var_os("XDG_DATA_HOME")
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .map(|base| base.join("zdeaddrop"))
    }
}
