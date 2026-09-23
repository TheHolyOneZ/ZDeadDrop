#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod aead;
pub mod capsule;
pub mod checkin;
pub mod clock;
pub mod codec;
pub mod ecies;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod merkle;
pub mod paths;
pub mod policy;
pub mod rehearsal;
pub mod release;
pub mod secret;
pub mod shamir;
pub mod stream;
pub mod vault;

pub use error::{ClockError, Error, ReleaseRefusal, Result, SharingError};
pub use secret::{harden_process, Key32, Key64, Secret, SecretBytes};

pub const FORMAT_VERSION: u16 = 1;

pub const VAULT_MAGIC: &[u8; 8] = b"ZDDVAULT";

pub const CAPSULE_MAGIC: &[u8; 8] = b"ZDDCAPSL";
