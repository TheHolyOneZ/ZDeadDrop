use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("authentication failed")]
    Authentication,

    #[error("no unlock path accepted the supplied credential")]
    UnlockRejected,

    #[error("malformed {what}: expected {expected} bytes, found {found}")]
    Length {
        what: &'static str,
        expected: usize,
        found: usize,
    },

    #[error("unsupported {what}: {detail}")]
    Format { what: &'static str, detail: String },

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("secret sharing: {0}")]
    Sharing(#[from] SharingError),

    #[error("signature verification failed")]
    Signature,

    #[error("release refused: {0}")]
    ReleaseRefused(#[from] ReleaseRefusal),

    #[error("clock integrity: {0}")]
    Clock(#[from] ClockError),

    #[error("encoding: {0}")]
    Encoding(String),

    #[error("stream i/o: {0}")]
    Io(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SharingError {
    #[error("threshold {threshold} exceeds share count {total}")]
    ThresholdTooHigh { threshold: u8, total: u8 },

    #[error("threshold must be at least 2, got {0}")]
    ThresholdTooLow(u8),

    #[error("share count must be between 2 and 255, got {0}")]
    ShareCountOutOfRange(u16),

    #[error("need {needed} shares, only {supplied} supplied")]
    InsufficientShares { needed: u8, supplied: usize },

    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),

    #[error("share index 0 is reserved for the secret itself")]
    ZeroIndex,

    #[error("shares have mismatched lengths")]
    MismatchedLength,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseRefusal {
    #[error("the owner has checked in more recently than the silence threshold")]
    OwnerStillPresent,

    #[error("trustee quorum not met: {have} of {need} required confirmations")]
    QuorumNotMet { have: u8, need: u8 },

    #[error("the final countdown has not elapsed")]
    CountdownRunning,

    #[error("the relay has not produced a valid silence proof")]
    NoRelayProof,

    #[error("the relay's silence proof did not verify")]
    BadRelayProof,

    #[error("the owner cancelled this release")]
    CancelledByOwner,

    #[error("a trustee vetoed this release")]
    VetoedByTrustee,

    #[error("the vigil is frozen pending clock reconciliation")]
    VigilFrozen,

    #[error("a vacation hold is active until the stated deadline")]
    HoldActive,

    #[error("this capsule is a rehearsal and can never release real content")]
    RehearsalOnly,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClockError {
    #[error("wall clock moved backwards by {0} seconds")]
    WentBackwards(u64),

    #[error("wall clock jumped forward {jumped}s while only {elapsed}s elapsed monotonically")]
    ImplausibleJump { jumped: u64, elapsed: u64 },

    #[error("no independent time attestation is available")]
    NoAttestation,

    #[error("time attestation disagrees with local clock by {0} seconds")]
    AttestationDisagrees(u64),

    #[error("time attestation is stale and cannot be aged across a restart")]
    StaleAttestation,
}

impl Error {
    pub(crate) fn length(what: &'static str, expected: usize, found: usize) -> Self {
        Error::Length {
            what,
            expected,
            found,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn format(what: &'static str, detail: impl fmt::Display) -> Self {
        Error::Format {
            what,
            detail: detail.to_string(),
        }
    }

    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Error::Authentication | Error::Signature | Error::UnlockRejected
        )
    }
}
