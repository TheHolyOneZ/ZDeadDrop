pub type Result<T> = std::result::Result<T, ImportError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    #[error("that {what} is not valid: {detail}")]
    Invalid { what: &'static str, detail: String },

    #[error("could not tell what kind of file {0} is")]
    Unrecognised(String),

    #[error("{0} is encrypted and needs its password")]
    NeedsPassword(String),

    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("{0}")]
    Parse(String),
}

impl ImportError {
    pub fn io(path: impl std::fmt::Display, source: std::io::Error) -> Self {
        ImportError::Io {
            path: path.to_string(),
            source,
        }
    }
}
