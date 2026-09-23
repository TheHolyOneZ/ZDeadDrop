use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub type Result<T> = std::result::Result<T, RelayError>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    #[error("no such vault")]
    UnknownVault(String),

    #[error("that vault is already enrolled")]
    AlreadyEnrolled,

    #[error("the signature did not verify")]
    BadSignature,

    #[error("that check-in names a different vault")]
    WrongVault,

    #[error("expected check-in #{expected}, got #{got}")]
    OutOfOrder { expected: u64, got: u64 },

    #[error("the owner has checked in more recently than the silence threshold")]
    StillPresent,

    #[error("stored data is unreadable: {0}")]
    Corrupt(String),

    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl IntoResponse for RelayError {
    fn into_response(self) -> Response {
        let status = match &self {
            RelayError::UnknownVault(_) | RelayError::BadSignature | RelayError::WrongVault => {
                StatusCode::NOT_FOUND
            }
            RelayError::AlreadyEnrolled => StatusCode::CONFLICT,
            RelayError::OutOfOrder { .. } => StatusCode::CONFLICT,
            RelayError::StillPresent => StatusCode::FORBIDDEN,
            RelayError::Corrupt(_) | RelayError::Db(_) | RelayError::Io(_) => {
                tracing::error!(error = %self, "internal relay failure");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let message = match &self {
            RelayError::OutOfOrder { expected, .. } => {
                format!("out of order; expected #{expected}")
            }
            RelayError::Corrupt(_) | RelayError::Db(_) | RelayError::Io(_) => {
                "internal error".to_string()
            }
            other => other.to_string(),
        };

        (status, axum::Json(serde_json::json!({ "error": message }))).into_response()
    }
}
