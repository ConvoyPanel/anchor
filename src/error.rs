use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use thiserror::Error as ThisError;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("invalid or expired session token")]
    InvalidSession,
    #[error("session is not valid for this Anchor installation")]
    InvalidAudience,
    #[error("unsupported protocol version {0}")]
    UnsupportedProtocol(u16),
    #[error("this session cannot be handled in {0} mode")]
    InvalidMode(String),
    #[error("console process failed: {0}")]
    Console(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    HttpBuild(#[from] axum::http::Error),
    #[error(transparent)]
    Axum(#[from] axum::Error),
    #[error(transparent)]
    TomlDeserialize(#[from] toml::de::Error),
    #[error(transparent)]
    TomlSerialize(#[from] toml::ser::Error),
    #[error(transparent)]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        let status = match self {
            Self::InvalidSession | Self::InvalidAudience => StatusCode::UNAUTHORIZED,
            Self::UnsupportedProtocol(_) | Self::InvalidMode(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "Anchor could not start this console session".to_owned()
        } else {
            self.to_string()
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
