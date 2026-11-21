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
    #[error("template installs are disabled on this Anchor")]
    TemplatesDisabled,
    #[error("guest exports are disabled on this Anchor")]
    ExportsDisabled,
    #[error("no such template job")]
    UnknownJob,
    #[error("no such artifact")]
    UnknownArtifact,
    #[error("the template install was cancelled")]
    TemplateCancelled,
    /// Carries the operational failures of both pipelines: a taken VMID, a
    /// `qmrestore` that exited non-zero, a `vzdump` that did the same. The
    /// message is written for an admin to read verbatim.
    #[error("{0}")]
    Template(String),
    #[error("could not read the Proxmox API schema: {0}")]
    Schema(String),
    #[error("provisioner snippets are disabled on this Anchor")]
    SnippetsDisabled,
    /// A snippet request refused for what it asked for: a name outside the
    /// `convoy-*.yaml` namespace, or a body that is not the one the token was
    /// minted for.
    #[error("{0}")]
    InvalidSnippet(String),
    /// The storage a snippet token names cannot hold one on this node: not a
    /// storage id, not active here, without the `snippets` content type, or
    /// resolving the file somewhere it has no business being.
    #[error("{0}")]
    SnippetStorage(String),
    #[error("the snippet is larger than the {0}-byte limit")]
    SnippetTooLarge(usize),
    /// `pvesm` could not be run or failed outright. Not the storage's fault but
    /// the node's, so it is a 500 and its detail goes to the log.
    #[error("{0}")]
    Pvesm(String),
    #[error("health check failed with HTTP {0}")]
    Health(reqwest::StatusCode),
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
            Self::UnsupportedProtocol(_)
            | Self::InvalidMode(_)
            | Self::Template(_)
            | Self::InvalidSnippet(_) => StatusCode::BAD_REQUEST,
            // The panel can act on this one: it names a file this node does not
            // have, which is a packaging problem an admin can fix.
            Self::Schema(_) => StatusCode::NOT_IMPLEMENTED,
            Self::UnknownJob | Self::UnknownArtifact => StatusCode::NOT_FOUND,
            Self::TemplatesDisabled
            | Self::ExportsDisabled
            | Self::SnippetsDisabled
            | Self::SnippetStorage(_) => StatusCode::CONFLICT,
            Self::SnippetTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // A 500 is a bug or a broken node, and its detail is for Anchor's log,
        // not the caller. Everything else is a verdict the panel needs to be
        // able to show an admin verbatim — "VMID 4001 is already in use" is
        // only actionable if it survives the trip.
        let message = if status == StatusCode::INTERNAL_SERVER_ERROR {
            "Anchor could not complete this request".to_owned()
        } else {
            self.to_string()
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
