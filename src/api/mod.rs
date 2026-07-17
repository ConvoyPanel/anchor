use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{State, WebSocketUpgrade, ws::WebSocket},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tower_http::{request_id::MakeRequestUuid, trace::TraceLayer};

use crate::{
    config::{Config, Mode},
    console,
    error::{Error, Result},
    protocol::{
        PROTOCOL_MAX, PROTOCOL_MIN, SESSION_PROTOCOL_PREFIX, WEBSOCKET_PROTOCOL, decode_session,
    },
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct InfoResponse<'a> {
    version: &'a str,
    mode: Mode,
    protocol: ProtocolRange,
    capabilities: &'a [&'a str],
}

#[derive(Debug, Serialize)]
struct ProtocolRange {
    min: u16,
    max: u16,
}

pub const AGENT_CAPABILITIES: &[&str] = &["console.qemu.vnc", "console.qemu.terminal"];
pub const RELAY_CAPABILITIES: &[&str] = &["console.relay"];

pub fn router(config: Config) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/info", get(info))
        .route("/api/v1/console", get(console_session))
        .with_state(AppState {
            config: Arc::new(config),
        })
        .layer(tower_http::request_id::SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn info(State(state): State<AppState>) -> Json<InfoResponse<'static>> {
    Json(InfoResponse {
        version: env!("CARGO_PKG_VERSION"),
        mode: state.config.mode,
        protocol: ProtocolRange {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        },
        capabilities: match state.config.mode {
            Mode::Agent => AGENT_CAPABILITIES,
            Mode::Relay => RELAY_CAPABILITIES,
        },
    })
}

async fn console_session(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response> {
    let token = session_token(&headers)?;
    let claims = decode_session(token, &state.config)?;

    match state.config.mode {
        Mode::Agent if claims.relay.is_some() => return Err(Error::InvalidMode("agent".into())),
        Mode::Relay if claims.relay.is_none() => return Err(Error::InvalidMode("relay".into())),
        _ => {}
    }

    Ok(ws
        .protocols([WEBSOCKET_PROTOCOL])
        .on_upgrade(move |socket| handle_socket(socket, state, claims))
        .into_response())
}

fn session_token(headers: &HeaderMap) -> Result<&str> {
    let protocols = headers
        .get(axum::http::header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .ok_or(Error::InvalidSession)?;

    protocols
        .split(',')
        .map(str::trim)
        .find_map(|protocol| protocol.strip_prefix(SESSION_PROTOCOL_PREFIX))
        .filter(|token| !token.is_empty())
        .ok_or(Error::InvalidSession)
}

async fn handle_socket(socket: WebSocket, state: AppState, claims: crate::protocol::SessionClaims) {
    let result = match state.config.mode {
        Mode::Agent => console::serve_agent(socket, &state.config, claims.console).await,
        Mode::Relay => {
            console::serve_relay(socket, claims.relay.expect("relay target was validated")).await
        }
    };

    if let Err(error) = result {
        tracing::warn!(%error, "console session ended with an error");
    }
}

impl IntoResponse for InfoResponse<'_> {
    fn into_response(self) -> Response {
        (StatusCode::OK, Json(self)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use url::Url;

    use super::*;
    use crate::config::AgentConfig;

    fn config(mode: Mode) -> Config {
        Config {
            mode,
            listen_addr: "127.0.0.1:2115".parse().unwrap(),
            installation_id: "anchor_1".into(),
            secret: "12345678901234567890123456789012".into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig::default(),
        }
    }

    #[tokio::test]
    async fn reports_mode_protocol_and_capabilities() {
        let response = router(config(Mode::Agent))
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["mode"], "agent");
        assert_eq!(body["protocol"]["max"], PROTOCOL_MAX);
        assert_eq!(body["capabilities"][0], "console.qemu.vnc");
    }

    #[tokio::test]
    async fn exposes_health_check() {
        let response = router(config(Mode::Relay))
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
