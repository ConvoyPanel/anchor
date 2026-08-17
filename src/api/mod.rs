use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State, WebSocketUpgrade, ws::WebSocket},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use tower_http::{request_id::MakeRequestUuid, trace::TraceLayer};

use crate::{
    config::{Config, Mode},
    console,
    error::{Error, Result},
    protocol::{
        PROTOCOL_MAX, PROTOCOL_MIN, SESSION_PROTOCOL_PREFIX, TemplateAction, WEBSOCKET_PROTOCOL,
        decode_session, decode_template,
    },
    templates::{Job, Jobs},
};

#[derive(Clone)]
struct AppState {
    config: Arc<Config>,
    jobs: Jobs,
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
    capabilities: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct ProtocolRange {
    min: u16,
    max: u16,
}

pub const AGENT_CAPABILITIES: &[&str] = &["console.qemu.vnc", "console.qemu.terminal"];
pub const TEMPLATE_CAPABILITY: &str = "templates.install";
pub const RELAY_CAPABILITIES: &[&str] = &["console.relay"];

/// What this installation can actually do.
///
/// Templates are advertised only when the agent is configured to install them,
/// so the panel can leave a node out of an import rather than queueing work
/// that is going to be refused.
fn capabilities(config: &Config) -> Vec<&'static str> {
    match config.mode {
        Mode::Relay => RELAY_CAPABILITIES.to_vec(),
        Mode::Agent => {
            let mut capabilities = AGENT_CAPABILITIES.to_vec();
            if config.agent.templates_enabled {
                capabilities.push(TEMPLATE_CAPABILITY);
            }
            capabilities
        }
    }
}

/// Build a router without holding on to the job registry — enough for tests
/// that only drive HTTP; `serve` uses [`build`].
#[cfg(test)]
pub fn router(config: Config) -> Router {
    build(Arc::new(config)).0
}

/// Build the router alongside the job registry it shares.
///
/// `serve` needs the registry itself — to clear scratch space left by a
/// previous run before anything can queue new work — so the two are handed back
/// together rather than the registry being buried in router state.
pub fn build(config: Arc<Config>) -> (Router, Jobs) {
    let jobs = Jobs::new(Arc::clone(&config));

    let router = Router::new()
        .route("/health", get(health))
        .route("/api/v1/info", get(info))
        .route("/api/v1/console", get(console_session))
        .route("/api/v1/templates/installs", post(start_install))
        .route(
            "/api/v1/templates/installs/{id}",
            get(install_status).delete(cancel_install),
        )
        .with_state(AppState {
            config,
            jobs: jobs.clone(),
        })
        .layer(tower_http::request_id::SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(TraceLayer::new_for_http());

    (router, jobs)
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
        capabilities: capabilities(&state.config),
    })
}

/// Queue a template install described entirely by the bearer token.
async fn start_install(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Job>)> {
    let claims = decode_template(bearer(&headers)?, &state.config)?;
    ensure_agent(&state)?;

    let TemplateAction::Install(spec) = claims.template else {
        return Err(Error::InvalidSession);
    };

    let job = state.jobs.start(*spec)?;

    Ok((StatusCode::ACCEPTED, Json(job)))
}

async fn install_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Job>> {
    authorise_job(&state, &headers, &id, JobAction::Status)?;

    Ok(Json(state.jobs.get(&id)?))
}

async fn cancel_install(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Job>> {
    authorise_job(&state, &headers, &id, JobAction::Cancel)?;

    Ok(Json(state.jobs.cancel(&id)?))
}

enum JobAction {
    Status,
    Cancel,
}

/// A job token names the job it may touch, so one minted to poll install A
/// cannot be replayed to cancel install B.
fn authorise_job(state: &AppState, headers: &HeaderMap, id: &str, action: JobAction) -> Result<()> {
    let claims = decode_template(bearer(headers)?, &state.config)?;
    ensure_agent(state)?;

    let job = match (&claims.template, action) {
        (TemplateAction::Status { job }, JobAction::Status) => job,
        (TemplateAction::Cancel { job }, JobAction::Cancel) => job,
        _ => return Err(Error::InvalidSession),
    };

    if job != id {
        return Err(Error::InvalidSession);
    }

    Ok(())
}

fn ensure_agent(state: &AppState) -> Result<()> {
    if state.config.mode != Mode::Agent {
        return Err(Error::InvalidMode("relay".into()));
    }

    Ok(())
}

fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or(Error::InvalidSession)
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
    tracing::debug!(
        protocol_count = protocols.split(',').count(),
        "received console WebSocket protocols"
    );

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
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use tower::ServiceExt;
    use url::Url;

    use super::*;
    use crate::{config::AgentConfig, protocol::now};

    const SECRET: &str = "12345678901234567890123456789012";

    fn config(mode: Mode) -> Config {
        Config {
            mode,
            listen_addr: "127.0.0.1:2115".parse().unwrap(),
            installation_id: "anchor_1".into(),
            secret: SECRET.into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig::default(),
        }
    }

    /// Mint a template token the way the panel does, so the tests exercise the
    /// real signature and audience checks rather than a bypass.
    fn token(template: serde_json::Value, audience: &str) -> String {
        let claims = json!({
            "iss": "https://panel.example.com",
            "sub": "panel",
            "aud": audience,
            "exp": now() + 60,
            "iat": now(),
            "jti": "job_1",
            "protocol": PROTOCOL_MAX,
            "template": template,
        });

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .unwrap()
    }

    fn install_claim() -> serde_json::Value {
        json!({
            "action": "install",
            "name": "debian-12-amd64",
            "url": "https://cdn.example.com/debian-12.vma.zst",
            "sha256": "a".repeat(64),
            "size": 1024,
            "vmid": 4001,
            "storage": "local",
            "overwrite": false,
        })
    }

    async fn status_of(router: Router, request: Request<Body>) -> StatusCode {
        router.oneshot(request).await.unwrap().status()
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
        assert!(
            body["capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!(TEMPLATE_CAPABILITY))
        );
    }

    #[tokio::test]
    async fn hides_the_template_capability_when_it_is_switched_off() {
        let mut config = config(Mode::Agent);
        config.agent.templates_enabled = false;

        let response = router(config)
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            !body["capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!(TEMPLATE_CAPABILITY))
        );
    }

    #[tokio::test]
    async fn exposes_health_check() {
        let response = router(config(Mode::Relay))
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn installs_require_a_bearer_token() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/installs")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn installs_reject_a_token_minted_for_another_anchor() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/installs")
                .header(
                    "authorization",
                    format!("Bearer {}", token(install_claim(), "anchor_2")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_status_token_cannot_start_an_install() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/installs")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "status", "job": "job_1" }), "anchor_1")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_status_token_cannot_cancel_a_different_job() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::delete("/api/v1/templates/installs/job_2")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "cancel", "job": "job_1" }), "anchor_1")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn polling_an_unknown_job_is_a_404() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::get("/api/v1/templates/installs/job_1")
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "status", "job": "job_1" }), "anchor_1")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_relay_refuses_template_work() {
        let status = status_of(
            router(config(Mode::Relay)),
            Request::post("/api/v1/templates/installs")
                .header(
                    "authorization",
                    format!("Bearer {}", token(install_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn installs_are_refused_when_templates_are_disabled() {
        let mut config = config(Mode::Agent);
        config.agent.templates_enabled = false;

        let status = status_of(
            router(config),
            Request::post("/api/v1/templates/installs")
                .header(
                    "authorization",
                    format!("Bearer {}", token(install_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
    }
}
