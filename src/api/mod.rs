mod artifacts;

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
        PROTOCOL_MAX, PROTOCOL_MIN, SESSION_PROTOCOL_PREFIX, SchemaRequest, TemplateAction,
        WEBSOCKET_PROTOCOL, decode_schema, decode_session, decode_template,
    },
    pve::schema::{self, QemuCreateSchema},
    templates::{Job, Jobs},
};

#[derive(Clone)]
pub(crate) struct AppState {
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
/// Reading the API schema needs no configuration beyond the docs package, so an
/// agent advertises it unconditionally and the panel falls back to its own
/// bundled copy only when a node cannot answer.
pub const SCHEMA_CAPABILITY: &str = "pve.schema";
/// This node can be the *source* of a migration.
pub const EXPORT_CAPABILITY: &str = "migration.export";
/// This node can be the *destination* of a migration.
///
/// It restores a URL, which is all `templates.install` ever did, so this looked
/// at first like it needed no capability of its own. It does: a migration sends
/// `finalize_as_template: false`, and an agent old enough to lack that field
/// silently defaults it to true and converts the tenant's guest into a template
/// that cannot be started. The panel must be able to tell those agents apart
/// before it moves anyone's machine, and a missing capability is how.
pub const MIGRATION_INSTALL_CAPABILITY: &str = "migration.install";
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
            capabilities.push(SCHEMA_CAPABILITY);
            if config.agent.templates_enabled {
                capabilities.push(TEMPLATE_CAPABILITY);
                // Same pipeline, but only an agent that honours
                // `finalize_as_template` may receive a migration.
                capabilities.push(MIGRATION_INSTALL_CAPABILITY);
                if config.agent.exports_enabled {
                    capabilities.push(EXPORT_CAPABILITY);
                }
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

/// As [`router`], but keeping the registry, so a test can put an artifact on
/// disk and then ask for it over HTTP.
#[cfg(test)]
pub fn router_and_jobs(config: Config) -> (Router, Jobs) {
    build(Arc::new(config))
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
        .route("/api/v1/pve/schema", get(pve_schema))
        .route("/api/v1/templates/installs", post(start_install))
        .route(
            "/api/v1/templates/installs/{id}",
            get(job_status).delete(cancel_job),
        )
        .route("/api/v1/templates/exports", post(start_export))
        // `Status` and `Cancel` are one pair of commands over both kinds of
        // job, so they get one pair of routes. The install path above stays
        // exactly where it was, because the panel is already polling it.
        .route(
            "/api/v1/templates/jobs/{id}",
            get(job_status).delete(cancel_job),
        )
        // The contract's path, unprefixed: it is the URL handed to another
        // node's installer, not part of the panel-facing v1 surface.
        .route(
            "/artifacts/{artifact}",
            get(artifacts::download).delete(artifacts::discard),
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

/// Hand back Proxmox's own parameter schema for creating a guest.
///
/// Read on demand rather than cached: it changes only when the node is upgraded,
/// the panel caches the answer anyway, and a stale schema is worse than a slow
/// one -- it would validate a profile against rules this node stopped enforcing.
async fn pve_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<QemuCreateSchema>> {
    let claims = decode_schema(bearer(&headers)?, &state.config)?;
    ensure_agent(&state)?;

    let SchemaRequest::QemuCreate = claims.schema;

    Ok(Json(schema::load(&state.config.agent.apidoc_path)?))
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

/// Queue an export described entirely by the bearer token.
async fn start_export(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Job>)> {
    let claims = decode_template(bearer(&headers)?, &state.config)?;
    ensure_agent(&state)?;

    let TemplateAction::Export(spec) = claims.template else {
        return Err(Error::InvalidSession);
    };

    let job = state.jobs.start_export(*spec)?;

    Ok((StatusCode::ACCEPTED, Json(job)))
}

async fn job_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Job>> {
    authorise_job(&state, &headers, &id, JobAction::Status)?;

    Ok(Json(state.jobs.get(&id)?))
}

async fn cancel_job(
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

pub(crate) fn ensure_agent(state: &AppState) -> Result<()> {
    if state.config.mode != Mode::Agent {
        return Err(Error::InvalidMode("relay".into()));
    }

    Ok(())
}

pub(crate) fn bearer(headers: &HeaderMap) -> Result<&str> {
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
    use sha2::{Digest, Sha256};

    use crate::{config::AgentConfig, protocol::now, templates::Artifacts};

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

    fn export_claim() -> serde_json::Value {
        json!({
            "action": "export",
            "vmid": 100,
            "mode": "stop",
            "compress": "zstd",
        })
    }

    /// A router with one artifact already on disk and in the registry, which is
    /// the state a finished export leaves behind.
    async fn node_with_artifact(body: &[u8]) -> (Router, tempfile::TempDir, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let mut config = config(Mode::Agent);
        config.agent.export_dir = dir.path().display().to_string();

        let (router, jobs) = router_and_jobs(config);
        let id = Artifacts::allocate_id();
        let artifact_dir = jobs.artifacts().directory_for(&id);
        tokio::fs::create_dir_all(&artifact_dir).await.unwrap();
        let path = artifact_dir.join("vzdump-qemu-100-2026_09_20-12_00_00.vma.zst");
        tokio::fs::write(&path, body).await.unwrap();

        let sha256 = hex::encode(Sha256::digest(body));
        jobs.artifacts().register(
            path,
            sha256.clone(),
            body.len() as u64,
            id.clone(),
            Some(artifact_dir),
        );

        (router, dir, id, sha256)
    }

    /// A download request carrying a token minted for `token_id`.
    fn fetch(id: &str, token_id: &str, range: Option<&str>) -> Request<Body> {
        let mut request = Request::get(format!("/artifacts/{id}")).header(
            "authorization",
            format!(
                "Bearer {}",
                token(
                    json!({ "action": "fetch", "artifact": token_id }),
                    "anchor_1"
                )
            ),
        );
        if let Some(range) = range {
            request = request.header("range", range);
        }

        request.body(Body::empty()).unwrap()
    }

    async fn body_of(response: Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    fn header_of(response: &Response, name: &str) -> String {
        response
            .headers()
            .get(name)
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default()
    }

    #[tokio::test]
    async fn advertises_the_export_capability() {
        let response = router(config(Mode::Agent))
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&body_of(response).await).unwrap();
        assert!(
            body["capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!(EXPORT_CAPABILITY))
        );
    }

    /// The destination half is a capability rather than an assumption because an
    /// agent that predates `finalize_as_template` silently defaults it to true
    /// and turns the tenant's guest into an unstartable template. The panel has
    /// to be able to refuse such an agent before it moves anyone's machine.
    #[tokio::test]
    async fn advertises_the_migration_install_capability() {
        let response = router(config(Mode::Agent))
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&body_of(response).await).unwrap();
        assert!(
            body["capabilities"]
                .as_array()
                .unwrap()
                .contains(&json!(MIGRATION_INSTALL_CAPABILITY))
        );
    }

    #[tokio::test]
    async fn hides_the_migration_install_capability_without_the_install_pipeline() {
        let mut config = config(Mode::Agent);
        config.agent.templates_enabled = false;

        let response = router(config)
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&body_of(response).await).unwrap();
        let capabilities = body["capabilities"].as_array().unwrap();
        assert!(!capabilities.contains(&json!(MIGRATION_INSTALL_CAPABILITY)));
    }

    #[tokio::test]
    async fn hides_the_export_capability_when_it_is_switched_off() {
        let mut config = config(Mode::Agent);
        config.agent.exports_enabled = false;

        let response = router(config)
            .oneshot(Request::get("/api/v1/info").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let body: serde_json::Value = serde_json::from_slice(&body_of(response).await).unwrap();
        let capabilities = body["capabilities"].as_array().unwrap();
        assert!(!capabilities.contains(&json!(EXPORT_CAPABILITY)));
        // The install half is unaffected.
        assert!(capabilities.contains(&json!(TEMPLATE_CAPABILITY)));
    }

    #[tokio::test]
    async fn exports_require_a_bearer_token() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/exports")
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_install_token_cannot_start_an_export() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/exports")
                .header(
                    "authorization",
                    format!("Bearer {}", token(install_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_export_token_cannot_start_an_install() {
        let status = status_of(
            router(config(Mode::Agent)),
            Request::post("/api/v1/templates/installs")
                .header(
                    "authorization",
                    format!("Bearer {}", token(export_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_relay_refuses_export_work() {
        let status = status_of(
            router(config(Mode::Relay)),
            Request::post("/api/v1/templates/exports")
                .header(
                    "authorization",
                    format!("Bearer {}", token(export_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn exports_are_refused_when_they_are_disabled() {
        let mut config = config(Mode::Agent);
        config.agent.exports_enabled = false;

        let status = status_of(
            router(config),
            Request::post("/api/v1/templates/exports")
                .header(
                    "authorization",
                    format!("Bearer {}", token(export_claim(), "anchor_1")),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
    }

    /// `Status` and `Cancel` are one pair of commands over both kinds of job,
    /// so the shared route answers for either.
    #[tokio::test]
    async fn the_shared_job_route_authorises_the_same_way() {
        let router = router(config(Mode::Agent));

        let status = status_of(
            router.clone(),
            Request::get("/api/v1/templates/jobs/job_1")
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

        let status = status_of(
            router,
            Request::get("/api/v1/templates/jobs/job_2")
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

    /// The destination downloads through the install pipeline, which fetches
    /// `spec.url` with a bare GET and sets no headers -- it was built to pull
    /// public CDN images. The URL is therefore the only channel the token has,
    /// and a header-only check fails the real migration with a 401 while every
    /// header-based test passes.
    #[tokio::test]
    async fn a_token_in_the_query_string_downloads() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let minted = token(json!({ "action": "fetch", "artifact": id }), "anchor_1");
        let response = router
            .oneshot(
                Request::get(format!("/artifacts/{id}?token={minted}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, b"payload");
    }

    /// The query string is a second door, not a weaker one.
    #[tokio::test]
    async fn a_query_token_for_another_artifact_is_still_refused() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;
        let other = Artifacts::allocate_id();

        let minted = token(json!({ "action": "fetch", "artifact": other }), "anchor_1");
        let status = status_of(
            router,
            Request::get(format!("/artifacts/{id}?token={minted}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn downloading_requires_a_bearer_token() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let status = status_of(
            router,
            Request::get(format!("/artifacts/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// A token authorises one artifact, not the dump directory.
    #[tokio::test]
    async fn a_token_for_one_artifact_cannot_fetch_another() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;
        let other = Artifacts::allocate_id();

        let status = status_of(router, fetch(&id, &other, None)).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_discard_token_cannot_download() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let status = status_of(
            router,
            Request::get(format!("/artifacts/{id}"))
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "discard", "artifact": id }), "anchor_1")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_fetch_token_cannot_discard() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let status = status_of(
            router,
            Request::delete(format!("/artifacts/{id}"))
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "fetch", "artifact": id }), "anchor_1")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_token_for_another_anchor_cannot_fetch() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let status = status_of(
            router,
            Request::get(format!("/artifacts/{id}"))
                .header(
                    "authorization",
                    format!(
                        "Bearer {}",
                        token(json!({ "action": "fetch", "artifact": id }), "anchor_2")
                    ),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_unknown_artifact_is_a_404() {
        let (router, _dir, _id, _) = node_with_artifact(b"payload").await;
        let absent = Artifacts::allocate_id();

        let status = status_of(router, fetch(&absent, &absent, None)).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Even a validly signed token naming a traversal never reaches a path:
    /// the id is a registry key, and one that is not an id is not a key.
    #[tokio::test]
    async fn a_traversing_artifact_id_reaches_nothing() {
        for hostile in [
            "..%2F..%2F..%2Fetc%2Fshadow",
            "%2Fetc%2Fshadow",
            "..",
            "%2E%2E",
            "vzdump-qemu-100.vma.zst",
        ] {
            let (router, _dir, _id, _) = node_with_artifact(b"payload").await;
            let decoded = percent_decode(hostile);

            let response = router
                .oneshot(
                    Request::get(format!("/artifacts/{hostile}"))
                        .header(
                            "authorization",
                            format!(
                                "Bearer {}",
                                token(
                                    json!({ "action": "fetch", "artifact": decoded }),
                                    "anchor_1"
                                )
                            ),
                        )
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert!(
                matches!(
                    response.status(),
                    StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST
                ),
                "{hostile} returned {}",
                response.status()
            );
            assert!(
                !body_of(response).await.starts_with(b"root:"),
                "{hostile} served a file"
            );
        }
    }

    fn percent_decode(raw: &str) -> String {
        let bytes = raw.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap();
                out.push(u8::from_str_radix(hex, 16).unwrap());
                index += 3;
            } else {
                out.push(bytes[index]);
                index += 1;
            }
        }

        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn serves_the_whole_artifact() {
        let payload = b"a-migration-artifact";
        let (router, _dir, id, sha256) = node_with_artifact(payload).await;

        let response = router.oneshot(fetch(&id, &id, None)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(header_of(&response, "accept-ranges"), "bytes");
        assert_eq!(header_of(&response, "content-length"), "20");
        assert_eq!(header_of(&response, "etag"), format!("\"{sha256}\""));
        assert_eq!(
            header_of(&response, "content-type"),
            "application/octet-stream"
        );
        assert!(
            header_of(&response, "content-disposition").contains("vzdump-qemu-100"),
            "the archive name is what qmrestore sniffs the format from"
        );
        assert_eq!(body_of(response).await, payload);
    }

    #[tokio::test]
    async fn serves_an_open_ended_range() {
        let payload = b"a-migration-artifact";
        let (router, _dir, id, _) = node_with_artifact(payload).await;

        let response = router
            .oneshot(fetch(&id, &id, Some("bytes=12-")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header_of(&response, "content-range"), "bytes 12-19/20");
        assert_eq!(header_of(&response, "content-length"), "8");
        assert_eq!(body_of(response).await, b"artifact");
    }

    #[tokio::test]
    async fn serves_a_closed_range() {
        let payload = b"a-migration-artifact";
        let (router, _dir, id, _) = node_with_artifact(payload).await;

        let response = router
            .oneshot(fetch(&id, &id, Some("bytes=2-10")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header_of(&response, "content-range"), "bytes 2-10/20");
        assert_eq!(body_of(response).await, b"migration");
    }

    #[tokio::test]
    async fn serves_a_suffix_range() {
        let payload = b"a-migration-artifact";
        let (router, _dir, id, _) = node_with_artifact(payload).await;

        let response = router
            .oneshot(fetch(&id, &id, Some("bytes=-8")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(header_of(&response, "content-range"), "bytes 12-19/20");
        assert_eq!(body_of(response).await, b"artifact");
    }

    #[tokio::test]
    async fn refuses_an_unsatisfiable_range() {
        let (router, _dir, id, _) = node_with_artifact(b"a-migration-artifact").await;

        let response = router
            .oneshot(fetch(&id, &id, Some("bytes=9000-")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(header_of(&response, "content-range"), "bytes */20");
        assert!(body_of(response).await.is_empty());
    }

    #[tokio::test]
    async fn ignores_a_range_header_it_cannot_honour_and_serves_everything() {
        let payload = b"a-migration-artifact";
        let (router, _dir, id, _) = node_with_artifact(payload).await;

        let response = router
            .oneshot(fetch(&id, &id, Some("furlongs=0-3")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_of(response).await, payload);
    }

    /// The case the whole feature turns on: a download that drops part-way
    /// resumes where it stopped and reassembles to the digest the destination
    /// is going to verify.
    #[tokio::test]
    async fn a_resumed_download_reassembles_to_the_right_digest() {
        // Bigger than one read chunk, so resumption crosses chunk boundaries.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (router, _dir, id, sha256) = node_with_artifact(&payload).await;

        let first = router
            .clone()
            .oneshot(fetch(&id, &id, Some("bytes=0-99999")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::PARTIAL_CONTENT);
        let mut assembled = body_of(first).await;
        assert_eq!(assembled.len(), 100_000, "the transfer dropped here");

        let resumed = router
            .oneshot(fetch(
                &id,
                &id,
                Some(&format!("bytes={}-", assembled.len())),
            ))
            .await
            .unwrap();
        assert_eq!(resumed.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            header_of(&resumed, "content-range"),
            "bytes 100000-199999/200000"
        );
        assembled.extend_from_slice(&body_of(resumed).await);

        assert_eq!(assembled, payload);
        assert_eq!(hex::encode(Sha256::digest(&assembled)), sha256);
    }

    #[tokio::test]
    async fn discarding_removes_the_artifact_and_then_it_is_gone() {
        let (router, _dir, id, _) = node_with_artifact(b"payload").await;

        let response = router
            .clone()
            .oneshot(
                Request::delete(format!("/artifacts/{id}"))
                    .header(
                        "authorization",
                        format!(
                            "Bearer {}",
                            token(json!({ "action": "discard", "artifact": id }), "anchor_1")
                        ),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let status = status_of(router, fetch(&id, &id, None)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
