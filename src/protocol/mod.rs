#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    config::Config,
    error::{Error, Result},
};

pub const PROTOCOL_MIN: u16 = 1;
pub const PROTOCOL_MAX: u16 = 1;
pub const WEBSOCKET_PROTOCOL: &str = "anchor.v1";
pub const SESSION_PROTOCOL_PREFIX: &str = "anchor.session.";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: f64,
    pub iat: f64,
    pub jti: String,
    pub protocol: u16,
    pub console: ConsoleTarget,
    #[serde(default)]
    pub relay: Option<RelayTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleTarget {
    QemuVnc { vm_id: u32, password: String },
    QemuTerminal { vm_id: u32 },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelayTarget {
    pub url: UrlString,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct UrlString(pub String);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

/// Claims on a template-management token.
///
/// Deliberately a separate claim set from [`SessionClaims`] rather than another
/// `console` variant: these tokens are minted for the panel's own background
/// jobs, never for a user's browser, and carry no console target at all.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TemplateClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: f64,
    pub iat: f64,
    pub jti: String,
    pub protocol: u16,
    pub template: TemplateAction,
}

/// What a template token authorises.
///
/// The work order travels *inside the token*, the same way [`ConsoleTarget`]
/// does, so a captured token can only ever replay the exact install it was
/// minted for — it cannot be pointed at a different URL, VMID or storage.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TemplateAction {
    Install(Box<InstallSpec>),
    Status { job: String },
    Cancel { job: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstallSpec {
    /// Registry template name, e.g. `debian-12-amd64`. Logging and display only.
    pub name: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub size: Option<u64>,
    pub vmid: u32,
    pub storage: String,
    /// Restore over an existing guest at this VMID instead of refusing.
    #[serde(default)]
    pub overwrite: bool,
}

/// Claims on a schema-read token.
///
/// Its own claim set for the same reason [`TemplateClaims`] is: the panel mints
/// these for itself, never for a browser, and they authorise reading a
/// definition off this node rather than doing anything to it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SchemaClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: f64,
    pub iat: f64,
    pub jti: String,
    pub protocol: u16,
    pub schema: SchemaRequest,
}

/// Which definition a schema token authorises reading.
///
/// An enum with one variant today, because the next thing the panel wants to
/// read off a node -- storage content types, say -- should be a new variant
/// rather than a new endpoint and a new token type.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SchemaRequest {
    QemuCreate,
}

/// Claim sets that carry the protocol version Anchor negotiates on.
pub trait Protocolled {
    fn protocol(&self) -> u16;
}

impl Protocolled for SessionClaims {
    fn protocol(&self) -> u16 {
        self.protocol
    }
}

impl Protocolled for TemplateClaims {
    fn protocol(&self) -> u16 {
        self.protocol
    }
}

impl Protocolled for SchemaClaims {
    fn protocol(&self) -> u16 {
        self.protocol
    }
}

pub fn decode_session(token: &str, config: &Config) -> Result<SessionClaims> {
    decode_claims(token, config)
}

pub fn decode_template(token: &str, config: &Config) -> Result<TemplateClaims> {
    decode_claims(token, config)
}

pub fn decode_schema(token: &str, config: &Config) -> Result<SchemaClaims> {
    decode_claims(token, config)
}

fn decode_claims<T: DeserializeOwned + Protocolled>(token: &str, config: &Config) -> Result<T> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[&config.installation_id]);
    validation.validate_exp = true;

    let claims = decode::<T>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|error| {
        tracing::debug!(kind = ?error.kind(), "session token validation failed");
        match error.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidAudience => Error::InvalidAudience,
            _ => Error::InvalidSession,
        }
    })?
    .claims;

    if !(PROTOCOL_MIN..=PROTOCOL_MAX).contains(&claims.protocol()) {
        return Err(Error::UnsupportedProtocol(claims.protocol()));
    }

    Ok(claims)
}

#[cfg(test)]
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time is after Unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use jsonwebtoken::{EncodingKey, Header, encode};
    use url::Url;

    use super::*;
    use crate::config::{AgentConfig, Mode};

    fn config() -> Config {
        Config {
            mode: Mode::Agent,
            listen_addr: "127.0.0.1:2115".parse::<SocketAddr>().unwrap(),
            installation_id: "agent_1".into(),
            secret: "12345678901234567890123456789012".into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig::default(),
        }
    }

    #[test]
    fn validates_audience_and_protocol() {
        let config = config();
        let claims = SessionClaims {
            iss: "https://panel.example.com".into(),
            sub: "user_1".into(),
            aud: Audience::One(config.installation_id.clone()),
            exp: (now() + 60) as f64,
            iat: now() as f64,
            jti: "session_1".into(),
            protocol: PROTOCOL_MAX,
            console: ConsoleTarget::QemuVnc {
                vm_id: 100,
                password: "12345678".into(),
            },
            relay: None,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )
        .unwrap();

        assert_eq!(decode_session(&token, &config).unwrap().sub, "user_1");
    }
}
