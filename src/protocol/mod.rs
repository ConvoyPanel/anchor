#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};

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
    pub aud: Vec<String>,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub protocol: u16,
    pub console: ConsoleTarget,
    #[serde(default)]
    pub relay: Option<RelayTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleTarget {
    QemuVnc { vm_id: u32 },
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

pub fn decode_session(token: &str, config: &Config) -> Result<SessionClaims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[&config.installation_id]);
    validation.validate_exp = true;

    let claims = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &validation,
    )
    .map_err(|error| match error.kind() {
        jsonwebtoken::errors::ErrorKind::InvalidAudience => Error::InvalidAudience,
        _ => Error::InvalidSession,
    })?
    .claims;

    if !(PROTOCOL_MIN..=PROTOCOL_MAX).contains(&claims.protocol) {
        return Err(Error::UnsupportedProtocol(claims.protocol));
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
            aud: vec![config.installation_id.clone()],
            exp: now() + 60,
            iat: now(),
            jti: "session_1".into(),
            protocol: PROTOCOL_MAX,
            console: ConsoleTarget::QemuVnc { vm_id: 100 },
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
