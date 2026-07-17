use std::{fmt, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Agent,
    Relay,
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Agent => formatter.write_str("agent"),
            Self::Relay => formatter.write_str("relay"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub mode: Mode,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: SocketAddr,
    pub installation_id: String,
    pub secret: String,
    pub panel_url: Url,
    #[serde(default)]
    pub public_url: Option<Url>,
    #[serde(default)]
    pub agent: AgentConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentConfig {
    #[serde(default = "default_qm_path")]
    pub qm_path: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            qm_path: default_qm_path(),
        }
    }
}

impl Config {
    pub async fn load(path: &Path) -> Result<Self> {
        let contents = tokio::fs::read_to_string(path).await?;
        let config: Self = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.installation_id.trim().is_empty() {
            return Err(Error::Configuration(
                "installation_id must not be empty".into(),
            ));
        }
        if self.secret.len() < 32 {
            return Err(Error::Configuration(
                "secret must contain at least 32 characters".into(),
            ));
        }
        if self.mode == Mode::Agent && self.agent.qm_path.trim().is_empty() {
            return Err(Error::Configuration(
                "agent.qm_path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

fn default_listen_addr() -> SocketAddr {
    "127.0.0.1:2115"
        .parse()
        .expect("default listen address is valid")
}

fn default_qm_path() -> String {
    "/usr/sbin/qm".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applies_safe_defaults() {
        let config: Config = toml::from_str(
            r#"
mode = "agent"
installation_id = "anchor_123"
secret = "12345678901234567890123456789012"
panel_url = "https://panel.example.com"
"#,
        )
        .unwrap();

        assert_eq!(config.listen_addr, "127.0.0.1:2115".parse().unwrap());
        assert_eq!(config.agent.qm_path, "/usr/sbin/qm");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_short_secrets() {
        let config: Config = toml::from_str(
            r#"
mode = "relay"
installation_id = "anchor_123"
secret = "short"
panel_url = "https://panel.example.com"
"#,
        )
        .unwrap();

        assert!(matches!(config.validate(), Err(Error::Configuration(_))));
    }
}
