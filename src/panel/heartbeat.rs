use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tokio::time::MissedTickBehavior;

use crate::{
    api::capabilities,
    config::{Config, Mode},
    protocol::{PROTOCOL_MAX, PROTOCOL_MIN},
};

#[derive(Debug, Serialize)]
struct Heartbeat<'a> {
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

pub async fn run(config: Config) {
    let client = Client::new();
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        interval.tick().await;
        if let Err(error) = send(&client, &config).await {
            tracing::warn!(%error, "could not report heartbeat to the panel");
        }
    }
}

async fn send(client: &Client, config: &Config) -> reqwest::Result<()> {
    let endpoint = config
        .panel_url
        .join("api/anchor/heartbeat")
        .expect("validated panel URL accepts a relative endpoint");
    let response = client
        .post(endpoint)
        .bearer_auth(format!("{}.{}", config.installation_id, config.secret))
        .json(&heartbeat(config))
        .send()
        .await?;

    response.error_for_status()?;
    Ok(())
}

/// The same capabilities `/api/v1/info` reports, not just the console ones.
///
/// The panel overwrites what it knows about an agent with each heartbeat, so a
/// heartbeat that listed only the consoles took back, the moment the agent
/// started, every capability the configuration had granted -- and with them
/// the panel's permission to send this node templates or migrations.
fn heartbeat(config: &Config) -> Heartbeat<'static> {
    Heartbeat {
        version: env!("CARGO_PKG_VERSION"),
        mode: config.mode,
        protocol: ProtocolRange {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        },
        capabilities: capabilities(config),
    }
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::*;
    use crate::{
        api::{EXPORT_CAPABILITY, RELAY_CAPABILITIES, SNIPPETS_CAPABILITY, TEMPLATE_CAPABILITY},
        config::AgentConfig,
    };

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

    #[test]
    fn reports_what_the_configuration_grants() {
        let capabilities = heartbeat(&config(Mode::Agent)).capabilities;

        assert!(capabilities.contains(&TEMPLATE_CAPABILITY));
        assert!(capabilities.contains(&EXPORT_CAPABILITY));
        assert!(capabilities.contains(&SNIPPETS_CAPABILITY));
    }

    #[test]
    fn withdraws_what_the_configuration_switches_off() {
        let mut config = config(Mode::Agent);
        config.agent.exports_enabled = false;
        config.agent.snippets_enabled = false;

        let capabilities = heartbeat(&config).capabilities;

        assert!(!capabilities.contains(&EXPORT_CAPABILITY));
        assert!(!capabilities.contains(&SNIPPETS_CAPABILITY));
        assert!(capabilities.contains(&TEMPLATE_CAPABILITY));
    }

    #[test]
    fn a_relay_reports_only_the_relay() {
        assert_eq!(
            heartbeat(&config(Mode::Relay)).capabilities,
            RELAY_CAPABILITIES
        );
    }
}
