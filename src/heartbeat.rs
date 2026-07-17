use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use tokio::time::MissedTickBehavior;

use crate::{
    app::{AGENT_CAPABILITIES, RELAY_CAPABILITIES},
    config::{Config, Mode},
    protocol::{PROTOCOL_MAX, PROTOCOL_MIN},
};

#[derive(Debug, Serialize)]
struct Heartbeat<'a> {
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
        .json(&Heartbeat {
            version: env!("CARGO_PKG_VERSION"),
            mode: config.mode,
            protocol: ProtocolRange {
                min: PROTOCOL_MIN,
                max: PROTOCOL_MAX,
            },
            capabilities: match config.mode {
                Mode::Agent => AGENT_CAPABILITIES,
                Mode::Relay => RELAY_CAPABILITIES,
            },
        })
        .send()
        .await?;

    response.error_for_status()?;
    Ok(())
}
