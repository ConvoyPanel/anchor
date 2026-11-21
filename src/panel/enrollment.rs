use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::{Config, Mode},
    error::{Error, Result},
    panel::report::Report,
};

#[derive(Debug, Serialize)]
struct EnrollmentRequest {
    token: String,
    /// Ignored by the panel on the targeted path, where the mode is already
    /// recorded against the row being re-keyed. Load-bearing when the token is
    /// an enrollment key: there is no row yet to disagree with.
    mode: Mode,
    report: Report,
}

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    config: Config,
}

pub async fn enroll(panel_url: Url, token: String, mode: Mode, path: PathBuf) -> Result<()> {
    let endpoint = panel_url
        .join("api/anchor/enroll")
        .map_err(|error| Error::Configuration(error.to_string()))?;
    let response = reqwest::Client::new()
        .post(endpoint)
        .json(&EnrollmentRequest {
            token,
            mode,
            report: Report::gather(mode).await,
        })
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        // The panel's own words where it has any: "this key does not admit an
        // agent" is the whole answer, and a bare status code sends an operator
        // to the panel's logs to rediscover it.
        let status = response.status();
        let detail = response
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|body| {
                body.get("message")
                    .and_then(|message| message.as_str())
                    .map(str::to_owned)
            });

        return Err(Error::Configuration(match detail {
            Some(message) => format!("panel rejected enrollment: {message}"),
            None => format!("panel rejected enrollment with HTTP {status}"),
        }));
    }

    let response: EnrollmentResponse = response.json().await?;
    response.config.validate()?;
    let contents = toml::to_string_pretty(&response.config)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Configuration("configuration path has no parent".into()))?;
    tokio::fs::create_dir_all(parent).await?;

    let temporary = path.with_extension("toml.tmp");
    tokio::fs::write(&temporary, contents).await?;
    tokio::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).await?;
    tokio::fs::rename(temporary, path).await?;

    Ok(())
}
