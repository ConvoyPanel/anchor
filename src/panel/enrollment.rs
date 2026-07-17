use std::{os::unix::fs::PermissionsExt, path::PathBuf};

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    config::Config,
    error::{Error, Result},
};

#[derive(Debug, Serialize)]
struct EnrollmentRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    config: Config,
}

pub async fn enroll(panel_url: Url, token: String, path: PathBuf) -> Result<()> {
    let endpoint = panel_url
        .join("api/anchor/enroll")
        .map_err(|error| Error::Configuration(error.to_string()))?;
    let response = reqwest::Client::new()
        .post(endpoint)
        .json(&EnrollmentRequest { token })
        .send()
        .await?;

    if response.status() != StatusCode::OK {
        return Err(Error::Configuration(format!(
            "panel rejected enrollment with HTTP {}",
            response.status()
        )));
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
