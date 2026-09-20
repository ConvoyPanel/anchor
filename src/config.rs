use std::{fmt, net::SocketAddr, path::Path};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

// `ValueEnum` so `anchor enroll --mode relay` accepts exactly the two values
// the wire format uses, rather than a free string validated after the request.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
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
    /// Still used for VNC, which needs Proxmox to install a one-time password.
    #[serde(default = "default_qm_path")]
    pub qm_path: String,
    /// Where PVE keeps guest configs; read to find a VM's serial interface.
    #[serde(default = "default_qemu_config_dir")]
    pub qemu_config_dir: String,
    /// Where QEMU exposes each running guest's chardev sockets.
    #[serde(default = "default_qemu_run_dir")]
    pub qemu_run_dir: String,
    /// Restores a downloaded vzdump artifact into a guest.
    #[serde(default = "default_qmrestore_path")]
    pub qmrestore_path: String,
    /// Dumps a guest into an artifact another node can restore. The source
    /// half of a migration; `qmrestore_path` is the destination half.
    #[serde(default = "default_vzdump_path")]
    pub vzdump_path: String,
    /// pmxcfs mount point, read to learn which VMIDs the cluster already uses.
    #[serde(default = "default_pve_dir")]
    pub pve_dir: String,
    /// Scratch space for in-flight template downloads. Lives under the dump
    /// directory because that is the volume sized for whole guest images.
    #[serde(default = "default_template_temp_dir")]
    pub template_temp_dir: String,
    /// Proxmox's own API schema, shipped with `pve-docs`. Read so the panel can
    /// validate a hardware profile against the rules this node will enforce,
    /// instead of against whatever PVE release the panel was built for.
    #[serde(default = "default_apidoc_path")]
    pub apidoc_path: String,
    /// Whether this agent will install templates at all.
    #[serde(default = "default_true")]
    pub templates_enabled: bool,
    /// How many template installs may run at once. Each one holds a multi-GB
    /// artifact on disk and a `qmrestore` writing it out, so this is a disk
    /// budget as much as a CPU one. Exports draw on the same budget: a
    /// `vzdump` costs the node the same disk and the same I/O bandwidth.
    #[serde(default = "default_template_concurrency")]
    pub template_concurrency: usize,
    /// Whether this agent will export guests for migration at all. Separate
    /// from `templates_enabled` because reading a guest's whole disk out to a
    /// file another machine may download is a different grant from writing an
    /// image in, and an admin may well want one without the other.
    #[serde(default = "default_true")]
    pub exports_enabled: bool,
    /// Where exports are written when the request names no storage. A
    /// directory Anchor owns outright, so it can be swept without ever
    /// touching an admin's own backups.
    #[serde(default = "default_export_dir")]
    pub export_dir: String,
    /// How long a finished artifact survives before it is deleted, whether or
    /// not a migration ever claimed it. The failure this exists for is a
    /// multi-gigabyte file nobody remembers to discard, so it is a ceiling and
    /// not a hint: the sweeper does not ask whether anything is still using it.
    #[serde(default = "default_export_ttl_secs")]
    pub export_ttl_secs: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            qm_path: default_qm_path(),
            qemu_config_dir: default_qemu_config_dir(),
            qemu_run_dir: default_qemu_run_dir(),
            qmrestore_path: default_qmrestore_path(),
            vzdump_path: default_vzdump_path(),
            pve_dir: default_pve_dir(),
            template_temp_dir: default_template_temp_dir(),
            apidoc_path: default_apidoc_path(),
            templates_enabled: default_true(),
            template_concurrency: default_template_concurrency(),
            exports_enabled: default_true(),
            export_dir: default_export_dir(),
            export_ttl_secs: default_export_ttl_secs(),
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
        if self.mode == Mode::Agent
            && self.agent.templates_enabled
            && self.agent.qmrestore_path.trim().is_empty()
        {
            return Err(Error::Configuration(
                "agent.qmrestore_path must not be empty when templates are enabled".into(),
            ));
        }
        if self.mode == Mode::Agent
            && self.agent.exports_enabled
            && self.agent.vzdump_path.trim().is_empty()
        {
            return Err(Error::Configuration(
                "agent.vzdump_path must not be empty when exports are enabled".into(),
            ));
        }
        if self.mode == Mode::Agent
            && self.agent.exports_enabled
            && self.agent.export_dir.trim().is_empty()
        {
            return Err(Error::Configuration(
                "agent.export_dir must not be empty when exports are enabled".into(),
            ));
        }
        if self.agent.template_concurrency == 0 {
            return Err(Error::Configuration(
                "agent.template_concurrency must be at least 1".into(),
            ));
        }
        // A zero TTL would sweep every artifact the instant it was registered,
        // so the export would succeed and the download would 404.
        if self.agent.exports_enabled && self.agent.export_ttl_secs == 0 {
            return Err(Error::Configuration(
                "agent.export_ttl_secs must be at least 1".into(),
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

fn default_qemu_config_dir() -> String {
    "/etc/pve/qemu-server".to_owned()
}

fn default_qemu_run_dir() -> String {
    "/var/run/qemu-server".to_owned()
}

fn default_qmrestore_path() -> String {
    "/usr/sbin/qmrestore".to_owned()
}

fn default_vzdump_path() -> String {
    "/usr/bin/vzdump".to_owned()
}

fn default_pve_dir() -> String {
    "/etc/pve".to_owned()
}

fn default_template_temp_dir() -> String {
    "/var/lib/vz/dump/anchor-tmp".to_owned()
}

fn default_apidoc_path() -> String {
    "/usr/share/pve-docs/api-viewer/apidoc.js".to_owned()
}

fn default_true() -> bool {
    true
}

fn default_template_concurrency() -> usize {
    2
}

fn default_export_dir() -> String {
    "/var/lib/vz/dump/anchor-exports".to_owned()
}

/// A day. Long enough that a slow transfer over a congested tailnet still
/// finds its artifact, short enough that a forgotten one does not outlive the
/// week.
fn default_export_ttl_secs() -> u64 {
    24 * 60 * 60
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
        assert_eq!(config.agent.vzdump_path, "/usr/bin/vzdump");
        assert_eq!(config.agent.export_dir, "/var/lib/vz/dump/anchor-exports");
        assert_eq!(config.agent.export_ttl_secs, 86_400);
        assert!(config.agent.exports_enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_an_export_ttl_that_would_sweep_every_artifact_immediately() {
        let config: Config = toml::from_str(
            r#"
mode = "agent"
installation_id = "anchor_123"
secret = "12345678901234567890123456789012"
panel_url = "https://panel.example.com"

[agent]
export_ttl_secs = 0
"#,
        )
        .unwrap();

        assert!(matches!(config.validate(), Err(Error::Configuration(_))));
    }

    #[test]
    fn a_node_that_never_exports_need_not_have_vzdump() {
        let config: Config = toml::from_str(
            r#"
mode = "agent"
installation_id = "anchor_123"
secret = "12345678901234567890123456789012"
panel_url = "https://panel.example.com"

[agent]
exports_enabled = false
vzdump_path = ""
export_ttl_secs = 0
"#,
        )
        .unwrap();

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
