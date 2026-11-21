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
///
/// The migration contract calls this enum `Command`; it is `TemplateAction`
/// here because that is the name the install side already shipped, and
/// renaming it would churn the destination side for no gain. The variants are
/// the contract's, and `action` is still the tag on the wire.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum TemplateAction {
    Install(Box<InstallSpec>),
    /// Produce a migratable archive of one guest on this node.
    Export(Box<ExportSpec>),
    /// Read one finished archive. Kept separate from [`Self::Discard`] so a
    /// token minted to let a destination node *download* an artifact cannot
    /// also delete it; neither one authorises the dump directory at large.
    Fetch {
        artifact: String,
    },
    /// Remove one finished archive.
    Discard {
        artifact: String,
    },
    Status {
        job: String,
    },
    Cancel {
        job: String,
    },
}

/// A request to dump one guest into an archive this node will then serve.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExportSpec {
    pub vmid: u32,
    /// `stop` is the only mode a migration may use: a snapshot-mode archive is
    /// crash-consistent as of the moment it began, so every write the guest
    /// made during the transfer would be silently lost at cutover. The panel
    /// stops the guest before asking for the export and leaves it stopped until
    /// the destination is verified, so this restates in the protocol what the
    /// ordering already requires.
    #[serde(default)]
    pub mode: ExportMode,
    #[serde(default)]
    pub compress: Compression,
    /// Where the archive is written. `None` means the node's own dump
    /// directory, which in practice is a per-artifact directory Anchor owns
    /// under `agent.export_dir` and can therefore sweep.
    #[serde(default)]
    pub storage: Option<String>,
}

/// How `vzdump` treats the guest it is dumping.
///
/// One variant, deliberately. See [`ExportSpec::mode`]: the alternatives are
/// all wrong for a migration, so this exists to state the choice on the wire
/// rather than to offer a menu.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportMode {
    #[default]
    Stop,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// `vzdump`'s own default, and much faster than gzip at a comparable ratio
    /// on the disk images this moves.
    #[default]
    Zstd,
    Lzo,
    None,
}

impl ExportMode {
    pub fn vzdump_arg(self) -> &'static str {
        match self {
            Self::Stop => "stop",
        }
    }
}

impl Compression {
    /// What `vzdump --compress` accepts. `0` is how it spells "none".
    pub fn vzdump_arg(self) -> &'static str {
        match self {
            Self::Zstd => "zstd",
            Self::Lzo => "lzo",
            Self::None => "0",
        }
    }

    /// The suffix `vzdump` gives an archive compressed this way. Used only to
    /// recognise the archive inside a directory Anchor owns, never to build a
    /// path from anything a caller supplied.
    pub fn archive_suffix(self) -> &'static str {
        match self {
            Self::Zstd => ".vma.zst",
            Self::Lzo => ".vma.lzo",
            Self::None => ".vma",
        }
    }
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
    /// Convert the restored guest into a template when the restore finishes.
    ///
    /// True for an image import, which is the only thing this pipeline used to
    /// serve: Convoy offers a guest only when it reports `template: 1`, so an
    /// import that skipped this would appear to succeed and then be invisible.
    ///
    /// A migration needs the opposite. The restored guest is the tenant's own
    /// machine and templating it would leave them with something that cannot be
    /// started, so the panel sends `false`. Defaults to true, which keeps every
    /// existing import caller correct without changing what it sends.
    #[serde(default = "default_finalize_as_template")]
    pub finalize_as_template: bool,
}

fn default_finalize_as_template() -> bool {
    true
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
    /// An import that never heard of this field must keep templating, or every
    /// existing caller silently starts producing guests Convoy will not offer.
    #[test]
    fn an_install_spec_without_the_field_still_templates() {
        let spec: InstallSpec = serde_json::from_str(
            r#"{"name":"debian-12","url":"https://example.invalid/a.vma.zst",
                "sha256":"ab","vmid":900,"storage":"local"}"#,
        )
        .expect("spec parses");

        assert!(spec.finalize_as_template);
    }

    /// A migration says so explicitly, and must be taken at its word.
    #[test]
    fn a_migration_install_spec_opts_out_of_templating() {
        let spec: InstallSpec = serde_json::from_str(
            r#"{"name":"guest-101","url":"https://example.invalid/a.vma.zst",
                "sha256":"ab","vmid":901,"storage":"local","finalize_as_template":false}"#,
        )
        .expect("spec parses");

        assert!(!spec.finalize_as_template);
    }

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

    fn template_token(action: serde_json::Value, audience: &str, expires_in: i64) -> String {
        let claims = serde_json::json!({
            "iss": "https://panel.example.com",
            "sub": "panel",
            "aud": audience,
            "exp": now() as i64 + expires_in,
            "iat": now() as i64 - 1,
            "jti": "token_1",
            "protocol": PROTOCOL_MAX,
            "template": action,
        });

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config().secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn an_export_action_round_trips_through_a_token() {
        let token = template_token(
            serde_json::json!({
                "action": "export",
                "vmid": 100,
                "mode": "stop",
                "compress": "zstd",
                "storage": null,
            }),
            "agent_1",
            60,
        );

        let claims = decode_template(&token, &config()).unwrap();
        let TemplateAction::Export(spec) = claims.template else {
            panic!("expected an export action");
        };
        assert_eq!(spec.vmid, 100);
        assert_eq!(spec.mode, ExportMode::Stop);
        assert_eq!(spec.compress, Compression::Zstd);
        assert!(spec.storage.is_none());
    }

    /// A panel that omits the optional fields gets the only safe combination
    /// rather than a deserialisation error.
    #[test]
    fn an_export_spec_defaults_to_a_stopped_zstd_dump() {
        let spec: ExportSpec = serde_json::from_value(serde_json::json!({ "vmid": 4001 })).unwrap();

        assert_eq!(spec.mode, ExportMode::Stop);
        assert_eq!(spec.compress, Compression::Zstd);
        assert_eq!(spec.storage, None);
    }

    #[test]
    fn fetch_and_discard_each_name_one_artifact() {
        for action in ["fetch", "discard"] {
            let token = template_token(
                serde_json::json!({ "action": action, "artifact": "artifact_1" }),
                "agent_1",
                60,
            );

            let named = match decode_template(&token, &config()).unwrap().template {
                TemplateAction::Fetch { artifact } | TemplateAction::Discard { artifact } => {
                    artifact
                }
                other => panic!("expected fetch or discard, got {other:?}"),
            };
            assert_eq!(named, "artifact_1");
        }
    }

    #[test]
    fn an_expired_artifact_token_is_rejected() {
        let token = template_token(
            serde_json::json!({ "action": "fetch", "artifact": "artifact_1" }),
            "agent_1",
            -120,
        );

        assert!(matches!(
            decode_template(&token, &config()),
            Err(Error::InvalidSession)
        ));
    }

    #[test]
    fn an_artifact_token_for_another_anchor_is_rejected() {
        let token = template_token(
            serde_json::json!({ "action": "fetch", "artifact": "artifact_1" }),
            "agent_2",
            60,
        );

        assert!(matches!(
            decode_template(&token, &config()),
            Err(Error::InvalidAudience)
        ));
    }

    #[test]
    fn compression_maps_onto_vzdumps_own_spelling() {
        assert_eq!(Compression::Zstd.vzdump_arg(), "zstd");
        assert_eq!(Compression::Lzo.vzdump_arg(), "lzo");
        assert_eq!(Compression::None.vzdump_arg(), "0");
        assert_eq!(ExportMode::Stop.vzdump_arg(), "stop");
        assert_eq!(Compression::None.archive_suffix(), ".vma");
        assert_eq!(Compression::Zstd.archive_suffix(), ".vma.zst");
    }

    #[test]
    fn the_wire_names_are_the_contracts() {
        assert_eq!(
            serde_json::to_value(ExportMode::Stop).unwrap(),
            serde_json::json!("stop")
        );
        assert_eq!(
            serde_json::to_value(Compression::None).unwrap(),
            serde_json::json!("none")
        );
    }
}
