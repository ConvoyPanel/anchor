use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;

use crate::{
    Error, Result, api,
    config::{Config, Mode},
    panel::{enrollment, heartbeat},
};

#[derive(Debug, Parser)]
#[command(name = "anchor", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the Anchor daemon.
    Serve {
        #[arg(short, long, default_value = "/etc/anchor/anchor.toml")]
        config: PathBuf,
    },
    /// Exchange a panel token for this installation's credentials.
    ///
    /// Works with both kinds of token: one issued for an Anchor the panel
    /// already has a row for, and an enrollment key that admits a machine the
    /// panel has never seen. The panel tells them apart; nothing here has to.
    Enroll {
        #[arg(long)]
        panel_url: url::Url,
        #[arg(long)]
        token: String,
        /// What this installation is going to run as. Only consulted when the
        /// token is an enrollment key -- otherwise the panel already knows.
        #[arg(long, value_enum, default_value_t = Mode::Agent)]
        mode: Mode,
        #[arg(short, long, default_value = "/etc/anchor/anchor.toml")]
        config: PathBuf,
    },
    /// Validate a configuration file without starting Anchor.
    Validate {
        #[arg(short, long, default_value = "/etc/anchor/anchor.toml")]
        config: PathBuf,
    },
    /// Check a running Anchor health endpoint.
    Health {
        #[arg(long, default_value = "http://127.0.0.1:2115/health")]
        url: url::Url,
    },
}

pub async fn run() -> Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve {
        config: PathBuf::from("/etc/anchor/anchor.toml"),
    }) {
        Command::Serve { config } => serve(config).await,
        Command::Enroll {
            panel_url,
            token,
            mode,
            config,
        } => enrollment::enroll(panel_url, token, mode, config).await,
        Command::Validate { config } => {
            Config::load(&config).await?;
            info!(path = %config.display(), "configuration is valid");
            Ok(())
        }
        Command::Health { url } => {
            let response = reqwest::get(url).await?;
            if !response.status().is_success() {
                return Err(Error::Health(response.status()));
            }
            Ok(())
        }
    }
}

async fn serve(path: PathBuf) -> Result<()> {
    let config = std::sync::Arc::new(Config::load(&path).await?);
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(mode = %config.mode, address = %config.listen_addr, "Anchor is ready");
    let heartbeat = tokio::spawn(heartbeat::run((*config).clone()));

    let (router, jobs) = api::build(config);
    // Template jobs do not survive a restart, so anything still in the scratch
    // directory is an orphaned partial download sitting on the dump volume.
    jobs.sweep_temp_dir().await;
    // Same reasoning for exports, which are larger still: the registry that
    // made them reachable is gone, so whatever is left is unreachable.
    jobs.artifacts().clear_root().await;
    // Nothing else deletes an artifact whose migration failed before the panel
    // got as far as `Discard`.
    let sweeper = tokio::spawn(jobs.artifacts().clone().run_sweeper());

    axum::serve(listener, router.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    heartbeat.abort();
    sweeper.abort();

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install termination handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
