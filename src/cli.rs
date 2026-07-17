use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tracing::info;

use crate::{
    Error, Result, api,
    config::Config,
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
    /// Exchange a one-time panel token for this installation's credentials.
    Enroll {
        #[arg(long)]
        panel_url: url::Url,
        #[arg(long)]
        token: String,
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
            config,
        } => enrollment::enroll(panel_url, token, config).await,
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
    let config = Config::load(&path).await?;
    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    info!(mode = %config.mode, address = %config.listen_addr, "Anchor is ready");
    let heartbeat = tokio::spawn(heartbeat::run(config.clone()));

    axum::serve(listener, api::router(config).into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    heartbeat.abort();

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
