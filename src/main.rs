mod analysis;
mod config;
mod models;
mod providers;
mod scanner;
mod server;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::AppConfig;
use scanner::Scanner;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "erc20-risk-gate")]
#[command(version)]
#[command(about = "ERC-20 token risk scanner")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to config.toml
    #[arg(long, global = true, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan one token and print JSON to stdout
    Scan {
        /// ERC-20 token address
        #[arg(long)]
        address: String,

        /// Chain ID. Overrides config.toml chain_id.
        #[arg(long)]
        chain_id: Option<String>,

        /// Pretty-print JSON
        #[arg(long)]
        pretty: bool,
    },

    /// Start HTTP server
    Serve {
        /// Override server host from config.toml
        #[arg(long)]
        host: Option<String>,

        /// Override server port from config.toml
        #[arg(long)]
        port: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut cfg = AppConfig::load(&cli.config)?;
    init_tracing(&cfg.logging.level);

    match cli.command {
        Commands::Scan {
            address,
            chain_id,
            pretty,
        } => {
            if let Some(chain_id) = chain_id {
                cfg.chain_id = chain_id;
            }

            info!(
                chain_id = %cfg.chain_id,
                address = %address,
                "starting CLI token scan"
            );

            let scanner = Scanner::new(cfg)?;
            let report = scanner.scan(address, None).await;

            if pretty {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", serde_json::to_string(&report)?);
            }
        }

        Commands::Serve { host, port } => {
            if let Some(host) = host {
                cfg.server.host = host;
            }

            if let Some(port) = port {
                cfg.server.port = port;
            }

            server::run(cfg).await?;
        }
    }

    Ok(())
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
}