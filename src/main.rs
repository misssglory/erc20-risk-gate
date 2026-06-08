mod analysis;
mod config;
mod models;
mod providers;

use anyhow::Result;
use clap::Parser;
use config::AppConfig;
use models::{ProviderError, ProviderOutputs, SkippedCheck};
use reqwest::Client;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Parser, Debug)]
struct Args {
    /// ERC-20 token address
    #[arg(long)]
    address: String,

    /// Chain ID. Overrides config.toml chain_id.
    #[arg(long)]
    chain_id: Option<String>,

    /// Path to config.toml
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    /// Pretty-print JSON
    #[arg(long)]
    pretty: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let mut cfg = AppConfig::load(&args.config)?;
    if let Some(chain_id) = args.chain_id {
        cfg.chain_id = chain_id;
    }

    init_tracing(&cfg.logging.level);

    info!(
        chain_id = %cfg.chain_id,
        address = %args.address,
        "starting token risk scan"
    );

    let http = Client::builder()
        .timeout(Duration::from_secs(cfg.http.timeout_seconds))
        .user_agent("erc20-risk-gate/0.1")
        .build()?;

    let outputs = fetch_all(&http, &cfg, &args.address).await;

    let report = analysis::rules::analyze(
        cfg.chain_id.clone(),
        args.address.clone(),
        &cfg.rules,
        outputs,
    );

    if args.pretty {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", serde_json::to_string(&report)?);
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

async fn fetch_all(http: &Client, cfg: &AppConfig, address: &str) -> ProviderOutputs {
    let mut outputs = ProviderOutputs::default();

    if cfg.api.tokensniffer_api_key.trim().is_empty() {
        outputs.skipped.push(SkippedCheck::new(
            "tokensniffer",
            "tokensniffer_api_key is missing",
        ));
    } else {
        match providers::tokensniffer::fetch(
            http,
            &cfg.chain_id,
            address,
            &cfg.api.tokensniffer_api_key,
        )
        .await
        {
            Ok(v) => {
                info!("TokenSniffer check completed");
                outputs.tokensniffer = Some(v);
            }
            Err(e) => {
                warn!(error = %e, "TokenSniffer check failed");
                outputs.errors.push(ProviderError::new("tokensniffer", e));
            }
        }
    }

    match providers::goplus::fetch(http, &cfg.chain_id, address, cfg.api.goplus_token.as_deref())
        .await
    {
        Ok(v) => {
            info!("GoPlus check completed");
            outputs.goplus = Some(v);
        }
        Err(e) => {
            warn!(error = %e, "GoPlus check failed");
            outputs.errors.push(ProviderError::new("goplus", e));
        }
    }

    match providers::honeypot::fetch(http, &cfg.chain_id, address).await {
        Ok(v) => {
            info!("Honeypot.is check completed");
            outputs.honeypot = Some(v);
        }
        Err(e) => {
            warn!(error = %e, "Honeypot.is check failed");
            outputs.errors.push(ProviderError::new("honeypot", e));
        }
    }

    if cfg.api.etherscan_api_key.trim().is_empty() {
        outputs.skipped.push(SkippedCheck::new(
            "etherscan",
            "etherscan_api_key is missing",
        ));
    } else {
        match providers::etherscan::fetch_source(
            http,
            &cfg.chain_id,
            address,
            &cfg.api.etherscan_api_key,
        )
        .await
        {
            Ok(v) => {
                info!("Etherscan source check completed");
                outputs.etherscan_source = Some(v);
            }
            Err(e) => {
                warn!(error = %e, "Etherscan source check failed");
                outputs.errors.push(ProviderError::new("etherscan", e));
            }
        }
    }

    match providers::dexscreener::fetch_token_pairs(http, &cfg.chain_id, address).await {
        Ok(v) => {
            info!("DexScreener check completed");
            outputs.dexscreener = Some(v);
        }
        Err(e) => {
            warn!(error = %e, "DexScreener check failed");
            outputs.errors.push(ProviderError::new("dexscreener", e));
        }
    }

    outputs
}