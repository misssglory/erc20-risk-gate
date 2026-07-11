use crate::analysis;
use crate::chains::ResolvedChain;
use crate::config::AppConfig;
use crate::models::{Decision, ProviderError, ProviderOutputs, ProviderStatus, RiskReport, SkippedCheck};
use anyhow::Result;
use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Scanner {
    cfg: AppConfig,
    http: Client,
}

impl Scanner {
    pub fn new(cfg: AppConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(cfg.http.timeout_seconds))
            .user_agent("erc20-risk-gate/0.1")
            .build()?;

        Ok(Self { cfg, http })
    }

    pub async fn scan(&self, address: String, chain_id_override: Option<String>) -> RiskReport {
        let chain_input = chain_id_override.unwrap_or_else(|| self.cfg.chain_id.clone());

        let chain = match ResolvedChain::resolve(&chain_input) {
            Ok(chain) => chain,
            Err(error) => {
                return unsupported_chain_report(chain_input, address, error.to_string());
            }
        };

        info!(
            chain_input = %chain.input,
            chain = %chain.canonical,
            evm_chain_id = %chain.evm_chain_id,
            dexscreener_chain_id = %chain.dexscreener_chain_id,
            address = %address,
            "starting token scan"
        );

        let outputs = self.fetch_all(&chain, &address).await;

        analysis::rules::analyze(
            chain.evm_chain_id.to_string(),
            address,
            &self.cfg.rules,
            outputs,
        )
    }

    async fn fetch_all(&self, chain: &ResolvedChain, address: &str) -> ProviderOutputs {
        let mut outputs = ProviderOutputs::default();

        if self.cfg.api.tokensniffer_api_key.trim().is_empty() {
            outputs.skipped.push(SkippedCheck::new(
                "tokensniffer",
                "tokensniffer_api_key is missing",
            ));
        } else {
            match crate::providers::tokensniffer::fetch(
                &self.http,
                chain.tokensniffer_chain_id,
                address,
                &self.cfg.api.tokensniffer_api_key,
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

        match crate::providers::goplus::fetch(
            &self.http,
            chain.goplus_chain_id,
            address,
            self.cfg.api.goplus_token.as_deref(),
        )
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

        match crate::providers::honeypot::fetch(&self.http, chain.honeypot_chain_id, address).await {
            Ok(v) => {
                info!("Honeypot.is check completed");
                outputs.honeypot = Some(v);
            }
            Err(e) => {
                warn!(error = %e, "Honeypot.is check failed");
                outputs.errors.push(ProviderError::new("honeypot", e));
            }
        }

        if self.cfg.api.etherscan_api_key.trim().is_empty() {
            outputs.skipped.push(SkippedCheck::new(
                "etherscan",
                "etherscan_api_key is missing",
            ));
        } else {
            match crate::providers::etherscan::fetch_source(
                &self.http,
                chain.etherscan_chain_id,
                address,
                &self.cfg.api.etherscan_api_key,
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

        match crate::providers::dexscreener::fetch_token_pairs(
            &self.http,
            chain.dexscreener_chain_id,
            address,
        )
        .await
        {
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
}

fn unsupported_chain_report(chain_id: String, address: String, message: String) -> RiskReport {
    RiskReport {
        chain_id,
        token_address: address,
        decision: Decision::Skip,
        score: 0,
        hard_blocks: vec![message],
        warnings: Vec::new(),
        skipped_checks: Vec::new(),
        provider_errors: Vec::new(),
        provider_status: ProviderStatus {
            tokensniffer: "not_run".to_string(),
            goplus: "not_run".to_string(),
            honeypot: "not_run".to_string(),
            etherscan_source: "not_run".to_string(),
            dexscreener: "not_run".to_string(),
        },
    }
}
