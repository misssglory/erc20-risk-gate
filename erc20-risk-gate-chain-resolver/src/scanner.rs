use crate::analysis;
use crate::chains::ResolvedChain;
use crate::config::AppConfig;
use crate::models::{Decision, ProviderError, ProviderOutputs, ProviderStatus, RiskReport, SkippedCheck};
use crate::providers::robinhood::BadActorStore;
use anyhow::Result;
use reqwest::Client;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Clone)]
pub struct Scanner {
    cfg: AppConfig,
    http: Client,
    robinhood_bad_actors: Arc<Mutex<BadActorStore>>,
}

impl Scanner {
    pub fn new(cfg: AppConfig) -> Result<Self> {
        let http = Client::builder()
            .timeout(Duration::from_secs(cfg.http.timeout_seconds))
            .user_agent("erc20-risk-gate/0.2")
            .build()?;

        let mut bad_actors = if cfg.robinhood.bad_actor_db_path.trim().is_empty() {
            BadActorStore::default()
        } else {
            match BadActorStore::load(Path::new(&cfg.robinhood.bad_actor_db_path)) {
                Ok(store) => store,
                Err(error) => {
                    warn!(error = %error, "failed to load Robinhood bad-actor DB; starting with an empty store");
                    BadActorStore::default()
                }
            }
        };
        bad_actors.seed(
            &cfg.robinhood.bad_deployers,
            &cfg.robinhood.bad_owners,
        );

        Ok(Self {
            cfg,
            http,
            robinhood_bad_actors: Arc::new(Mutex::new(bad_actors)),
        })
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
            &self.cfg.robinhood,
            outputs,
        )
    }

    async fn fetch_all(&self, chain: &ResolvedChain, address: &str) -> ProviderOutputs {
        let mut outputs = ProviderOutputs::default();
        let is_robinhood = chain.canonical == "robinhood";

        if is_robinhood {
            if !self.cfg.robinhood.enabled {
                outputs.skipped.push(SkippedCheck::new(
                    "robinhood",
                    "Robinhood native risk gate is disabled in config",
                ));
            } else {
                match crate::providers::robinhood::fetch(
                    &self.http,
                    &self.cfg.robinhood.rpc_url,
                    &self.cfg.robinhood.blockscout_url,
                    address,
                    self.cfg.robinhood.holders_limit,
                    self.cfg.robinhood.transfer_amount_divisor,
                    &self.cfg.robinhood.transfer_target,
                    self.cfg.robinhood.template_min_bytecode_bytes,
                    self.cfg.robinhood.template_max_bytecode_bytes,
                )
                .await
                {
                    Ok(mut value) => {
                        let direct_evidence = value.direct_honeypot_evidence();
                        let direct_reason = value.direct_evidence_reason();

                        let mut store = self
                            .robinhood_bad_actors
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());

                        value.known_bad_deployer = store.is_bad_deployer(value.deployer.as_deref());
                        value.known_bad_owner = store.is_bad_owner(value.owner.as_deref());

                        if direct_evidence {
                            if let Some(reason) = direct_reason {
                                let changed = store.record_direct_evidence(
                                    address,
                                    value.deployer.as_deref(),
                                    value.owner.as_deref(),
                                    reason,
                                );

                                if changed && !self.cfg.robinhood.bad_actor_db_path.trim().is_empty() {
                                    if let Err(error) = store.save(Path::new(
                                        &self.cfg.robinhood.bad_actor_db_path,
                                    )) {
                                        warn!(error = %error, "failed to persist Robinhood bad-actor DB");
                                        value.diagnostics.push(format!(
                                            "failed to persist bad-actor DB: {error}"
                                        ));
                                    }
                                }
                            }
                        }

                        info!("Robinhood native risk check completed");
                        outputs.robinhood = Some(value);
                    }
                    Err(error) => {
                        warn!(error = %error, "Robinhood native risk check failed");
                        outputs.errors.push(ProviderError::new("robinhood", error));
                    }
                }
            }
        }

        if is_robinhood {
            outputs.skipped.push(SkippedCheck::new(
                "tokensniffer",
                "Robinhood Chain uses the native RPC/Blockscout risk gate instead",
            ));
        } else if self.cfg.api.tokensniffer_api_key.trim().is_empty() {
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

        if is_robinhood {
            outputs.skipped.push(SkippedCheck::new(
                "honeypot",
                "Honeypot.is is not used for Robinhood Chain; native holder transfer simulation is used",
            ));
        } else {
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
        }

        if is_robinhood {
            outputs.skipped.push(SkippedCheck::new(
                "etherscan",
                "Robinhood Chain uses Blockscout, not Etherscan",
            ));
        } else if self.cfg.api.etherscan_api_key.trim().is_empty() {
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
            robinhood: "not_run".to_string(),
        },
        robinhood_risk: None,
    }
}
