use crate::providers::etherscan::EtherscanContract;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Default)]
pub struct ProviderOutputs {
    pub tokensniffer: Option<Value>,
    pub goplus: Option<Value>,
    pub honeypot: Option<Value>,
    pub etherscan_source: Option<EtherscanContract>,
    pub dexscreener: Option<Value>,
    pub skipped: Vec<SkippedCheck>,
    pub errors: Vec<ProviderError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskReport {
    pub chain_id: String,
    pub token_address: String,
    pub decision: Decision,
    pub score: i32,
    pub hard_blocks: Vec<String>,
    pub warnings: Vec<String>,
    pub skipped_checks: Vec<SkippedCheck>,
    pub provider_errors: Vec<ProviderError>,
    pub provider_status: ProviderStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    BuyAllowed,
    ManualReview,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedCheck {
    pub provider: String,
    pub reason: String,
}

impl SkippedCheck {
    pub fn new(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderError {
    pub provider: String,
    pub message: String,
}

impl ProviderError {
    pub fn new(provider: impl Into<String>, error: impl std::fmt::Display) -> Self {
        Self {
            provider: provider.into(),
            message: error.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderStatus {
    pub tokensniffer: String,
    pub goplus: String,
    pub honeypot: String,
    pub etherscan_source: String,
    pub dexscreener: String,
}