use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub chain_id: String,
    pub logging: LoggingConfig,
    pub http: HttpConfig,
    pub api: ApiConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub tokensniffer_api_key: String,
    pub etherscan_api_key: String,
    pub goplus_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub min_score_buy: i32,
    pub tokensniffer_min_score: i64,

    pub sell_tax_warn: f64,
    pub sell_tax_block: f64,

    pub buy_tax_warn: f64,
    pub buy_tax_block: f64,

    pub skip_unverified_source: bool,
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;

        Ok(cfg)
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            chain_id: "1".to_string(),
            logging: LoggingConfig::default(),
            http: HttpConfig::default(),
            api: ApiConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: 20,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            tokensniffer_api_key: String::new(),
            etherscan_api_key: String::new(),
            goplus_token: None,
        }
    }
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            min_score_buy: 85,
            tokensniffer_min_score: 60,
            sell_tax_warn: 10.0,
            sell_tax_block: 30.0,
            buy_tax_warn: 10.0,
            buy_tax_block: 30.0,
            skip_unverified_source: true,
        }
    }
}