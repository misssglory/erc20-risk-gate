use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub chain_id: String,
    pub logging: LoggingConfig,
    pub server: ServerConfig,
    pub http: HttpConfig,
    pub api: ApiConfig,
    pub robinhood: RobinhoodConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
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
pub struct RobinhoodConfig {
    pub enabled: bool,
    pub rpc_url: String,
    pub blockscout_url: String,
    pub holders_limit: u32,
    pub transfer_amount_divisor: u32,
    pub transfer_target: String,
    pub template_min_bytecode_bytes: usize,
    pub template_max_bytecode_bytes: usize,
    pub bad_actor_db_path: String,
    pub hard_block_known_bad_actor: bool,
    pub bad_deployers: Vec<String>,
    pub bad_owners: Vec<String>,
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
            server: ServerConfig::default(),
            http: HttpConfig::default(),
            api: ApiConfig::default(),
            robinhood: RobinhoodConfig::default(),
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

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
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

impl Default for RobinhoodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rpc_url: "https://rpc.mainnet.chain.robinhood.com".to_string(),
            blockscout_url: "https://robinhoodchain.blockscout.com".to_string(),
            holders_limit: 50,
            transfer_amount_divisor: 100,
            transfer_target: "0x8366a39cc670b4001a1121b8f6a443a643e40951".to_string(),
            template_min_bytecode_bytes: 8 * 1024,
            template_max_bytecode_bytes: 10 * 1024,
            bad_actor_db_path: "robinhood-bad-actors.json".to_string(),
            hard_block_known_bad_actor: true,
            bad_deployers: Vec::new(),
            bad_owners: Vec::new(),
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
