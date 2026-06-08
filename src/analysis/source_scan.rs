use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SourceWarning {
    pub label: String,
    pub pattern: String,
}

pub fn scan_source_code(source: &str) -> Vec<SourceWarning> {
    let checks = [
        (
            "blacklist_or_botlist",
            r"(?i)blacklist|isBlacklisted|_blacklist|botlist|bots|_bots|ban",
        ),
        (
            "whitelist_or_allowlist",
            r"(?i)whitelist|allowlist|isWhitelisted|isAllowed|_whitelist",
        ),
        (
            "fee_or_tax_setter",
            r"(?i)function\s+\w*(set|update|change)\w*(fee|tax|slippage)",
        ),
        (
            "max_transaction_or_wallet_setter",
            r"(?i)function\s+\w*(set|update|change)\w*(maxTx|maxWallet|maxTransaction)",
        ),
        (
            "pause_or_trading_gate",
            r"(?i)pause|paused|tradingEnabled|enableTrading|swapEnabled",
        ),
        (
            "mint_function",
            r"(?i)function\s+mint|_mint\s*\(",
        ),
        (
            "owner_balance_manipulation",
            r"(?i)_balances\s*\[.*\]\s*=",
        ),
        (
            "delegatecall_or_proxy_like",
            r"(?i)delegatecall",
        ),
        (
            "cooldown_logic",
            r"(?i)cooldown|lastTransfer|lastTx|transferDelay",
        ),
        (
            "fee_exclusion_logic",
            r"(?i)excludeFromFee|isExcludedFromFee|_isExcluded",
        ),
    ];

    let mut warnings = Vec::new();

    for (label, pattern) in checks {
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };

        if re.is_match(source) {
            warnings.push(SourceWarning {
                label: label.to_string(),
                pattern: pattern.to_string(),
            });
        }
    }

    warnings
}