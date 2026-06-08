use crate::analysis::source_scan::scan_source_code;
use crate::analysis::value_ext::{
    bool_at, first_goplus_token, number_at, recursive_bool, recursive_number,
};
use crate::config::RulesConfig;
use crate::models::{Decision, ProviderOutputs, ProviderStatus, RiskReport};

pub fn analyze(
    chain_id: String,
    token_address: String,
    rules: &RulesConfig,
    outputs: ProviderOutputs,
) -> RiskReport {
    let mut score: i32 = 100;
    let mut hard_blocks = Vec::new();
    let mut warnings = Vec::new();

    analyze_tokensniffer(
        outputs.tokensniffer.as_ref(),
        rules,
        &mut score,
        &mut hard_blocks,
        &mut warnings,
    );

    analyze_goplus(
        outputs.goplus.as_ref(),
        rules,
        &mut score,
        &mut hard_blocks,
        &mut warnings,
    );

    analyze_honeypot(
        outputs.honeypot.as_ref(),
        rules,
        &mut score,
        &mut hard_blocks,
        &mut warnings,
    );

    analyze_etherscan_source(
        outputs.etherscan_source.as_ref(),
        rules,
        &mut score,
        &mut hard_blocks,
        &mut warnings,
    );

    analyze_dexscreener(
        outputs.dexscreener.as_ref(),
        &mut score,
        &mut warnings,
    );

    score = score.clamp(0, 100);

    let decision = if !hard_blocks.is_empty() {
        Decision::Skip
    } else if score >= rules.min_score_buy {
        Decision::BuyAllowed
    } else {
        Decision::ManualReview
    };

    let provider_status = ProviderStatus {
        tokensniffer: status(outputs.tokensniffer.is_some(), "tokensniffer", &outputs),
        goplus: status(outputs.goplus.is_some(), "goplus", &outputs),
        honeypot: status(outputs.honeypot.is_some(), "honeypot", &outputs),
        etherscan_source: status(outputs.etherscan_source.is_some(), "etherscan", &outputs),
        dexscreener: status(outputs.dexscreener.is_some(), "dexscreener", &outputs),
    };

    RiskReport {
        chain_id,
        token_address,
        decision,
        score,
        hard_blocks,
        warnings,
        skipped_checks: outputs.skipped,
        provider_errors: outputs.errors,
        provider_status,
    }
}

fn status(ok: bool, provider: &str, outputs: &ProviderOutputs) -> String {
    if ok {
        return "ok".to_string();
    }

    if outputs.skipped.iter().any(|s| s.provider == provider) {
        return "skipped".to_string();
    }

    if outputs.errors.iter().any(|e| e.provider == provider) {
        return "error".to_string();
    }

    "not_run".to_string()
}

fn analyze_tokensniffer(
    value: Option<&serde_json::Value>,
    rules: &RulesConfig,
    score: &mut i32,
    hard_blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(v) = value else {
        warnings.push("TokenSniffer skipped or unavailable".to_string());
        *score -= 5;
        return;
    };

    if recursive_bool(v, "is_flagged").unwrap_or(false) {
        hard_blocks.push("TokenSniffer: token is flagged".to_string());
        *score -= 100;
    }

    if recursive_bool(v, "is_scam").unwrap_or(false) {
        hard_blocks.push("TokenSniffer: scam flag detected".to_string());
        *score -= 100;
    }

    if recursive_bool(v, "is_rugpull").unwrap_or(false) {
        hard_blocks.push("TokenSniffer: rugpull flag detected".to_string());
        *score -= 100;
    }

    if recursive_bool(v, "is_suspect").unwrap_or(false) {
        warnings.push("TokenSniffer: suspicious token flag detected".to_string());
        *score -= 20;
    }

    if let Some(ts_score) = recursive_number(v, "score") {
        if ts_score < rules.tokensniffer_min_score as f64 {
            hard_blocks.push(format!(
                "TokenSniffer score too low: {}",
                clean_num(ts_score)
            ));
            *score -= 50;
        } else if ts_score < 85.0 {
            warnings.push(format!(
                "TokenSniffer medium score: {}",
                clean_num(ts_score)
            ));
            *score -= 15;
        }
    }

    if recursive_bool(v, "has_blocklist").unwrap_or(false) {
        hard_blocks.push("TokenSniffer: blocklist detected".to_string());
        *score -= 80;
    }

    if recursive_bool(v, "has_fee_modifier").unwrap_or(false) {
        warnings.push("TokenSniffer: fee modifier detected".to_string());
        *score -= 25;
    }

    if recursive_bool(v, "has_mint").unwrap_or(false) {
        warnings.push("TokenSniffer: mint function detected".to_string());
        *score -= 25;
    }

    if recursive_bool(v, "has_proxy").unwrap_or(false) {
        warnings.push("TokenSniffer: proxy behavior detected".to_string());
        *score -= 20;
    }

    if let Some(false) = recursive_bool(v, "is_sellable") {
        hard_blocks.push("TokenSniffer: simulated sell failed".to_string());
        *score -= 100;
    }

    if let Some(sell_fee) = recursive_number(v, "sell_fee") {
        check_tax(
            "TokenSniffer sell fee",
            sell_fee,
            rules.sell_tax_warn,
            rules.sell_tax_block,
            score,
            hard_blocks,
            warnings,
        );
    }

    if let Some(buy_fee) = recursive_number(v, "buy_fee") {
        check_tax(
            "TokenSniffer buy fee",
            buy_fee,
            rules.buy_tax_warn,
            rules.buy_tax_block,
            score,
            hard_blocks,
            warnings,
        );
    }
}

fn analyze_goplus(
    value: Option<&serde_json::Value>,
    rules: &RulesConfig,
    score: &mut i32,
    hard_blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(v) = value else {
        warnings.push("GoPlus unavailable".to_string());
        *score -= 5;
        return;
    };

    let token = first_goplus_token(v);

    if token.and_then(|t| bool_at(t, &["is_honeypot"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: honeypot detected".to_string());
        *score -= 100;
    }

    if token.and_then(|t| bool_at(t, &["is_blacklisted"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: blacklist detected".to_string());
        *score -= 80;
    }

    if token.and_then(|t| bool_at(t, &["is_whitelisted"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: whitelist restriction detected".to_string());
        *score -= 80;
    }

    if token.and_then(|t| bool_at(t, &["hidden_owner"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: hidden owner detected".to_string());
        *score -= 90;
    }

    if token.and_then(|t| bool_at(t, &["owner_change_balance"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: owner can change balances".to_string());
        *score -= 100;
    }

    if token.and_then(|t| bool_at(t, &["cannot_sell_all"])).unwrap_or(false) {
        hard_blocks.push("GoPlus: cannot sell all tokens".to_string());
        *score -= 100;
    }

    if token.and_then(|t| bool_at(t, &["trading_cooldown"])).unwrap_or(false) {
        warnings.push("GoPlus: trading cooldown detected".to_string());
        *score -= 20;
    }

    if token.and_then(|t| bool_at(t, &["transfer_pausable"])).unwrap_or(false) {
        warnings.push("GoPlus: transfers can be paused".to_string());
        *score -= 30;
    }

    if token.and_then(|t| bool_at(t, &["is_mintable"])).unwrap_or(false) {
        warnings.push("GoPlus: token is mintable".to_string());
        *score -= 25;
    }

    if token.and_then(|t| bool_at(t, &["slippage_modifiable"])).unwrap_or(false) {
        warnings.push("GoPlus: tax/slippage can be modified".to_string());
        *score -= 25;
    }

    if let Some(t) = token {
        if let Some(sell_tax) = number_at(t, &["sell_tax"]) {
            check_tax(
                "GoPlus sell tax",
                sell_tax,
                rules.sell_tax_warn,
                rules.sell_tax_block,
                score,
                hard_blocks,
                warnings,
            );
        }

        if let Some(buy_tax) = number_at(t, &["buy_tax"]) {
            check_tax(
                "GoPlus buy tax",
                buy_tax,
                rules.buy_tax_warn,
                rules.buy_tax_block,
                score,
                hard_blocks,
                warnings,
            );
        }
    }
}

fn analyze_honeypot(
    value: Option<&serde_json::Value>,
    rules: &RulesConfig,
    score: &mut i32,
    hard_blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(v) = value else {
        warnings.push("Honeypot.is unavailable".to_string());
        *score -= 5;
        return;
    };

    if bool_at(v, &["honeypotResult", "isHoneypot"]).unwrap_or(false) {
        hard_blocks.push("Honeypot.is: honeypot detected".to_string());
        *score -= 100;
    }

    if let Some(reason) = v
        .get("honeypotResult")
        .and_then(|x| x.get("honeypotReason"))
        .and_then(|x| x.as_str())
    {
        if !reason.trim().is_empty() {
            warnings.push(format!("Honeypot.is reason: {reason}"));
            *score -= 20;
        }
    }

    if let Some(sell_tax) = number_at(v, &["simulationResult", "sellTax"]) {
        check_tax(
            "Honeypot.is sell tax",
            sell_tax,
            rules.sell_tax_warn,
            rules.sell_tax_block,
            score,
            hard_blocks,
            warnings,
        );
    }

    if let Some(buy_tax) = number_at(v, &["simulationResult", "buyTax"]) {
        check_tax(
            "Honeypot.is buy tax",
            buy_tax,
            rules.buy_tax_warn,
            rules.buy_tax_block,
            score,
            hard_blocks,
            warnings,
        );
    }
}

fn analyze_etherscan_source(
    source: Option<&crate::providers::etherscan::EtherscanContract>,
    rules: &RulesConfig,
    score: &mut i32,
    hard_blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(contract) = source else {
        warnings.push("Etherscan source skipped or unavailable".to_string());
        *score -= 10;
        return;
    };

    let source_code = contract.source_code.trim();

    if source_code.is_empty() || source_code == "Contract source code not verified" {
        if rules.skip_unverified_source {
            hard_blocks.push("Source code is not verified".to_string());
            *score -= 80;
        } else {
            warnings.push("Source code is not verified".to_string());
            *score -= 30;
        }

        return;
    }

    if contract.proxy == "1" {
        warnings.push(format!(
            "Etherscan: proxy contract detected, implementation: {}",
            contract.implementation
        ));
        *score -= 25;
    }

    if !contract.similar_match.trim().is_empty() {
        warnings.push(format!(
            "Etherscan: similar contract match: {}",
            contract.similar_match
        ));
        *score -= 10;
    }

    let source_warnings = scan_source_code(source_code);

    for warning in source_warnings {
        warnings.push(format!("Source scan: {}", warning.label));
        *score -= 10;
    }
}

fn analyze_dexscreener(
    value: Option<&serde_json::Value>,
    score: &mut i32,
    warnings: &mut Vec<String>,
) {
    let Some(v) = value else {
        warnings.push("DexScreener unavailable".to_string());
        *score -= 5;
        return;
    };

    let Some(pairs) = v.as_array() else {
        warnings.push("DexScreener: unexpected response format".to_string());
        *score -= 5;
        return;
    };

    if pairs.is_empty() {
        warnings.push("DexScreener: no token pairs found".to_string());
        *score -= 20;
        return;
    }

    let mut best_liquidity_usd = 0.0;

    for pair in pairs {
        let liquidity = pair
            .get("liquidity")
            .and_then(|l| l.get("usd"))
            .and_then(|x| {
                if x.is_string() {
                    x.as_str()?.parse::<f64>().ok()
                } else {
                    x.as_f64()
                }
            })
            .unwrap_or(0.0);

        if liquidity > best_liquidity_usd {
            best_liquidity_usd = liquidity;
        }
    }

    if best_liquidity_usd <= 0.0 {
        warnings.push("DexScreener: liquidity not found".to_string());
        *score -= 20;
    } else if best_liquidity_usd < 10_000.0 {
        warnings.push(format!(
            "DexScreener: very low liquidity: ${}",
            clean_num(best_liquidity_usd)
        ));
        *score -= 25;
    } else if best_liquidity_usd < 50_000.0 {
        warnings.push(format!(
            "DexScreener: low liquidity: ${}",
            clean_num(best_liquidity_usd)
        ));
        *score -= 10;
    }
}

fn check_tax(
    label: &str,
    tax: f64,
    warn_threshold: f64,
    block_threshold: f64,
    score: &mut i32,
    hard_blocks: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if tax >= block_threshold {
        hard_blocks.push(format!("{label} too high: {}%", clean_num(tax)));
        *score -= 100;
    } else if tax >= warn_threshold {
        warnings.push(format!("{label} is high: {}%", clean_num(tax)));
        *score -= 25;
    }
}

fn clean_num(n: f64) -> String {
    if n.fract() == 0.0 {
        format!("{}", n as i64)
    } else {
        format!("{:.4}", n)
    }
}