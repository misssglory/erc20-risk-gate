use crate::providers::etherscan::{normalize_source_files, EtherscanContract, EtherscanSourceFile};
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize)]
pub struct SourceWarning {
    pub label: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LaunchpadEntityMatch {
    pub entity: String,
    pub found_in_source: bool,
    pub found_in_file_name: bool,
    pub found_in_contract_name: bool,
    pub matched_file_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceAnalysis {
    pub verified: bool,
    pub provider: String,
    pub source_url: String,
    pub contract_name: String,
    pub source_file_names: Vec<String>,
    pub launchpad_entity_found: bool,
    pub pons_found: bool,
    pub launchpad_entities_found: Vec<LaunchpadEntityMatch>,
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

pub fn build_source_analysis(contract: &EtherscanContract) -> SourceAnalysis {
    let files = normalized_files(contract);
    let entities = detect_launchpad_entities(&files, &contract.contract_name);
    let pons_found = entities
        .iter()
        .any(|entity| entity.entity.eq_ignore_ascii_case("Pons"));

    SourceAnalysis {
        verified: !files.is_empty(),
        provider: if contract.source_origin.trim().is_empty() {
            "etherscan".to_string()
        } else {
            contract.source_origin.clone()
        },
        source_url: contract.source_url.clone(),
        contract_name: contract.contract_name.clone(),
        source_file_names: files.iter().map(|file| file.name.clone()).collect(),
        launchpad_entity_found: !entities.is_empty(),
        pons_found,
        launchpad_entities_found: entities,
    }
}

pub fn combined_source_code(contract: &EtherscanContract) -> String {
    let files = normalized_files(contract);
    if files.is_empty() {
        contract.source_code.clone()
    } else {
        files
            .iter()
            .map(|file| file.content.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

fn normalized_files(contract: &EtherscanContract) -> Vec<EtherscanSourceFile> {
    if !contract.source_files.is_empty() {
        contract.source_files.clone()
    } else {
        normalize_source_files(&contract.source_code, &contract.contract_name)
    }
}

fn detect_launchpad_entities(
    files: &[EtherscanSourceFile],
    contract_name: &str,
) -> Vec<LaunchpadEntityMatch> {
    let launchpads = [
        (
            "Pons",
            r"(?i)\b(?:i)?pons(?:v\d+)?(?:[_\- ]?(?:launcher|launchpad|factory|router|token|bondingcurve|curve|pool|pair))*\b|pons\.fun|0x7ed598bcef8bd9edd8c97a195c6d13f40801ec7e|0xe33e9e479df8802cb0866d5d05258bec4cf62948|0xe5e702641ea86f4ae6cc3cdaed2b886f976be044|0xa5aab3f0c6eeadf30ef1d3eb997108e976351feb|0x0c37a24f5d23a486fa692d1500881d698b1f77a4",
        ),
        (
            "Fomo.Family",
            r"(?i)\bfomo(?:[_\- ]?(?:family|launchpad|factory|router|token|curve|pool|pair))?\b|fomo\.family",
        ),
        (
            "Runitup",
            r"(?i)\brunitup(?:[_\- ]?(?:launchpad|factory|router|token|curve|pool|pair))?\b|run[ _\-]?it[ _\-]?up",
        ),
        (
            "Flaunch",
            r"(?i)\bflaunch(?:[_\- ]?(?:launchpad|factory|router|token|curve|pool|pair))?\b",
        ),
        (
            "PairPad",
            r"(?i)\bpairpad(?:[_\- ]?(?:launchpad|factory|router|token|curve|pool|pair))?\b",
        ),
    ];

    let mut found = Vec::new();

    for (entity, pattern) in launchpads {
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };

        let mut found_in_source = false;
        let mut found_in_file_name = false;
        let found_in_contract_name = re.is_match(contract_name);
        let mut matched_files = BTreeSet::new();

        for file in files {
            let name_match = re.is_match(&file.name);
            let source_match = re.is_match(&file.content);
            found_in_file_name |= name_match;
            found_in_source |= source_match;

            if name_match || source_match {
                matched_files.insert(file.name.clone());
            }
        }

        if found_in_source || found_in_file_name || found_in_contract_name {
            found.push(LaunchpadEntityMatch {
                entity: entity.to_string(),
                found_in_source,
                found_in_file_name,
                found_in_contract_name,
                matched_file_names: matched_files.into_iter().collect(),
            });
        }
    }

    found
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pons_v2_launcher_from_contract_and_filename() {
        let files = vec![EtherscanSourceFile {
            name: "contracts/src/v2/PonsV2LauncherToken.sol".to_string(),
            content: "contract PonsV2LauncherToken {}".to_string(),
        }];

        let matches = detect_launchpad_entities(&files, "PonsV2LauncherToken");
        let pons = matches
            .iter()
            .find(|item| item.entity == "Pons")
            .expect("Pons should be detected");

        assert!(pons.found_in_contract_name);
        assert!(pons.found_in_file_name);
        assert!(pons.found_in_source);
    }

    #[test]
    fn pons_does_not_match_sponsor() {
        let files = vec![EtherscanSourceFile {
            name: "SponsorToken.sol".to_string(),
            content: "contract SponsorToken {}".to_string(),
        }];

        let matches = detect_launchpad_entities(&files, "SponsorToken");
        assert!(!matches.iter().any(|item| item.entity == "Pons"));
    }
}
