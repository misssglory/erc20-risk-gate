use anyhow::{bail, Context, Result};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize)]
struct EtherscanResponse {
    status: String,
    message: String,
    result: Vec<EtherscanContract>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EtherscanContract {
    #[serde(rename = "SourceCode")]
    pub source_code: String,

    #[serde(rename = "ABI")]
    pub abi: String,

    #[serde(rename = "ContractName")]
    pub contract_name: String,

    #[serde(rename = "CompilerVersion")]
    pub compiler_version: String,

    #[serde(rename = "Proxy")]
    pub proxy: String,

    #[serde(rename = "Implementation")]
    pub implementation: String,

    #[serde(rename = "SimilarMatch")]
    pub similar_match: String,

    /// Normalized source files extracted from Etherscan's standard-json SourceCode payload
    /// or from the RobinScan HTML code tab fallback.
    #[serde(default)]
    pub source_files: Vec<EtherscanSourceFile>,

    /// Where this source was loaded from: `etherscan_v2` or `robinscan_html`.
    #[serde(default)]
    pub source_origin: String,

    /// Human-facing explorer page corresponding to the loaded source.
    #[serde(default)]
    pub source_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EtherscanSourceFile {
    pub name: String,
    pub content: String,
}


/// Fetch the creator/deployer of a contract through Etherscan API V2.
/// This is used by the Robinhood gate instead of a chain-specific explorer API.
pub async fn fetch_contract_creator(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
) -> Result<Option<String>> {
    if api_key.trim().is_empty() {
        bail!("etherscan_api_key is required for contract creator lookup");
    }

    let value = http
        .get("https://api.etherscan.io/v2/api")
        .query(&[
            ("chainid", chain_id),
            ("module", "contract"),
            ("action", "getcontractcreation"),
            ("contractaddresses", address),
            ("apikey", api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    ensure_v2_success(&value, "getcontractcreation")?;
    let result = value
        .get("result")
        .and_then(Value::as_array)
        .context("Etherscan getcontractcreation returned non-array result")?;

    Ok(result.first().and_then(|item| {
        ["contractCreator", "ContractCreator", "contractcreator"]
            .iter()
            .find_map(|key| item.get(*key).and_then(Value::as_str))
            .map(str::to_string)
    }))
}

/// Fetch token holders through Etherscan API V2.
/// Addresses are returned in Etherscan's holder order (largest first for the
/// tokenholderlist endpoint), and the caller can perform its own EOA/balance checks.
pub async fn fetch_token_holders(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
    limit: u32,
) -> Result<Vec<String>> {
    if api_key.trim().is_empty() {
        bail!("etherscan_api_key is required for token holder lookup");
    }

    match fetch_tokenholderlist(http, chain_id, address, api_key, limit).await {
        Ok(holders) if !holders.is_empty() => Ok(holders),
        primary_result => {
            // tokenholderlist/topholder access may depend on the Etherscan plan.
            // We only need genuine holder candidates for the live transfer test, so
            // stay entirely on Etherscan and fall back to recent ERC-20 transfer
            // participants, then let the Robinhood RPC verify EOA status + balance.
            match fetch_recent_token_participants(http, chain_id, address, api_key, limit).await {
                Ok(holders) if !holders.is_empty() => Ok(holders),
                Ok(_) => match primary_result {
                    Ok(_) => Ok(Vec::new()),
                    Err(primary_error) => Err(primary_error).context(
                        "Etherscan tokenholderlist failed and tokentx fallback returned no holder candidates",
                    ),
                },
                Err(fallback_error) => match primary_result {
                    Ok(_) => Err(fallback_error).context(
                        "Etherscan tokenholderlist returned no holders and tokentx fallback failed",
                    ),
                    Err(primary_error) => bail!(
                        "Etherscan holder discovery failed: tokenholderlist: {primary_error}; tokentx fallback: {fallback_error}"
                    ),
                },
            }
        }
    }
}

async fn fetch_tokenholderlist(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
    limit: u32,
) -> Result<Vec<String>> {
    let page = "1".to_string();
    let offset = limit.clamp(1, 100).to_string();
    let value = http
        .get("https://api.etherscan.io/v2/api")
        .query(&[
            ("chainid", chain_id),
            ("module", "token"),
            ("action", "tokenholderlist"),
            ("contractaddress", address),
            ("page", page.as_str()),
            ("offset", offset.as_str()),
            ("apikey", api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    ensure_v2_success(&value, "tokenholderlist")?;
    let result = value
        .get("result")
        .and_then(Value::as_array)
        .context("Etherscan tokenholderlist returned non-array result")?;

    Ok(result
        .iter()
        .filter_map(|item| {
            [
                "TokenHolderAddress",
                "tokenHolderAddress",
                "tokenholderaddress",
                "address",
            ]
            .iter()
            .find_map(|key| item.get(*key).and_then(Value::as_str))
        })
        .map(str::to_string)
        .collect())
}

async fn fetch_recent_token_participants(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
    limit: u32,
) -> Result<Vec<String>> {
    let page = "1".to_string();
    let offset = limit.max(1).saturating_mul(6).min(300).to_string();
    let value = http
        .get("https://api.etherscan.io/v2/api")
        .query(&[
            ("chainid", chain_id),
            ("module", "account"),
            ("action", "tokentx"),
            ("contractaddress", address),
            ("page", page.as_str()),
            ("offset", offset.as_str()),
            ("sort", "desc"),
            ("apikey", api_key),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    ensure_v2_success(&value, "tokentx")?;
    let result = value
        .get("result")
        .and_then(Value::as_array)
        .context("Etherscan tokentx returned non-array result")?;

    let wanted = limit.max(1) as usize;
    let mut seen = BTreeSet::new();
    let mut holders = Vec::new();

    for item in result {
        for key in ["to", "from"] {
            let Some(candidate) = item.get(key).and_then(Value::as_str) else {
                continue;
            };
            let candidate = candidate.trim().to_ascii_lowercase();
            if candidate.len() != 42 || !candidate.starts_with("0x") {
                continue;
            }
            if seen.insert(candidate.clone()) {
                holders.push(candidate);
                if holders.len() >= wanted.saturating_mul(3) {
                    return Ok(holders);
                }
            }
        }
    }

    Ok(holders)
}

fn ensure_v2_success(value: &Value, action: &str) -> Result<()> {
    if value.get("status").and_then(Value::as_str) == Some("1") {
        return Ok(());
    }

    let message = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("unknown Etherscan error");
    let result = value
        .get("result")
        .map(|result| result.to_string())
        .unwrap_or_else(|| "null".to_string());
    bail!("Etherscan {action} failed: {message}; result={result}");
}

pub async fn fetch_source(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
) -> Result<EtherscanContract> {
    let url = format!(
        "https://api.etherscan.io/v2/api?chainid={}&module=contract&action=getsourcecode&address={}&apikey={}",
        chain_id, address, api_key
    );

    let response = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<EtherscanResponse>()
        .await?;

    if response.status != "1" && response.result.is_empty() {
        bail!(
            "Etherscan getsourcecode failed: status={}, message={}",
            response.status,
            response.message
        );
    }

    let mut contract = response
        .result
        .into_iter()
        .next()
        .context("Etherscan returned no contract result")?;

    contract.source_origin = "etherscan_v2".to_string();
    contract.source_url = explorer_url(chain_id, address);
    contract.source_files = normalize_source_files(&contract.source_code, &contract.contract_name);
    Ok(contract)
}

/// Robinhood Chain source loader.
///
/// Prefer Etherscan V2 when an API key exists. If it is unavailable or fails,
/// scrape the server-rendered RobinScan code tab so source scanning still works
/// without relying on the old assumption that Robinhood has no Etherscan explorer.
pub async fn fetch_robinhood_source(
    http: &Client,
    address: &str,
    api_key: Option<&str>,
) -> Result<EtherscanContract> {
    let mut api_error = None;

    if let Some(api_key) = api_key.filter(|value| !value.trim().is_empty()) {
        match fetch_source(http, "4663", address, api_key).await {
            Ok(contract) => return Ok(contract),
            Err(error) => api_error = Some(error.to_string()),
        }
    }

    match fetch_robinhood_source_page(http, address).await {
        Ok(contract) => Ok(contract),
        Err(html_error) => {
            if let Some(api_error) = api_error {
                bail!(
                    "Robinhood source lookup failed: Etherscan V2: {api_error}; RobinScan HTML fallback: {html_error}"
                );
            }
            bail!("Robinhood source lookup failed: RobinScan HTML fallback: {html_error}");
        }
    }
}

fn explorer_url(chain_id: &str, address: &str) -> String {
    if chain_id == "4663" {
        format!("https://robin.etherscan.io/token/{address}#code")
    } else {
        format!("https://etherscan.io/address/{address}#code")
    }
}

async fn fetch_robinhood_source_page(http: &Client, address: &str) -> Result<EtherscanContract> {
    let token_url = format!("https://robin.etherscan.io/token/{address}");
    let address_url = format!("https://robin.etherscan.io/address/{address}");

    let token_result = match fetch_explorer_html(http, &token_url).await {
        Ok(html) => parse_robinhood_source_html(&html, &token_url),
        Err(error) => Err(error),
    };

    let token_error = match token_result {
        Ok(contract) => return Ok(contract),
        Err(error) => error,
    };

    let address_result = match fetch_explorer_html(http, &address_url).await {
        Ok(html) => parse_robinhood_source_html(&html, &address_url),
        Err(error) => Err(error),
    };

    match address_result {
        Ok(contract) => Ok(contract),
        Err(address_error) => bail!(
            "token page failed ({token_error}); address page failed ({address_error})"
        ),
    }
}

fn parse_robinhood_source_html(html: &str, loaded_url: &str) -> Result<EtherscanContract> {
    if !html_contains_source(html) {
        bail!("page does not advertise verified contract source");
    }

    let source_files = extract_html_source_files(html)?;
    let contract_name = extract_labeled_value(html, "Contract Name")
        .or_else(|| source_files.first().and_then(|file| contract_name_from_file(&file.name)))
        .unwrap_or_else(|| "UnknownContract".to_string());
    let compiler_version = extract_labeled_value(html, "Compiler Version").unwrap_or_default();
    let source_code = source_files
        .iter()
        .map(|file| file.content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");

    if source_code.trim().is_empty() {
        bail!("RobinScan page did not contain verified source code");
    }

    Ok(EtherscanContract {
        source_code,
        abi: String::new(),
        contract_name,
        compiler_version,
        proxy: "0".to_string(),
        implementation: String::new(),
        similar_match: String::new(),
        source_files,
        source_origin: "robinscan_html".to_string(),
        source_url: format!("{loaded_url}#code"),
    })
}

async fn fetch_explorer_html(http: &Client, url: &str) -> Result<String> {
    let response = http
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/149 Safari/537.36",
        )
        .header(
            reqwest::header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!("HTTP {status} from {url}");
    }
    Ok(body)
}

fn html_contains_source(html: &str) -> bool {
    let lower = html.to_ascii_lowercase();
    lower.contains("contract source code verified")
        || lower.contains("js-sourcecopyarea")
        || lower.contains("id=\"editor1\"")
        || lower.contains("id='editor1'")
}

fn extract_html_source_files(html: &str) -> Result<Vec<EtherscanSourceFile>> {
    let pre_re = Regex::new(
        r#"(?is)<pre[^>]*(?:id=["']editor\d+["']|class=["'][^"']*js-sourcecopyarea[^"']*["'])[^>]*>(.*?)</pre>"#,
    )?;

    let mut contents = Vec::new();
    for captures in pre_re.captures_iter(html) {
        let Some(content) = captures.get(1) else {
            continue;
        };
        let decoded = decode_html_entities(content.as_str());
        if !decoded.trim().is_empty() {
            contents.push(decoded);
        }
    }

    if contents.is_empty() {
        bail!("no source editor blocks found on RobinScan page");
    }

    let page_text = html_to_text(html);
    let file_re = Regex::new(r"(?i)File\s+\d+\s+of\s+\d+\s*:\s*([^\r\n]+)")?;
    let mut file_names = file_re
        .captures_iter(&page_text)
        .filter_map(|captures| captures.get(1))
        .map(|value| clean_file_name(value.as_str()))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    file_names.dedup();

    let contract_name = extract_labeled_value(html, "Contract Name")
        .unwrap_or_else(|| "Contract".to_string());

    Ok(contents
        .into_iter()
        .enumerate()
        .map(|(index, content)| EtherscanSourceFile {
            name: file_names.get(index).cloned().unwrap_or_else(|| {
                if index == 0 {
                    format!("{contract_name}.sol")
                } else {
                    format!("source_{}.sol", index + 1)
                }
            }),
            content,
        })
        .collect())
}

fn extract_labeled_value(html: &str, label: &str) -> Option<String> {
    let text = html_to_text(html);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(label) {
            let value = rest.trim_start_matches(':').trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    let escaped = regex::escape(label);
    let pattern = format!(r"(?i){}\s*:\s*([^\r\n]+)", escaped);
    let re = Regex::new(&pattern).ok()?;
    re.captures(&text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

fn html_to_text(html: &str) -> String {
    let block_re = Regex::new(r"(?i)</?(?:br|div|p|pre|li|tr|td|th|h[1-6])\b[^>]*>")
        .expect("valid block tag regex");
    let with_lines = block_re.replace_all(html, "\n");
    let tag_re = Regex::new(r"(?is)<[^>]+>").expect("valid tag regex");
    let no_tags = tag_re.replace_all(&with_lines, "");
    decode_html_entities(&no_tags)
}

fn decode_html_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn clean_file_name(value: &str) -> String {
    value
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .trim_matches(|ch: char| ch == '`' || ch == '\'' || ch == '"')
        .to_string()
}

fn contract_name_from_file(name: &str) -> Option<String> {
    let base = name.rsplit('/').next()?.rsplit('\\').next()?;
    let value = base.strip_suffix(".sol").unwrap_or(base).trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn normalize_source_files(source_code: &str, contract_name: &str) -> Vec<EtherscanSourceFile> {
    let trimmed = source_code.trim();
    if trimmed.is_empty() || trimmed == "Contract source code not verified" {
        return Vec::new();
    }

    let json_candidate = if trimmed.starts_with("{{") && trimmed.ends_with("}}") && trimmed.len() >= 4 {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };

    if let Ok(value) = serde_json::from_str::<Value>(json_candidate) {
        if let Some(files) = source_files_from_json(&value) {
            if !files.is_empty() {
                return files;
            }
        }
    }

    let name = if contract_name.trim().is_empty() {
        "Contract.sol".to_string()
    } else if contract_name.ends_with(".sol") {
        contract_name.to_string()
    } else {
        format!("{contract_name}.sol")
    };

    vec![EtherscanSourceFile {
        name,
        content: source_code.to_string(),
    }]
}

fn source_files_from_json(value: &Value) -> Option<Vec<EtherscanSourceFile>> {
    let sources = value.get("sources").and_then(Value::as_object).or_else(|| {
        value.as_object().filter(|object| {
            object.values().any(|entry| {
                entry
                    .get("content")
                    .and_then(Value::as_str)
                    .is_some()
            })
        })
    })?;

    let files = sources
        .iter()
        .filter_map(|(name, entry)| {
            let content = entry
                .get("content")
                .and_then(Value::as_str)
                .or_else(|| entry.as_str())?;
            Some(EtherscanSourceFile {
                name: name.clone(),
                content: content.to_string(),
            })
        })
        .collect::<Vec<_>>();

    Some(files)
}
