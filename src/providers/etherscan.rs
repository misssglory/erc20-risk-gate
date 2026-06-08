use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};

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

    response
        .result
        .into_iter()
        .next()
        .context("Etherscan returned no contract result")
}