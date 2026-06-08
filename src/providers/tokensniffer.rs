use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub async fn fetch(
    http: &Client,
    chain_id: &str,
    address: &str,
    api_key: &str,
) -> Result<Value> {
    let url = format!(
        "https://tokensniffer.com/api/v2/tokens/{}/{}?include_metrics=true&include_tests=true&include_similar=true&block_until_ready=true",
        chain_id, address
    );

    let value = http
        .get(url)
        .header("X-API-Key", api_key)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    Ok(value)
}