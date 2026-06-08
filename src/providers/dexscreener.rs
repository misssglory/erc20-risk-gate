use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub async fn fetch_token_pairs(http: &Client, chain_id: &str, address: &str) -> Result<Value> {
    let url = format!(
        "https://api.dexscreener.com/token-pairs/v1/{}/{}",
        chain_id, address
    );

    let value = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    Ok(value)
}