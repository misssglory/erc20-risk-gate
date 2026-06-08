use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub async fn fetch(http: &Client, chain_id: &str, address: &str) -> Result<Value> {
    let url = format!(
        "https://api.honeypot.is/v2/IsHoneypot?address={}&chainID={}",
        address, chain_id
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