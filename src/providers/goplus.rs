use anyhow::Result;
use reqwest::Client;
use serde_json::Value;

pub async fn fetch(
    http: &Client,
    chain_id: &str,
    address: &str,
    bearer_token: Option<&str>,
) -> Result<Value> {
    let url = format!(
        "https://api.gopluslabs.io/api/v1/token_security/{}?contract_addresses={}",
        chain_id, address
    );

    let mut request = http.get(url);

    if let Some(token) = bearer_token {
        let token = token.trim();
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
    }

    let value = request
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    Ok(value)
}