use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const OWNER_SELECTOR: &str = "0x8da5cb5b";
const DECIMALS_SELECTOR: &str = "0x313ce567";
const BALANCE_OF_SELECTOR: &str = "70a08231";
const TRANSFER_SELECTOR: &str = "a9059cbb";
const BLOCKED_SELL_TEXT: &str = "Blocked: cannot sell.";
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize)]
pub struct RobinhoodRiskResult {
    pub bytecode_bytes: usize,
    pub blocked_sell_signature: bool,
    pub blocked_sell_signature_shift: Option<u8>,
    pub decimals: Option<u8>,
    pub deployer: Option<String>,
    pub owner: Option<String>,
    pub owner_equals_deployer: Option<bool>,
    pub ownership_retained: bool,
    pub template_shape_match: bool,
    pub holder_transfer_test: Option<HolderTransferTest>,
    pub known_bad_deployer: bool,
    pub known_bad_owner: bool,
    pub diagnostics: Vec<String>,
}

impl RobinhoodRiskResult {
    pub fn direct_honeypot_evidence(&self) -> bool {
        if self.blocked_sell_signature {
            return true;
        }

        self.holder_transfer_test
            .as_ref()
            .map(|test| matches!(test.outcome.as_str(), "reverted" | "returned_false"))
            .unwrap_or(false)
    }

    pub fn direct_evidence_reason(&self) -> Option<String> {
        if let Some(shift) = self.blocked_sell_signature_shift {
            return Some(format!("blocked_sell_bytecode_signature_shift_{shift}"));
        }

        let test = self.holder_transfer_test.as_ref()?;
        match test.outcome.as_str() {
            "reverted" => Some(match test.revert_reason.as_deref() {
                Some(reason) if !reason.trim().is_empty() => {
                    format!("holder_transfer_reverted: {reason}")
                }
                _ => "holder_transfer_reverted".to_string(),
            }),
            "returned_false" => Some("holder_transfer_returned_false".to_string()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HolderTransferTest {
    pub holder: String,
    pub target: String,
    pub balance_raw: String,
    pub amount_raw: String,
    pub outcome: String,
    pub revert_reason: Option<String>,
    pub revert_data: Option<String>,
    pub blocked_sell_message: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BadActorStore {
    #[serde(default)]
    pub bad_deployers: BTreeSet<String>,
    #[serde(default)]
    pub bad_owners: BTreeSet<String>,
    #[serde(default)]
    pub flagged_tokens: Vec<FlaggedTokenRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlaggedTokenRecord {
    pub token: String,
    pub deployer: Option<String>,
    pub owner: Option<String>,
    pub reason: String,
    pub first_seen_unix: u64,
}

impl BadActorStore {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read Robinhood bad-actor DB: {}", path.display()))?;

        let mut store: Self = serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse Robinhood bad-actor DB: {}", path.display()))?;
        store.normalize();
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create bad-actor DB directory: {}", parent.display())
                })?;
            }
        }

        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)
            .with_context(|| format!("failed to write Robinhood bad-actor DB: {}", tmp.display()))?;
        fs::rename(&tmp, path)
            .with_context(|| format!("failed to replace Robinhood bad-actor DB: {}", path.display()))?;
        Ok(())
    }

    pub fn seed(&mut self, deployers: &[String], owners: &[String]) {
        for address in deployers {
            if let Some(address) = normalize_address(address) {
                self.bad_deployers.insert(address);
            }
        }
        for address in owners {
            if let Some(address) = normalize_address(address) {
                self.bad_owners.insert(address);
            }
        }
    }

    pub fn is_bad_deployer(&self, address: Option<&str>) -> bool {
        address
            .and_then(normalize_address)
            .map(|address| self.bad_deployers.contains(&address))
            .unwrap_or(false)
    }

    pub fn is_bad_owner(&self, address: Option<&str>) -> bool {
        address
            .and_then(normalize_address)
            .map(|address| self.bad_owners.contains(&address))
            .unwrap_or(false)
    }

    pub fn record_direct_evidence(
        &mut self,
        token: &str,
        deployer: Option<&str>,
        owner: Option<&str>,
        reason: String,
    ) -> bool {
        let token = normalize_address(token).unwrap_or_else(|| token.to_ascii_lowercase());
        let deployer = deployer.and_then(normalize_address);
        let owner = owner.and_then(normalize_address);
        let mut changed = false;

        if let Some(address) = deployer.as_ref() {
            if self.bad_deployers.insert(address.clone()) {
                changed = true;
            }
        }

        if let Some(address) = owner.as_ref() {
            if address.as_str() != ZERO_ADDRESS && self.bad_owners.insert(address.clone()) {
                changed = true;
            }
        }

        if !self.flagged_tokens.iter().any(|item| item.token == token) {
            self.flagged_tokens.push(FlaggedTokenRecord {
                token,
                deployer,
                owner,
                reason,
                first_seen_unix: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });
            changed = true;
        }

        changed
    }

    fn normalize(&mut self) {
        self.bad_deployers = self
            .bad_deployers
            .iter()
            .filter_map(|address| normalize_address(address))
            .collect();
        self.bad_owners = self
            .bad_owners
            .iter()
            .filter_map(|address| normalize_address(address))
            .collect();

        for item in &mut self.flagged_tokens {
            item.token = normalize_address(&item.token).unwrap_or_else(|| item.token.to_ascii_lowercase());
            item.deployer = item.deployer.as_deref().and_then(normalize_address);
            item.owner = item.owner.as_deref().and_then(normalize_address);
        }
    }
}

pub async fn fetch(
    http: &Client,
    rpc_url: &str,
    blockscout_url: &str,
    address: &str,
    holders_limit: u32,
    transfer_amount_divisor: u32,
    transfer_target: &str,
    template_min_bytecode_bytes: usize,
    template_max_bytecode_bytes: usize,
) -> Result<RobinhoodRiskResult> {
    let address = normalize_address(address).context("invalid Robinhood token address")?;
    let target = normalize_address(transfer_target).context("invalid Robinhood transfer target")?;
    let mut diagnostics = Vec::new();

    let code_hex = rpc_result(
        http,
        rpc_url,
        "eth_getCode",
        json!([address.clone(), "latest"]),
    )
    .await?
    .as_str()
    .context("eth_getCode returned non-string result")?
    .to_string();

    let bytecode = decode_hex(&code_hex).context("invalid runtime bytecode hex")?;
    if bytecode.is_empty() {
        bail!("token address has no runtime bytecode");
    }

    let blocked_sell_signature_shift = find_bit_aligned_ascii(&bytecode, BLOCKED_SELL_TEXT);
    let blocked_sell_signature = blocked_sell_signature_shift.is_some();

    let decimals = match eth_call_data(http, rpc_url, &address, None, DECIMALS_SELECTOR).await {
        Ok(value) => parse_u8_word(&value),
        Err(error) => {
            diagnostics.push(format!("decimals() call failed: {error}"));
            None
        }
    };

    let owner = match eth_call_data(http, rpc_url, &address, None, OWNER_SELECTOR).await {
        Ok(value) => parse_address_word(&value),
        Err(error) => {
            diagnostics.push(format!("owner() call unavailable: {error}"));
            None
        }
    };

    let deployer = match fetch_deployer(http, blockscout_url, &address).await {
        Ok(value) => value,
        Err(error) => {
            diagnostics.push(format!("Blockscout deployer lookup failed: {error}"));
            None
        }
    };

    let owner_equals_deployer = match (owner.as_deref(), deployer.as_deref()) {
        (Some(owner), Some(deployer)) => Some(owner.eq_ignore_ascii_case(deployer)),
        _ => None,
    };

    let ownership_retained = owner
        .as_deref()
        .map(|owner| !owner.eq_ignore_ascii_case(ZERO_ADDRESS))
        .unwrap_or(false);

    let template_shape_match = bytecode.len() >= template_min_bytecode_bytes
        && bytecode.len() <= template_max_bytecode_bytes
        && decimals == Some(9)
        && ownership_retained
        && owner_equals_deployer.unwrap_or(false);

    let holder_transfer_test = match fetch_holders(http, blockscout_url, &address, holders_limit).await {
        Ok(holders) => match select_real_holder(
            http,
            rpc_url,
            &address,
            holders,
            deployer.as_deref(),
            owner.as_deref(),
        )
        .await
        {
            Ok(Some((holder, balance))) => {
                let amount = divide_be(&balance, transfer_amount_divisor.max(1));
                let amount = if is_zero_bytes(&amount) { vec![1] } else { amount };
                match simulate_transfer(http, rpc_url, &address, &holder, &target, &balance, &amount).await {
                    Ok(test) => Some(test),
                    Err(error) => {
                        diagnostics.push(format!("holder transfer simulation failed: {error}"));
                        None
                    }
                }
            }
            Ok(None) => {
                diagnostics.push(format!(
                    "no non-contract holder with a positive on-chain balance found in top {holders_limit} holders"
                ));
                None
            }
            Err(error) => {
                diagnostics.push(format!("holder selection failed: {error}"));
                None
            }
        },
        Err(error) => {
            diagnostics.push(format!("Blockscout holder lookup failed: {error}"));
            None
        }
    };

    Ok(RobinhoodRiskResult {
        bytecode_bytes: bytecode.len(),
        blocked_sell_signature,
        blocked_sell_signature_shift,
        decimals,
        deployer,
        owner,
        owner_equals_deployer,
        ownership_retained,
        template_shape_match,
        holder_transfer_test,
        known_bad_deployer: false,
        known_bad_owner: false,
        diagnostics,
    })
}

async fn fetch_deployer(http: &Client, blockscout_url: &str, address: &str) -> Result<Option<String>> {
    let url = format!(
        "{}/api/v2/addresses/{}",
        blockscout_url.trim_end_matches('/'),
        address
    );
    let value = http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    Ok(value
        .get("creator_address_hash")
        .and_then(Value::as_str)
        .and_then(normalize_address))
}

async fn fetch_holders(
    http: &Client,
    blockscout_url: &str,
    address: &str,
    limit: u32,
) -> Result<Vec<String>> {
    let url = format!("{}/api", blockscout_url.trim_end_matches('/'));
    let limit_string = limit.max(1).to_string();
    let value = http
        .get(url)
        .query(&[
            ("module", "token"),
            ("action", "getTokenHolders"),
            ("contractaddress", address),
            ("page", "1"),
            ("offset", limit_string.as_str()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?;

    let result = value
        .get("result")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("unexpected getTokenHolders response: {value}"))?;

    Ok(result
        .iter()
        .filter_map(|item| item.get("address").and_then(Value::as_str))
        .filter_map(normalize_address)
        .collect())
}

async fn select_real_holder(
    http: &Client,
    rpc_url: &str,
    token: &str,
    holders: Vec<String>,
    deployer: Option<&str>,
    owner: Option<&str>,
) -> Result<Option<(String, Vec<u8>)>> {
    for holder in holders {
        if holder.eq_ignore_ascii_case(ZERO_ADDRESS)
            || deployer.map(|v| holder.eq_ignore_ascii_case(v)).unwrap_or(false)
            || owner.map(|v| holder.eq_ignore_ascii_case(v)).unwrap_or(false)
        {
            continue;
        }

        let code = rpc_result(http, rpc_url, "eth_getCode", json!([holder.clone(), "latest"])).await?;
        let code = code.as_str().unwrap_or("0x");
        if code != "0x" && code != "0x0" && !code.trim_start_matches("0x").is_empty() {
            continue;
        }

        let holder_word = padded_address_word(&holder)?;
        let data = format!("0x{BALANCE_OF_SELECTOR}{holder_word}");
        let balance_hex = eth_call_data(http, rpc_url, token, None, &data).await?;
        let balance = decode_hex(&balance_hex)?;
        if !is_zero_bytes(&balance) {
            return Ok(Some((holder, trim_leading_zeros(balance))));
        }
    }

    Ok(None)
}

async fn simulate_transfer(
    http: &Client,
    rpc_url: &str,
    token: &str,
    holder: &str,
    target: &str,
    balance: &[u8],
    amount: &[u8],
) -> Result<HolderTransferTest> {
    let target_word = padded_address_word(target)?;
    let amount_word = padded_u256_word(amount)?;
    let data = format!("0x{TRANSFER_SELECTOR}{target_word}{amount_word}");
    let params = json!([{
        "from": holder,
        "to": token,
        "data": data
    }, "latest"]);

    let envelope = rpc_raw(http, rpc_url, "eth_call", params).await?;

    if let Some(error) = envelope.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("RPC eth_call error")
            .to_string();
        let revert_data = find_hex_error_data(error);
        let decoded = revert_data.as_deref().and_then(decode_revert_reason);
        let reason = decoded.clone().or_else(|| Some(message.clone()));
        let message_lc = message.to_ascii_lowercase();
        let rpc_code = error.get("code").and_then(Value::as_i64);
        let is_revert = rpc_code == Some(3)
            || message_lc.contains("revert")
            || message_lc.contains("execution reverted");

        if !is_revert {
            bail!("eth_call RPC error: {message}");
        }

        let blocked_sell_message = reason
            .as_deref()
            .map(|value| value.to_ascii_lowercase().contains("blocked: cannot sell"))
            .unwrap_or(false);

        return Ok(HolderTransferTest {
            holder: holder.to_string(),
            target: target.to_string(),
            balance_raw: format_u256_hex(balance),
            amount_raw: format_u256_hex(amount),
            outcome: "reverted".to_string(),
            revert_reason: reason,
            revert_data,
            blocked_sell_message,
        });
    }

    let result = envelope
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("0x");
    let returned_false = result.len() >= 66
        && decode_hex(result)
            .map(|bytes| is_zero_bytes(&bytes))
            .unwrap_or(false);

    Ok(HolderTransferTest {
        holder: holder.to_string(),
        target: target.to_string(),
        balance_raw: format_u256_hex(balance),
        amount_raw: format_u256_hex(amount),
        outcome: if returned_false {
            "returned_false".to_string()
        } else {
            "success".to_string()
        },
        revert_reason: None,
        revert_data: None,
        blocked_sell_message: false,
    })
}

async fn eth_call_data(
    http: &Client,
    rpc_url: &str,
    to: &str,
    from: Option<&str>,
    data: &str,
) -> Result<String> {
    let mut call = json!({"to": to, "data": data});
    if let Some(from) = from {
        call["from"] = Value::String(from.to_string());
    }

    let value = rpc_result(http, rpc_url, "eth_call", json!([call, "latest"])).await?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .context("eth_call returned non-string result")
}

async fn rpc_result(http: &Client, rpc_url: &str, method: &str, params: Value) -> Result<Value> {
    let value = rpc_raw(http, rpc_url, method, params).await?;
    if let Some(error) = value.get("error") {
        bail!("RPC {method} error: {error}");
    }
    value
        .get("result")
        .cloned()
        .with_context(|| format!("RPC {method} response missing result"))
}

async fn rpc_raw(http: &Client, rpc_url: &str, method: &str, params: Value) -> Result<Value> {
    Ok(http
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<Value>()
        .await?)
}

fn find_bit_aligned_ascii(bytecode: &[u8], needle: &str) -> Option<u8> {
    let needle = needle.as_bytes();
    for shift in 0u8..=7 {
        if shift == 0 {
            if contains_bytes(bytecode, needle) {
                return Some(0);
            }
            continue;
        }

        let view: Vec<u8> = bytecode
            .windows(2)
            .map(|window| {
                (window[0] << shift) | (window[1] >> (8 - shift))
            })
            .collect();
        if contains_bytes(&view, needle) {
            return Some(shift);
        }
    }
    None
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn decode_revert_reason(data: &str) -> Option<String> {
    let bytes = decode_hex(data).ok()?;
    if bytes.len() < 4 || bytes[..4] != [0x08, 0xc3, 0x79, 0xa0] {
        return printable_tail(&bytes);
    }
    if bytes.len() < 4 + 32 + 32 {
        return None;
    }

    let len_word = &bytes[4 + 32..4 + 64];
    let len = u256_word_to_usize(len_word)?;
    let start: usize = 4 + 64;
    let end = start.checked_add(len)?;
    if end > bytes.len() {
        return None;
    }
    String::from_utf8(bytes[start..end].to_vec()).ok()
}

fn printable_tail(bytes: &[u8]) -> Option<String> {
    let mut best = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if (0x20..=0x7e).contains(byte) {
            current.push(*byte);
            if current.len() > best.len() {
                best = current.clone();
            }
        } else {
            current.clear();
        }
    }
    if best.len() >= 4 {
        String::from_utf8(best).ok()
    } else {
        None
    }
}

fn find_hex_error_data(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if text.starts_with("0x") && text.len() >= 10 => Some(text.clone()),
        Value::Array(items) => items.iter().find_map(find_hex_error_data),
        Value::Object(map) => {
            if let Some(data) = map.get("data").and_then(find_hex_error_data) {
                return Some(data);
            }
            map.values().find_map(find_hex_error_data)
        }
        _ => None,
    }
}

fn parse_u8_word(value: &str) -> Option<u8> {
    let bytes = decode_hex(value).ok()?;
    let last = *bytes.last()?;
    if bytes[..bytes.len().saturating_sub(1)].iter().all(|byte| *byte == 0) {
        Some(last)
    } else {
        None
    }
}

fn parse_address_word(value: &str) -> Option<String> {
    let bytes = decode_hex(value).ok()?;
    if bytes.len() < 20 {
        return None;
    }
    let address = &bytes[bytes.len() - 20..];
    Some(format!("0x{}", encode_hex(address)))
}

fn normalize_address(address: &str) -> Option<String> {
    let trimmed = address.trim();
    let raw = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if raw.len() != 40 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!("0x{}", raw.to_ascii_lowercase()))
}

fn padded_address_word(address: &str) -> Result<String> {
    let address = normalize_address(address).context("invalid address")?;
    Ok(format!("{:0>64}", address.trim_start_matches("0x")))
}

fn padded_u256_word(bytes: &[u8]) -> Result<String> {
    if bytes.len() > 32 {
        bail!("uint256 value exceeds 32 bytes");
    }
    Ok(format!("{:0>64}", encode_hex(bytes)))
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.len() % 2 != 0 {
        return decode_hex(&format!("0{raw}"));
    }

    (0..raw.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&raw[index..index + 2], 16)
                .map_err(|error| anyhow!("invalid hex at byte {}: {error}", index / 2))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn divide_be(bytes: &[u8], divisor: u32) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len());
    let mut remainder: u32 = 0;
    for byte in bytes {
        let current = (remainder << 8) | (*byte as u32);
        output.push((current / divisor) as u8);
        remainder = current % divisor;
    }
    trim_leading_zeros(output)
}

fn trim_leading_zeros(bytes: Vec<u8>) -> Vec<u8> {
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    if first == bytes.len() {
        vec![0]
    } else {
        bytes[first..].to_vec()
    }
}

fn is_zero_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn format_u256_hex(bytes: &[u8]) -> String {
    let trimmed = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    if trimmed == bytes.len() {
        "0x0".to_string()
    } else {
        format!("0x{}", encode_hex(&bytes[trimmed..]))
    }
}

fn u256_word_to_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.len() != 32 {
        return None;
    }
    let usize_len = std::mem::size_of::<usize>();
    if bytes[..32 - usize_len].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut output = 0usize;
    for byte in &bytes[32 - usize_len..] {
        output = (output << 8) | (*byte as usize);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix_bits(data: &[u8], prefix_bits: u8) -> Vec<u8> {
        assert!(prefix_bits < 8);
        if prefix_bits == 0 {
            return data.to_vec();
        }
        let mut out = vec![0u8; data.len() + 1];
        for (index, byte) in data.iter().enumerate() {
            out[index] |= byte >> prefix_bits;
            out[index + 1] |= byte << (8 - prefix_bits);
        }
        out
    }

    #[test]
    fn finds_plain_and_bit_aligned_blocked_sell_string() {
        let plain = format!("xxxx{BLOCKED_SELL_TEXT}yyyy").into_bytes();
        assert_eq!(find_bit_aligned_ascii(&plain, BLOCKED_SELL_TEXT), Some(0));

        for prefix in 1..=7 {
            let shifted = prefix_bits(&plain, prefix);
            assert_eq!(
                find_bit_aligned_ascii(&shifted, BLOCKED_SELL_TEXT),
                Some(prefix)
            );
        }
    }

    #[test]
    fn decodes_standard_error_string() {
        let reason = "Blocked: cannot sell.";
        let mut bytes = vec![0x08, 0xc3, 0x79, 0xa0];
        bytes.extend([0u8; 31]);
        bytes.push(0x20);
        bytes.extend([0u8; 31]);
        bytes.push(reason.len() as u8);
        bytes.extend(reason.as_bytes());
        while bytes.len() % 32 != 4 {
            bytes.push(0);
        }
        let data = format!("0x{}", encode_hex(&bytes));
        assert_eq!(decode_revert_reason(&data).as_deref(), Some(reason));
    }

    #[test]
    fn divides_big_endian_u256_without_bigint_dependency() {
        assert_eq!(divide_be(&[0x03, 0xe8], 100), vec![0x0a]);
        assert_eq!(divide_be(&[0x01], 100), vec![0]);
    }
}
