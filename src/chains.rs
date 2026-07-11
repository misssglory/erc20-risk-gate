use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct ResolvedChain {
    pub input: String,
    pub canonical: &'static str,
    pub evm_chain_id: &'static str,
    pub tokensniffer_chain_id: &'static str,
    pub goplus_chain_id: &'static str,
    pub honeypot_chain_id: &'static str,
    pub etherscan_chain_id: &'static str,
    pub dexscreener_chain_id: &'static str,
}

impl ResolvedChain {
    pub fn resolve(input: impl AsRef<str>) -> Result<Self> {
        let raw = input.as_ref().trim();

        if raw.is_empty() {
            bail!("empty chain; supported chains: {}", Self::supported_names());
        }

        let key = raw.to_ascii_lowercase().replace(['_', '-', ' '], "");

        match key.as_str() {
            "1" | "eth" | "ethereum" | "mainnet" | "ethmainnet" => {
                Ok(Self::new(raw, "ethereum", "1", "ethereum"))
            }

            "8453" | "base" | "basemainnet" => {
                Ok(Self::new(raw, "base", "8453", "base"))
            }

            "56" | "bsc" | "bnb" | "binance" | "binancesmartchain" | "bnbsmartchain" => {
                Ok(Self::new(raw, "bsc", "56", "bsc"))
            }

            _ => bail!(
                "unsupported chain `{}`; supported chains: {}",
                raw,
                Self::supported_names()
            ),
        }
    }

    fn new(
        input: &str,
        canonical: &'static str,
        evm_chain_id: &'static str,
        dexscreener_chain_id: &'static str,
    ) -> Self {
        Self {
            input: input.to_string(),
            canonical,
            evm_chain_id,
            tokensniffer_chain_id: evm_chain_id,
            goplus_chain_id: evm_chain_id,
            honeypot_chain_id: evm_chain_id,
            etherscan_chain_id: evm_chain_id,
            dexscreener_chain_id,
        }
    }

    pub fn supported_names() -> &'static str {
        "ethereum/eth/1, base/8453, bsc/bnb/56"
    }
}
