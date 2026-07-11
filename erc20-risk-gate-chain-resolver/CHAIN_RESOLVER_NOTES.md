# Chain Resolver Notes

This ZIP includes a chain resolver layer for friendly chain selectors:

- `ethereum`, `eth`, `mainnet`, `1`
- `base`, `base-mainnet`, `8453`
- `bsc`, `bnb`, `binance-smart-chain`, `56`

The resolver maps each selector into provider-specific formats:

| Chain | EVM / GoPlus / Honeypot / Etherscan / TokenSniffer | DexScreener |
|---|---:|---|
| Ethereum | `1` | `ethereum` |
| Base | `8453` | `base` |
| BSC | `56` | `bsc` |

The `config.toml` API key fields are intentionally blank in this ZIP. Put your own keys back locally.
