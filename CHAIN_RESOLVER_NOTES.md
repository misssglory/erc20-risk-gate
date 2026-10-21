# Chain Resolver Notes

The resolver accepts:

- `ethereum`, `eth`, `mainnet`, `1`
- `base`, `base-mainnet`, `8453`
- `bsc`, `bnb`, `binance-smart-chain`, `56`
- `robinhood`, `hood`, `rh`, `robinhood-chain`, `4663`

Provider mapping:

| Chain | EVM / GoPlus | DexScreener | Native gate |
|---|---:|---|---|
| Ethereum | `1` | `ethereum` | — |
| Base | `8453` | `base` | — |
| BSC | `56` | `bsc` | — |
| Robinhood Chain | `4663` | `robinhood` | RPC + Etherscan V2 honeypot gate |

For Robinhood Chain, TokenSniffer and Honeypot.is are intentionally not used by the scan path. The native gate uses Etherscan V2 for deployer/source/holder discovery and the configured Robinhood RPC only for direct EVM reads and holder transfer simulation. GoPlus and DexScreener remain supplemental providers.
