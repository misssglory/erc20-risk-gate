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
| Robinhood Chain | `4663` | `robinhood` | RPC + Blockscout honeypot gate |

For Robinhood Chain, TokenSniffer, Honeypot.is and Etherscan are intentionally not used by the scan path. The native gate uses the configured Robinhood RPC and Blockscout endpoints, while GoPlus and DexScreener remain supplemental providers.
