# ERC20 Risk Gate

A modular Rust command-line scanner for ERC-20 token risk analysis.

It fetches token security data from multiple providers, applies configurable hard-block and scoring rules, and returns a machine-readable JSON decision:

* `buy_allowed`
* `manual_review`
* `skip`

The project is designed as a **pre-trade risk gate** for trading bots, snipers, dashboards, or manual token research.

> This tool does not guarantee that a token is safe. It is a defensive filter. Treat every new ERC-20 token as hostile until proven otherwise.

---

## Features

* Modular Rust architecture
* `config.toml` configuration
* Optional API keys
* Skips provider checks when API keys are missing
* JSON output for automation
* Logs via `tracing-subscriber`
* TokenSniffer integration
* GoPlus Security integration
* Honeypot.is integration
* Etherscan source-code lookup
* DexScreener liquidity check
* Native Robinhood Chain (4663) honeypot gate
* Bit-aligned runtime-bytecode fingerprinting (shifts 0 through 7)
* Real-holder `eth_call` transfer simulation through the Uniswap v4 PoolManager
* Persistent bad-deployer / bad-owner memory for confirmed Robinhood honeypots
* Basic Solidity source-code pattern scanner
* Nix flake support
* NixOS system-wide installation support

---

## Decision model

The scanner returns one of three decisions.

### `buy_allowed`

Returned when:

* no hard blockers are found
* risk score is above the configured buy threshold
* token passes available scanner checks

### `manual_review`

Returned when:

* no hard blockers are found
* score is below the buy threshold
* some warnings exist
* some providers are unavailable or skipped

### `skip`

Returned when at least one hard blocker is found.

Examples of hard blockers:

* Robinhood blocked-sell bytecode signature detected
* Robinhood real-holder transfer reverts or returns `false`
* Robinhood deployer/owner matches the local confirmed bad-actor database
* honeypot detected
* sell simulation failed
* sell tax too high
* blacklist detected
* whitelist trading restriction detected
* owner can change balances
* TokenSniffer scam/rugpull flag
* source code is unverified when `skip_unverified_source = true`

---

## Project structure

```text
erc20-risk-gate/
  Cargo.toml
  Cargo.lock
  config.toml
  flake.nix
  src/
    main.rs
    chains.rs
    config.rs
    models.rs
    providers/
      mod.rs
      tokensniffer.rs
      goplus.rs
      honeypot.rs
      etherscan.rs
      dexscreener.rs
      robinhood.rs
    analysis/
      mod.rs
      rules.rs
      source_scan.rs
      value_ext.rs
```

---

## Installation

### Build with Cargo

```bash
cargo build --release
```

Run:

```bash
./target/release/erc20-risk-gate --help
```

---

## Configuration

Create a `config.toml` file in the project root.

```toml
# Accepts: ethereum/eth/1, base/8453, bsc/bnb/56, robinhood/hood/rh/4663
chain_id = "ethereum"

[logging]
level = "info"

[http]
timeout_seconds = 20

[api]
tokensniffer_api_key = ""
etherscan_api_key = ""
goplus_token = ""

[robinhood]
enabled = true
rpc_url = "https://rpc.mainnet.chain.robinhood.com"
blockscout_url = "https://robinhoodchain.blockscout.com"
holders_limit = 50
transfer_amount_divisor = 100
transfer_target = "0x8366a39cc670b4001a1121b8f6a443a643e40951"
template_min_bytecode_bytes = 8192
template_max_bytecode_bytes = 10240
bad_actor_db_path = "robinhood-bad-actors.json"
hard_block_known_bad_actor = true
bad_deployers = []
bad_owners = []

[rules]
min_score_buy = 85
tokensniffer_min_score = 60

sell_tax_warn = 10.0
sell_tax_block = 30.0

buy_tax_warn = 10.0
buy_tax_block = 30.0

skip_unverified_source = true
```

---

## API keys

All API keys are configured through `config.toml`.

### TokenSniffer

If `tokensniffer_api_key` is empty or missing, the TokenSniffer check is skipped.

```toml
[api]
tokensniffer_api_key = "YOUR_TOKENSNIFFER_API_KEY"
```

### Etherscan

If `etherscan_api_key` is empty or missing, the Etherscan source-code check is skipped.

```toml
[api]
etherscan_api_key = "YOUR_ETHERSCAN_API_KEY"
```

### GoPlus

GoPlus may work without a token depending on current API access rules.

```toml
[api]
goplus_token = ""
```

If you have a token:

```toml
[api]
goplus_token = "YOUR_GOPLUS_TOKEN"
```

---

## Supported chains

The scanner accepts friendly names and numeric aliases:

```text
ethereum: ethereum, eth, mainnet, 1
base:     base, base-mainnet, 8453
bsc:      bsc, bnb, binance-smart-chain, 56
robinhood: robinhood, hood, rh, robinhood-chain, 4663
```

Internally, each provider receives the chain format it expects:

```text
ethereum  -> EVM 1    -> DexScreener ethereum
base      -> EVM 8453 -> DexScreener base
bsc       -> EVM 56   -> DexScreener bsc
robinhood -> EVM 4663 -> DexScreener robinhood + native RPC/Blockscout gate
```

---

## Usage

Basic scan:

```bash
cargo run -- \
  --config config.toml \
  scan \
  --address 0xTOKEN_ADDRESS
```

Override chain ID:

```bash
cargo run -- \
  --config config.toml \
  scan \
  --chain-id ethereum \
  --address 0xTOKEN_ADDRESS
```

Pretty JSON:

```bash
cargo run -- \
  --config config.toml \
  scan \
  --chain-id ethereum \
  --address 0xTOKEN_ADDRESS \
  --pretty
```


Robinhood Chain native gate:

```bash
cargo run -- \
  --config config.toml \
  scan \
  --chain-id 4663 \
  --address 0xTOKEN_ADDRESS \
  --pretty
```

For Robinhood Chain, the report includes a `robinhood_risk` object with runtime bytecode size, bit-shift signature match, decimals, deployer, owner, selected real holder, transfer-test outcome and bad-actor matches.

---

Release binary:

```bash
./target/release/erc20-risk-gate \
  --config config.toml \
  scan \
  --chain-id ethereum \
  --address 0xTOKEN_ADDRESS \
  --pretty
```

---

## Example output

```json
{
  "chain_id": "1",
  "token_address": "0xTOKEN_ADDRESS",
  "decision": "manual_review",
  "score": 72,
  "hard_blocks": [],
  "warnings": [
    "TokenSniffer skipped or unavailable",
    "Etherscan source skipped or unavailable",
    "DexScreener: low liquidity: $42000"
  ],
  "skipped_checks": [
    {
      "provider": "tokensniffer",
      "reason": "tokensniffer_api_key is missing"
    },
    {
      "provider": "etherscan",
      "reason": "etherscan_api_key is missing"
    }
  ],
  "provider_errors": [],
  "provider_status": {
    "tokensniffer": "skipped",
    "goplus": "ok",
    "honeypot": "ok",
    "etherscan_source": "skipped",
    "dexscreener": "ok",
    "robinhood": "not_run"
  }
}
```

---

## Logging

Logs are emitted to `stderr`.

JSON result is printed to `stdout`.

This makes the tool safe to pipe into other programs:

```bash
erc20-risk-gate \
  --config config.toml \
  scan \
  --chain-id ethereum \
  --address 0xTOKEN_ADDRESS \
  | jq .
```

Example with debug logs:

```toml
[logging]
level = "debug"
```

Supported examples:

```toml
level = "error"
level = "warn"
level = "info"
level = "debug"
level = "trace"
```

---

## Robinhood Chain native honeypot gate

Robinhood Chain mainnet is chain ID `4663`. When that chain is selected, the scanner runs a native gate that does not depend on a third-party honeypot API:

1. Fetch runtime bytecode with `eth_getCode`.
2. Re-align the byte stream at bit shifts `0..7` and search for `Blocked: cannot sell.`. A match is a hard block even before the storage flag flips.
3. Read `decimals()` and `owner()` and resolve the deployer through Blockscout.
4. Fetch the top token holders from Blockscout, skip the deployer, owner and contract addresses (pools/lockers), then confirm the holder's current balance with `balanceOf`.
5. Simulate `transfer(holder -> PoolManager, amount)` with `eth_call`, using 1% of the holder balance by default. A revert or an ERC-20 `false` return is a hard block.
6. If direct honeypot evidence is found, persist the token's deployer and owner in `robinhood-bad-actors.json`. Future tokens from either actor are hard-blocked before purchase when `hard_block_known_bad_actor = true`.

The 8-10 KB / 9-decimal / retained-owner shape is also reported as a warning. The static blocked-sell signature itself is treated as direct evidence because it survives the pre-flip window.

### Rechecking

A successful transfer simulation is a point-in-time result. The observed Robinhood honeypot family can enable the sell block after buyers arrive. Call `/scan` again for young or held tokens; the static fingerprint catches the known family before the flip, while repeated live simulations catch state changes and unrelated dynamic restrictions. The service intentionally leaves scheduling cadence to the caller/trading system.

### Bad-actor persistence

`bad_actor_db_path` is updated only from **direct evidence** (blocked-sell bytecode signature or a failed real-holder transfer). A token that is blocked only because its deployer was already known bad does not cause unrelated addresses to be learned transitively. You can pre-seed known addresses with `bad_deployers` and `bad_owners` in `config.toml`.

---

## Providers

### Robinhood native gate

Used on chain `4663` for runtime bytecode fingerprinting, deployer/owner attribution, real-holder transfer simulation, and local bad-actor persistence.

### TokenSniffer

Used for:

* scam flags
* rugpull flags
* smell-test score
* sellability
* fee checks
* source/code risk flags
* similar contract information

Skipped if no API key is configured. On Robinhood Chain it is intentionally skipped in favor of the native gate.

### GoPlus Security

Used for:

* honeypot checks
* blacklist checks
* whitelist checks
* mintability
* hidden owner detection
* balance modification risk
* transfer pause risk
* buy/sell tax

### Honeypot.is

Used on supported non-Robinhood chains for:

* honeypot detection
* buy/sell simulation data
* tax simulation

### Etherscan

Used on supported non-Robinhood chains for:

* verified source-code lookup
* proxy detection
* implementation address
* similar contract match
* basic static source scan

Skipped if no API key is configured.

### DexScreener

Used for:

* liquidity discovery
* token pair discovery
* basic liquidity risk warning

---

## Source-code risk scan

The built-in source scanner looks for suspicious Solidity patterns such as:

* blacklist logic
* whitelist logic
* fee/tax setters
* max transaction setters
* max wallet setters
* pause logic
* trading gates
* mint functions
* balance manipulation
* delegatecall
* cooldown logic
* fee exclusion logic

This is not a full static analyzer.

For production-grade analysis, consider adding Slither integration.

---

## Suggested production flow

The safest usage pattern is:

```text
candidate token
  ↓
ERC20 Risk Gate scan
  ↓
skip / manual_review / buy_allowed
  ↓
forked buy + sell simulation
  ↓
tiny first buy
  ↓
immediate test sell
  ↓
only then real position sizing
```

Do not rely on scanner APIs alone for large trades.

---

## Risk scoring

The scanner starts with a score of `100`.

Warnings reduce score.

Hard blockers force decision to `skip`.

Example scoring logic:

```text
100 = clean starting score
85+ = buy_allowed if no hard blockers
below 85 = manual_review
any hard blocker = skip
```

The buy threshold is configurable:

```toml
[rules]
min_score_buy = 85
```

---

## Rule configuration

### TokenSniffer score

```toml
tokensniffer_min_score = 60
```

If TokenSniffer score is below this value, the token is blocked.

### Tax thresholds

```toml
sell_tax_warn = 10.0
sell_tax_block = 30.0

buy_tax_warn = 10.0
buy_tax_block = 30.0
```

Example behavior:

```text
sell tax >= 10% → warning
sell tax >= 30% → hard block
```

### Unverified source

```toml
skip_unverified_source = true
```

When enabled, unverified source code becomes a hard blocker.

When disabled, unverified source code becomes a warning.

---

## Nix

This project can be built with Nix flakes.

### Build

```bash
nix build
```

Run the built binary:

```bash
./result/bin/erc20-risk-gate --help
```

### Run directly

```bash
nix run . -- --help
```

### Install with user profile

```bash
nix profile install .
```

### NixOS system-wide install

Add this project as an input in your NixOS system flake:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    erc20-risk-gate = {
      url = "path:/home/YOUR_USER/projects/erc20-risk-gate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ self, nixpkgs, erc20-risk-gate, ... }:
    let
      system = "x86_64-linux";
    in
    {
      nixosConfigurations.my-hostname = nixpkgs.lib.nixosSystem {
        inherit system;

        modules = [
          ./configuration.nix

          ({ pkgs, ... }: {
            environment.systemPackages = [
              erc20-risk-gate.packages.${pkgs.stdenv.hostPlatform.system}.default
            ];
          })
        ];
      };
    };
}
```

Then rebuild:

```bash
sudo nixos-rebuild switch --flake /etc/nixos#my-hostname
```

After rebuild:

```bash
erc20-risk-gate --help
```

---

## Security notes

This tool is defensive software.

It should not be treated as financial advice.

It should not be used as the only condition for automated buying.

Recommended extra protections:

* forked transaction simulation
* tiny first buy
* immediate test sell
* strict position sizing
* max slippage limits
* max tax limits
* liquidity lock verification
* owner/deployer behavior tracking
* mempool and pair-age filters
* blocklist for known scam deployers

---

## Limitations

The scanner can miss:

* delayed honeypot activation
* owner actions after initial scan
* proxy implementation changes
* off-chain coordinated rugs
* malicious external dependencies
* contracts that behave differently for different wallets
* liquidity removal after buy
* dynamic tax changes after launch

If source code is unavailable, bytecode-only checks are weaker.

If provider APIs are unavailable, the report may return `manual_review` instead of `buy_allowed`.

---

## Development

Format code:

```bash
cargo fmt
```

Run lints:

```bash
cargo clippy --all-targets --all-features
```

Run tests:

```bash
cargo test
```

Build release:

```bash
cargo build --release
```

---

## Roadmap

Possible next features:

* Slither JSON integration
* Sourcify source fallback
* Alloy-based on-chain calls
* EIP-1967 proxy implementation lookup
* bytecode selector scanner
* forked buy/sell simulation
* liquidity lock provider integration
* deployer reputation scoring
* Telegram/Discord bot output
* SQLite scan history
* batch scanning
* Prometheus metrics
* REST API mode

---

## Disclaimer

ERC-20 trading is risky.

New tokens can be malicious, unstable, illiquid, or intentionally deceptive.

This project helps identify common risks, but it cannot prove that a token is safe.

Use at your own risk.
