<h1 align="center">🛡️ EVM Sentry</h1>

<p align="center">
  <b>On-chain anomaly &amp; risk scanner for Base and Ethereum smart contracts.</b><br/>
  Point it at any contract address and get a transparent, explainable risk report —
  proxy/upgradeability, access-control centralization, dangerous opcodes, honeypot
  signals, and provenance — in seconds.
</p>

<p align="center">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-blue.svg"/>
  <img alt="python" src="https://img.shields.io/badge/python-3.9%2B-blue.svg"/>
  <img alt="chains" src="https://img.shields.io/badge/chains-Ethereum%20%7C%20Base%20%7C%20Optimism-6f42c1.svg"/>
  <img alt="status" src="https://img.shields.io/badge/status-beta-yellow.svg"/>
</p>

---

## Why this exists

Most people interact with smart contracts they have never read. The information
needed to judge risk *is* on-chain and in verified source, but it's scattered
across explorers, storage slots, and bytecode. **EVM Sentry pulls it together
into one explainable score** so a researcher, a user, or a CI pipeline can ask
"what can this contract actually do to me?" before signing.

It is deliberately **heuristic and transparent**, not a black box. Every signal
in a report names the check that produced it, the evidence, and why it matters.
It is a triage and research tool — *not* a substitute for a professional audit.

## What it checks

| Category | Signals | Works without API key? |
|---|---|---|
| **Verification** | Verified vs. unverified source on the block explorer | needs explorer key |
| **Proxy / upgradeability** | EIP-1967 (transparent/UUPS) & EIP-1167 minimal proxies, implementation + admin slots, UUPS missing `_authorizeUpgrade` guard, `delegatecall`+`selfdestruct` (Parity-style brick) | ✅ (slots via RPC) |
| **Access control** | `Ownable`/single-owner vs. role-based, renounceable ownership, privileged powers (mint, adjustable fees, admin withdraw/sweep) | partial (full with source) |
| **Dangerous opcodes** | `SELFDESTRUCT`, `DELEGATECALL`, `CALLCODE`, `CREATE2` — parsed correctly, skipping PUSH immediate data | ✅ (bytecode only) |
| **Token honeypot signals** | blacklist/denylist, trading on/off toggle, max-tx / max-wallet limits, adjustable buy/sell fees, owner-controlled mint | needs source |
| **Provenance / freshness** | deployer, creation block, contract age (fresh deploys flagged) | needs explorer key |

Findings roll up into a **0–100 risk score** and a band
(`Minimal → Low → Elevated → High → Critical`).

## How it degrades gracefully

EVM Sentry is built to return something useful no matter what credentials you have:

- **Zero config** → public RPC gives bytecode + storage slots, so proxy detection
  and opcode analysis already work.
- **+ Etherscan V2 API key** (`ETHERSCAN_API_KEY`, one key for ETH/Base/OP) →
  unlocks verified-source heuristics, ABI checks, and deployment provenance.

The report's *Notes* section always states which data sources were available, so
a low score is never silently mistaken for a clean bill of health.

## Install

```bash
git clone https://github.com/ianalloway/evm-sentry.git
cd evm-sentry
pip install -e .
```

Optional (recommended) — set a free Etherscan V2 key to unlock source heuristics:

```bash
export ETHERSCAN_API_KEY=YourKeyHere
```

## Usage

```bash
# Scan a Base contract (terminal summary)
evm-sentry 0xYourContract --chain base

# Ethereum, full Markdown report to a file
evm-sentry 0xYourContract --chain ethereum --format markdown -o report.md

# JSON for piping into other tools
evm-sentry 0xYourContract --chain base --format json

# CI gate: exit non-zero if risk is High or worse
evm-sentry 0xYourContract --chain base --fail-on high
```

Supported chains: `ethereum` (1), `base` (8453), `optimism` (10). Override any
RPC with `EVM_SENTRY_RPC_<CHAIN>`.

### As a library

```python
from evm_sentry import Scanner

result = Scanner(chain="base").scan_address("0x...")
print(result.risk_score, result.risk_band)
for f in result.findings:
    print(f.severity.label, f.id, f.title)
```

## Example output

Running against an illustrative risky upgradeable token
([full report](examples/sample_report.md) ·
[JSON](examples/sample_report.json)):

```
Score   : 100/100 (Critical)
Findings:
  [High    ] UUPS_NO_AUTH_GUARD     UUPS proxy without visible _authorizeUpgrade guard
  [High    ] OPCODE_SELFDESTRUCT    SELFDESTRUCT reachable in bytecode
  [Medium  ] PROXY_UPGRADEABLE      Upgradeable proxy detected
  [Medium  ] PRIVILEGED_POWERS      Privileged owner powers present (mint, fees, withdraw)
  [Medium  ] TOKEN_BLACKLIST        Address blacklist / denylist mechanism
  [Medium  ] TOKEN_TRADING_TOGGLE   Trading can be toggled on/off by admin
  [Medium  ] TOKEN_ADJUSTABLE_FEES  Adjustable buy/sell fees
  [Medium  ] TOKEN_OWNER_MINT       Owner-controlled minting
  [Medium  ] FRESH_DEPLOYMENT       Recently deployed contract (18h old)
  [Low     ] SINGLE_OWNER           Single-owner access control
```

## Architecture

```
        address ──► EVMClient ──► ContractContext ──► [ checks ] ──► ScanResult ──► report
                    (RPC +                 (pure        (pure fns)      (score +     (md/json/
                   explorer)             gathered state)                band)        terminal)
```

- **`client.py`** gathers on-chain state (bytecode, balance, EIP-1967 slots,
  verified source, ABI, creation data) into a `ContractContext`.
- **`checks/`** are *pure functions* of a context → findings, so every rule is
  unit-tested with hand-built fixtures and needs no network.
- **`scoring.py`** maps severities to a clamped 0–100 score.
- **`report.py`** renders terminal / Markdown / JSON.

Adding a check is a ~15-line function dropped into `checks/` and registered in
`checks/__init__.py`. See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the
rationale behind each heuristic and its known false-positive modes.

## Not implemented yet

Ideas under consideration, not committed to: approval/allowance risk scanning,
reentrancy static patterns, storage-layout diffing across upgrades, batch/
watchlist mode, and an allowlist of known-good implementations to cut noise.
None of these exist in the codebase today — if you want one, open an issue.

## Limitations & disclaimer

EVM Sentry produces **heuristic risk signals, not guarantees**. Many flagged
patterns (proxies, owner mint, pausing) are perfectly legitimate; the tool
surfaces *capabilities and centralization*, and you must apply judgment. A low
score is **not** an endorsement and a high score is **not** proof of malice.
This is not financial advice and not a security audit. Always do your own
research and commission a professional audit before trusting a contract with
meaningful value.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). New detection
heuristics, false-positive reports with example addresses, and additional chains
are especially valuable. To report a security issue in EVM Sentry itself, see
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Ian Alloway
