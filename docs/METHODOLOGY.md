# Methodology

EVM Sentry favors **transparent, explainable heuristics** over opaque scoring.
This document explains what each check looks for, why it matters, and its known
false-positive modes. Honesty about limitations is a feature: a risk tool that
overclaims is worse than none.

## Data sources

| Source | Provides | Requires |
|---|---|---|
| `eth_getCode` (RPC) | runtime bytecode → opcode analysis, contract-vs-EOA | RPC URL only |
| `eth_getStorageAt` (RPC) | EIP-1967 implementation/admin slots | RPC URL only |
| `eth_getBalance` (RPC) | native balance | RPC URL only |
| Etherscan V2 `getsourcecode` | verified source, ABI, proxy flag | API key |
| Etherscan V2 `getcontractcreation` | deployer, creation block | API key |

The Etherscan **V2** API is multichain: a single key serves Ethereum, Base, and
Optimism by passing `chainid`.

## Scoring

Each finding has a severity (`INFO/LOW/MEDIUM/HIGH/CRITICAL`) with a fixed
weight (0/5/15/30/50). The score is the clamped sum over **non-informational**
findings, capped at 100, mapped to a band:

| Score | Band |
|---|---|
| 0 | Minimal |
| 1–24 | Low |
| 25–49 | Elevated |
| 50–74 | High |
| 75–100 | Critical |

This is intentionally simple and auditable. It is a **triage prioritizer**, not
a probability of loss. Two MEDIUM findings can outweigh one HIGH by design,
because stacked centralization powers compound.

## Checks

### Verification (`verification`)
Flags unverified source as MEDIUM — but **only when the explorer was actually
queried**, so we never assert "unverified" just because no API key was set. With
verified source, the richer source-based checks below become available.

### Proxy / upgradeability (`proxy`)
- **EIP-1167 minimal proxies** detected by runtime prefix; the implementation
  address is extracted from the clone.
- **EIP-1967** transparent/UUPS proxies detected by reading the canonical
  implementation/admin storage slots directly — works even without source.
- **UUPS without `_authorizeUpgrade`**: HIGH. A missing/empty upgrade guard has
  allowed unauthorized upgrades in the wild.
- **`delegatecall` + `selfdestruct`**: HIGH. The pattern behind the Parity
  multisig freeze, where a library self-destruct bricked dependent proxies.

*False positives:* legitimate, well-governed proxies are extremely common. The
finding reports a **capability** (logic can change), not wrongdoing. Always
check who controls the admin/owner (timelock + multisig is much safer than EOA).

### Access control (`ownership`)
Distinguishes single-owner (`Ownable`) from role-based (`AccessControl`).
Single-owner is LOW on its own but a single point of failure if the key is an
EOA. Privileged powers (mint, adjustable fees, admin withdraw/sweep) are MEDIUM
because they are the exact levers used in rug pulls — while also being normal in
many honest designs.

*False positives:* renounced ownership or a governance timelock substantially
reduces real risk; the tool flags the *presence* of the power, not its current
controllability. The roadmap includes resolving owner/admin to a contract type.

### Dangerous opcodes (`dangerous_opcodes`)
Parses runtime bytecode, **correctly skipping PUSH immediate data** (a frequent
source of false positives in naive scanners). Flags `SELFDESTRUCT` (HIGH),
`DELEGATECALL` (MEDIUM), `CALLCODE` (LOW, deprecated), `CREATE2` (LOW,
metamorphic-contract enabler).

*False positives:* `DELEGATECALL` is ubiquitous in proxies and libraries; treat
it as context, not a verdict.

### Token honeypot signals (`token_traps`)
Source-text heuristics for classic honeypot/rug levers: blacklist/denylist,
trading on/off toggles, max-tx / max-wallet caps, adjustable buy/sell fees, and
owner-controlled minting. Any one can be legitimate (anti-bot launches use
limits); **clusters** of them on a fresh, single-owner token are the real
signal.

*False positives:* regex over source can match comments or unrelated identifiers.
These are MEDIUM/LOW precisely because they require human confirmation. The
roadmap replaces regex with AST/ABI-level matching to cut noise.

### Provenance / freshness (`freshness`)
Contracts younger than 48h are MEDIUM, 2–14 days LOW. New code has no track
record and most scams operate within their first days. Old age is not safety,
but youth plus privileged powers is a meaningful combination.

## Roadmap toward higher precision

The current rules optimize for **recall and explainability** at the cost of some
precision (false positives the user can dismiss with the provided evidence).
Planned precision work: AST-based source analysis instead of regex, resolving
owner/admin addresses to EOA-vs-multisig-vs-timelock, and an allowlist of
known-good implementation contracts (OpenZeppelin, Uniswap, etc.).
