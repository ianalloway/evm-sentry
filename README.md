# EVM Sentry

Explainable, read-only smart-contract risk triage for Ethereum, Base, Optimism, and Arbitrum.

EVM Sentry combines bytecode, proxy storage, verified source, ABI, and deployment provenance into a transparent risk report. It never sends transactions or needs a private key. The output is heuristic triage, not an audit or proof of safety.

## Install

```bash
git clone https://github.com/ianalloway/evm-sentry.git
cd evm-sentry
pip install -e .
```

An Etherscan V2 key is optional. Without one, public RPC still supports bytecode, opcode, proxy-slot, and upgrade-timeline analysis.

```bash
export ETHERSCAN_API_KEY=...
```

## Scan a contract

```bash
# Terminal report
evm-sentry 0xYourContract --chain base

# Machine-readable or Markdown output
evm-sentry 0xYourContract --chain ethereum --format json
evm-sentry 0xYourContract --chain optimism --format markdown -o report.md

# CI gate: exit 1 for High or Critical results
evm-sentry 0xYourContract --chain arbitrum --fail-on high
```

Supported chains: `ethereum`, `base`, `optimism`, and `arbitrum`. Override a public RPC with `EVM_SENTRY_RPC_<CHAIN>`, such as `EVM_SENTRY_RPC_BASE`.

## Inspect upgrade history

The timeline command reads common OpenZeppelin/EIP-1967 events directly from `eth_getLogs`:

```bash
evm-sentry timeline 0xYourProxy --chain base
evm-sentry timeline 0xYourProxy --chain arbitrum --lookback 50000 --format json
evm-sentry timeline 0xYourProxy --from-block 123000 --to-block 124000 -o timeline.md
```

It decodes:

- `Upgraded(address)`
- `AdminChanged(address,address)`
- `BeaconUpgraded(address)`

The default lookback is 1,000 blocks to work with restrictive public RPCs. No matching event is not evidence that a contract is immutable or safe.

## What the scanner checks

| Area | Signals | Zero-config? |
|---|---|---|
| Verification | verified vs. unverified explorer source | explorer key |
| Proxy risk | EIP-1967, EIP-1167, implementation/admin slots, UUPS guard patterns | yes/partial |
| Upgrade history | implementation, admin, and beacon events | yes |
| Access control | single owner, roles, renounceability, privileged powers | source improves results |
| Bytecode | `SELFDESTRUCT`, `DELEGATECALL`, `CALLCODE`, `CREATE2` | yes |
| Token traps | blacklist, trading toggle, limits, adjustable fees, owner mint | explorer key |
| Provenance | deployer, creation block, contract age | explorer key |

Findings are individually explained and rolled into a clamped 0–100 score: Minimal, Low, Elevated, High, or Critical. Reports always list missing data sources so an incomplete scan is not mistaken for a clean result.

## Python API

```python
from evm_sentry import Scanner
from evm_sentry.config import resolve_chain
from evm_sentry.timeline import scan_timeline

result = Scanner(chain="base").scan_address("0x...")
print(result.risk_score, result.risk_band)

history = scan_timeline("0x...", resolve_chain("base"), lookback=10_000)
for event in history.events:
    print(event.block_number, event.event, event.values)
```

## Design

```text
address -> EVMClient -> ContractContext -> pure checks -> ScanResult -> report
                    \-> upgrade/admin logs -> TimelineReport
```

- `client.py` is the only network boundary.
- `checks/` contains pure, fixture-testable rules.
- `scoring.py` owns score calculation.
- `report.py` and `timeline.py` own rendering.
- The CLI only parses arguments and selects those components.

## Development

```bash
pip install -e ".[dev]"
ruff check src tests examples
pytest -q
python examples/generate_sample.py
```

CI tests the minimum supported Python and a modern Python, builds the package, installs the wheel, and smoke-tests the console entry point.

## Safety and limitations

EVM Sentry is for authorized, read-only analysis. A flagged capability can be legitimate, a low score is not an endorsement, and no heuristic scanner replaces source review, threat modeling, or a professional audit. Do not use it to attack contracts or bypass access controls.

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md), [SECURITY.md](SECURITY.md), and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © 2026 Ian Alloway
