# EVM Sentry — 1 minute demo

EVM Sentry is an MIT-licensed CLI/library that scans deployed EVM contracts on
Base, Ethereum, and Optimism and produces explainable risk reports.

## Demo: scan Base USDC

```bash
pipx install git+https://github.com/ianalloway/evm-sentry.git
# or: pip install git+https://github.com/ianalloway/evm-sentry.git

evm-sentry 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --chain base --markdown
```

Output includes:

- contract/EOA detection from on-chain bytecode
- proxy / upgradeability signals
- privileged ownership and admin-power signals
- dangerous opcode checks
- token trap / honeypot-style heuristics
- JSON and Markdown output for CI or public writeups

A sample report (illustrative, generated offline) showing the full output
shape is committed here:

- [`examples/sample_report.md`](../examples/sample_report.md)
- [`examples/sample_report.json`](../examples/sample_report.json)

## Why this matters for Base

Base has fast-moving token and contract deployment. EVM Sentry gives builders,
security researchers, and users a free first-pass risk triage tool before they
integrate with, audit, or interact with a contract.
