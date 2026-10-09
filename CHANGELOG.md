# Changelog

Notable changes to evm-sentry. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Explorer API keys no longer leak into scan output. `requests` errors embed
  the full request URL (including `apikey=…`), and those messages flowed into
  report warnings (JSON / Markdown / terminal) and CLI `error:` lines. Warnings
  and errors now go through `redact_secrets()`, which masks key-like query
  params, the configured key, `ETHERSCAN_API_KEY`, and custom
  `EVM_SENTRY_RPC_*` URLs.
- RPC provider keys are redacted even when an error quotes only part of the
  URL (e.g. `Max retries exceeded with url: /v2/<key>`): key-like path
  segments and `user:pass@` userinfo from the RPC URL are masked, URL
  userinfo is masked everywhere, and the engine redacts context warnings and
  check exception text before they enter a `ScanResult`.

### Fixed

- The "No explorer API key set" note is only shown when no key is configured;
  an explorer request failure now reports as "Explorer source lookup failed".

## [0.2.0] - 2026-09-29

### Added

- **Approval / permit phishing risk signal** (`approval_traps` check, #5).
  Bytecode-only, so it works without verified source: scans PUSH4 function
  selectors and PUSH32 constants rather than raw hex substrings.
  - `APPROVAL_UNLIMITED_CONSTANT` (Medium): a hardcoded `type(uint256).max`
    alongside `approve` / `permit` / `increaseAllowance` /
    `setApprovalForAll` selectors.
  - `APPROVAL_PERMIT_DRAIN_SURFACE`: EIP-2612 or DAI-style `permit` plus a
    `transferFrom` / `safeTransferFrom` pull selector. Low on contracts that
    look like a plain ERC-20 Permit token; Medium otherwise, or when
    max-uint256 is also hardcoded.
  - New bytecode helpers: `iter_push_immediates()`, `push4_selectors()`,
    `has_push_immediate()`, and the `MAX_UINT256` constant.
- CLI `--markdown` flag as shorthand for `--format markdown`. The one-minute
  demo already used it, but argparse rejected it.
- CLI `--fail-on elevated`, an alias of `--fail-on medium` (both map to the
  Elevated risk band).
- CLI parser tests (`tests/test_cli.py`) that run without network access.

### Changed

- Package description, README, and CLI help now list Optimism alongside
  Ethereum and Base. Added a `Documentation` project URL and an `optimism`
  keyword.
- README: scan usage comes first, install from GitHub via `pipx`/`pip`,
  documents chain aliases (`eth`/`mainnet`, `op`), the `--timeline` window
  flags, the approval/permit check, and adds a CI badge. `docs/METHODOLOGY.md`
  documents the approval/permit heuristics and their false-positive modes.
- Sample reports in `examples/` regenerated to include the new check.

### Fixed

- Import ordering in `cli.py` flagged by ruff (I001).

### Maintenance

- Added a pull request template, a Contributor Covenant code of conduct, and
  a Dependabot auto-merge workflow for patch/minor dependency bumps.

## [0.1.0] - 2026-07-25

Initial release.
