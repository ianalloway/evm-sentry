# Security Policy

## Scope

EVM Sentry is a **read-only** analysis tool. It never signs transactions, holds
keys, or moves funds. It makes outbound RPC and block-explorer API calls only.

## Reporting a vulnerability in EVM Sentry

If you find a security issue in this tool (e.g. a way to make it crash on
crafted input, leak an API key, or produce dangerously misleading output),
please open a GitHub security advisory or email the maintainer rather than
filing a public issue. We aim to acknowledge within a few days.

## Using EVM Sentry responsibly

This tool helps **defensive, white-hat** research: triaging contracts, screening
before interacting, and building toward responsible disclosure on platforms like
Immunefi, HackenProof, and Sherlock. It is not a guarantee of safety and not a
substitute for a professional audit. Do not represent its output as one.
