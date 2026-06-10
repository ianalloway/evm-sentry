# Contributing to EVM Sentry

Thanks for helping make on-chain risk more transparent.

## Dev setup

```bash
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

## Adding a detection heuristic

Checks are **pure functions** of a `ContractContext` returning `list[Finding]`.
No network calls inside a check — the client gathers all state first.

1. Add a function in `src/evm_sentry/checks/your_check.py`:

   ```python
   from ..context import ContractContext
   from ..models import Finding, Severity

   def check_your_thing(ctx: ContractContext) -> list[Finding]:
       if not ctx.is_contract:
           return []
       # ... inspect ctx.bytecode / ctx.source_code / ctx.abi ...
       return [Finding(id="YOUR_ID", title="...", severity=Severity.MEDIUM,
                       check="your_thing", description="why it matters")]
   ```

2. Register it in `checks/__init__.py` (`ALL_CHECKS`).
3. Add tests in `tests/` with a hand-built `ContractContext` fixture.
4. Document the rationale + false-positive modes in `docs/METHODOLOGY.md`.

## Guidelines

- **Explain, don't just flag.** Every finding needs a `description` a non-expert
  can act on. Prefer surfacing a *capability* over asserting intent.
- **Pick severity honestly.** Reserve HIGH/CRITICAL for signals with a direct
  loss path. Centralization powers that are normal-but-risky are MEDIUM.
- **No false confidence.** If a check needs source/ABI, return nothing when it's
  unavailable rather than guessing.

## Reporting false positives

Open an issue with the address, chain, the finding ID, and why it's wrong. Real
example addresses make the heuristic measurably better.
