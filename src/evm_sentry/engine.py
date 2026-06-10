"""Scanner engine: orchestrates context-gathering + checks + scoring."""

from __future__ import annotations

from typing import List, Optional

from .checks import ALL_CHECKS, Check
from .client import EVMClient, is_address
from .config import resolve_chain
from .context import ContractContext
from .models import Finding, ScanResult, Severity
from .scoring import score


class Scanner:
    def __init__(
        self,
        chain: str = "ethereum",
        api_key: Optional[str] = None,
        checks: Optional[List[Check]] = None,
        client: Optional[EVMClient] = None,
    ):
        self.chain_cfg = resolve_chain(chain)
        self.checks = checks if checks is not None else list(ALL_CHECKS)
        self.client = client or EVMClient(self.chain_cfg, api_key=api_key)

    def scan_address(self, address: str) -> ScanResult:
        if not is_address(address):
            raise ValueError(f"Not a valid 0x address: {address!r}")
        ctx = self.client.build_context(address)
        return self.scan_context(ctx)

    def scan_context(self, ctx: ContractContext) -> ScanResult:
        """Run all checks against an already-gathered context (pure, testable)."""
        result = ScanResult(
            address=ctx.address,
            chain=ctx.chain,
            is_contract=ctx.is_contract,
            warnings=list(ctx.warnings),
            metadata={
                "chain_id": ctx.chain_id,
                "contract_name": ctx.contract_name,
                "compiler": ctx.compiler_version,
                "verified": ctx.verified,
                "proxy_kind": ctx.proxy_kind,
                "implementation": ctx.proxy_implementation,
                "balance_eth": round(ctx.balance_wei / 1e18, 6),
                "creator": ctx.creator,
                "data_sources": ctx.data_sources,
            },
        )

        if not ctx.is_contract:
            result.add(
                Finding(
                    id="NOT_A_CONTRACT",
                    title="Address is an externally owned account (EOA), not a contract",
                    severity=Severity.INFO,
                    check="engine",
                    description=(
                        "No bytecode at this address. It is a wallet/EOA (or a "
                        "not-yet-deployed counterfactual address)."
                    ),
                )
            )
            result.risk_score, result.risk_band = 0, "N/A"
            return result

        for check in self.checks:
            try:
                for finding in check(ctx):
                    result.add(finding)
            except Exception as exc:  # noqa: BLE001
                result.warnings.append(
                    f"Check '{getattr(check, '__name__', check)}' errored: {exc}"
                )

        # Score on non-informational findings.
        scored = [f for f in result.findings if f.severity > Severity.INFO]
        result.risk_score, result.risk_band = score(scored)
        return result
