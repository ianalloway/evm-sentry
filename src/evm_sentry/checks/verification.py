"""Source-verification check."""

from __future__ import annotations

from typing import List

from ..context import ContractContext
from ..models import Finding, Severity


def check_verification(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract:
        return []
    # Only assert "unverified" when we actually queried the explorer.
    queried = any(s.startswith("explorer") for s in ctx.data_sources)
    if not queried:
        return []  # can't claim verified/unverified without a key
    if ctx.verified:
        return [
            Finding(
                id="SOURCE_VERIFIED",
                title="Source code is verified on the block explorer",
                severity=Severity.INFO,
                check="verification",
                description=(
                    f"Verified as '{ctx.contract_name}' "
                    f"(compiler {ctx.compiler_version})."
                ),
            )
        ]
    return [
        Finding(
            id="SOURCE_UNVERIFIED",
            title="Contract source code is NOT verified",
            severity=Severity.MEDIUM,
            check="verification",
            description=(
                "No verified source is published. Behavior can only be "
                "inferred from bytecode, which materially raises the risk of "
                "hidden logic. Treat with caution."
            ),
            recommendation=(
                "Prefer contracts with verified, audited source. Manually "
                "decompile and review before interacting with value."
            ),
        )
    ]
