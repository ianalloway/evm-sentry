"""Provenance / freshness checks."""

from __future__ import annotations

import time
from typing import List

from ..context import ContractContext
from ..models import Finding, Severity

DAY = 86400


def check_freshness(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract or not ctx.creation_timestamp:
        return []
    age_days = (time.time() - ctx.creation_timestamp) / DAY
    findings: List[Finding] = []

    if age_days < 2:
        sev = Severity.MEDIUM
        msg = "deployed less than 48 hours ago"
    elif age_days < 14:
        sev = Severity.LOW
        msg = f"deployed {age_days:.0f} days ago"
    else:
        return []

    findings.append(
        Finding(
            id="FRESH_DEPLOYMENT",
            title="Recently deployed contract",
            severity=sev,
            check="freshness",
            description=(
                f"Contract was {msg}. New contracts have little track record; "
                "many rugs and scams operate within their first days. Combine "
                "with privileged-power findings for an overall picture."
            ),
            evidence={
                "creation_block": ctx.creation_block,
                "age_days": round(age_days, 1),
                "creator": ctx.creator,
            },
        )
    )
    return findings
