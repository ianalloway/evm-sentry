"""Proxy / upgradeability checks."""

from __future__ import annotations

from typing import List

from ..context import ContractContext
from ..models import Finding, Severity
from .base import source_has


def check_proxy(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract:
        return []
    findings: List[Finding] = []

    if ctx.proxy_implementation:
        sev = Severity.MEDIUM
        desc = (
            f"This is an upgradeable proxy ({ctx.proxy_kind or 'unknown'} "
            f"pattern). Implementation -> {ctx.proxy_implementation}. "
            "The logic users interact with can be replaced by whoever holds "
            "upgrade rights, changing behavior after you've approved or "
            "deposited funds."
        )
        ev = {
            "proxy_kind": ctx.proxy_kind,
            "implementation": ctx.proxy_implementation,
        }
        if ctx.proxy_admin:
            ev["admin"] = ctx.proxy_admin
        findings.append(
            Finding(
                id="PROXY_UPGRADEABLE",
                title="Upgradeable proxy detected",
                severity=sev,
                check="proxy",
                description=desc,
                evidence=ev,
                recommendation=(
                    "Identify who controls upgrades (admin / owner). If it is "
                    "an EOA or unaudited multisig, treat upgradeability as a "
                    "centralization risk."
                ),
            )
        )

    # UUPS without an explicit upgrade guard is a known footgun.
    if source_has(ctx, r"\bUUPSUpgradeable\b") and not source_has(
        ctx, r"_authorizeUpgrade"
    ):
        findings.append(
            Finding(
                id="UUPS_NO_AUTH_GUARD",
                title="UUPS proxy without visible _authorizeUpgrade guard",
                severity=Severity.HIGH,
                check="proxy",
                description=(
                    "UUPSUpgradeable is used but no _authorizeUpgrade override "
                    "was found in source. A missing/empty guard can let anyone "
                    "upgrade the implementation."
                ),
                recommendation="Confirm _authorizeUpgrade restricts to owner/governance.",
            )
        )

    if source_has(ctx, r"\bdelegatecall\b") and source_has(
        ctx, r"selfdestruct|suicide"
    ):
        findings.append(
            Finding(
                id="DELEGATECALL_SELFDESTRUCT",
                title="delegatecall + selfdestruct present in source",
                severity=Severity.HIGH,
                check="proxy",
                description=(
                    "Combination seen in proxy-bricking incidents (e.g. the "
                    "Parity wallet freeze). A delegatecall into logic that can "
                    "selfdestruct may permanently disable the proxy."
                ),
            )
        )

    return findings
