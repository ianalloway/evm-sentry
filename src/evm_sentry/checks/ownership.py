"""Ownership & access-control / centralization checks."""

from __future__ import annotations

from typing import List

from ..context import ContractContext
from ..models import Finding, Severity
from .base import abi_has_function, source_has


def check_ownership(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract:
        return []
    findings: List[Finding] = []

    has_owner = (
        abi_has_function(ctx, "owner", "getOwner")
        or source_has(ctx, r"\bOwnable\b|\bonlyOwner\b")
    )
    has_roles = abi_has_function(
        ctx, "hasRole", "grantRole", "DEFAULT_ADMIN_ROLE"
    ) or source_has(ctx, r"AccessControl")

    if has_owner and not has_roles:
        findings.append(
            Finding(
                id="SINGLE_OWNER",
                title="Single-owner access control",
                severity=Severity.LOW,
                check="ownership",
                description=(
                    "Privileged actions are gated by a single owner. If that "
                    "key is an EOA, it is a single point of failure and a "
                    "centralization/rug vector."
                ),
                recommendation=(
                    "Check whether ownership is renounced or held by a "
                    "timelock/multisig. A lone EOA owner is higher risk."
                ),
            )
        )

    if source_has(ctx, r"renounceOwnership"):
        findings.append(
            Finding(
                id="OWNERSHIP_RENOUNCEABLE",
                title="Ownership can be renounced",
                severity=Severity.INFO,
                check="ownership",
                description=(
                    "renounceOwnership present. Renouncing can reduce rug risk "
                    "but also permanently disables admin functions (e.g. "
                    "pausing during an exploit)."
                ),
            )
        )

    # Privileged token-supply / fund-movement powers.
    powers = []
    if abi_has_function(ctx, "mint") or source_has(ctx, r"function\s+mint"):
        powers.append("mint")
    if source_has(ctx, r"function\s+(setFee|setTax|updateFee)"):
        powers.append("adjustable fees")
    if abi_has_function(ctx, "withdraw", "rescueTokens", "sweep") or source_has(
        ctx, r"function\s+(withdraw|sweep|rescue\w*)"
    ):
        powers.append("admin withdraw/sweep")
    if powers:
        findings.append(
            Finding(
                id="PRIVILEGED_POWERS",
                title="Privileged owner powers present",
                severity=Severity.MEDIUM,
                check="ownership",
                description=(
                    "Owner/admin can: " + ", ".join(powers) + ". These are "
                    "legitimate in many designs but are also the levers used "
                    "in rug pulls. Confirm who holds the keys and any limits."
                ),
                evidence={"powers": powers},
            )
        )

    return findings
