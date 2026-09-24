"""Unlimited-approval & EIP-2612 permit phishing surfaces (bytecode selectors).

Works without verified source: scans PUSH4 immediates and PUSH32 constants so
dispatchers / external calls are detected without misreading push data as code.
"""

from __future__ import annotations

from typing import Dict, List, Set

from .. import bytecode as bc
from ..context import ContractContext
from ..models import Finding, Severity

# Canonical 4-byte selectors (hex, no 0x), as they appear in PUSH4 immediates.
SELECTOR_NAMES: Dict[str, str] = {
    "095ea7b3": "approve",
    "d505accf": "permit",  # EIP-2612
    "8fcbaf0c": "permit_dai",  # DAI-style permit(holder,spender,nonce,expiry,allowed,...)
    "39509351": "increaseAllowance",
    "a22cb465": "setApprovalForAll",
    "23b872dd": "transferFrom",
    "42842e0e": "safeTransferFrom",
    "b88d4fde": "safeTransferFrom_data",
    "70a08231": "balanceOf",
    "a9059cbb": "transfer",
    "18160ddd": "totalSupply",
}

_APPROVAL_NAMES = frozenset(
    {"approve", "permit", "permit_dai", "increaseAllowance", "setApprovalForAll"}
)
_PERMIT_NAMES = frozenset({"permit", "permit_dai"})
_PULL_NAMES = frozenset({"transferFrom", "safeTransferFrom", "safeTransferFrom_data"})
_ERC20_MARKERS = frozenset({"balanceOf", "transfer", "totalSupply"})


def named_selectors(code: str) -> Set[str]:
    """Map PUSH4 immediates in ``code`` to known selector names."""
    found = bc.push4_selectors(code)
    return {SELECTOR_NAMES[s] for s in found if s in SELECTOR_NAMES}


def check_approval_traps(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract:
        return []

    names = named_selectors(ctx.bytecode)
    if not names:
        return []

    findings: List[Finding] = []
    approval_hits = sorted(names & _APPROVAL_NAMES)
    permit_hits = sorted(names & _PERMIT_NAMES)
    pull_hits = sorted(names & _PULL_NAMES)
    has_max = bc.has_push_immediate(ctx.bytecode, bc.MAX_UINT256)
    looks_like_erc20 = _ERC20_MARKERS <= names

    # Hardcoded type(uint256).max beside approve/permit/setApprovalForAll is the
    # classic unlimited-allowance fingerprint used by drainers and aggressive routers.
    if approval_hits and has_max:
        findings.append(
            Finding(
                id="APPROVAL_UNLIMITED_CONSTANT",
                title="Hardcoded unlimited approval constant in bytecode",
                severity=Severity.MEDIUM,
                check="approval_traps",
                description=(
                    "Runtime bytecode pushes type(uint256).max and exposes "
                    f"approval-related selectors ({', '.join(approval_hits)}). "
                    "Phishing drainers and some routers hardcode unlimited "
                    "approvals so a single signature/tx can seize a victim's "
                    "full token balance."
                ),
                evidence={
                    "selectors": approval_hits,
                    "max_uint256_push32": True,
                },
                recommendation=(
                    "Prefer bounded allowances. If this is a router/aggregator, "
                    "confirm it is a known-good implementation before approving."
                ),
            )
        )

    # EIP-2612 / DAI permit + pull = the surface phishing sites abuse for
    # gasless allowance capture, then transferFrom.
    if permit_hits and pull_hits:
        if looks_like_erc20 and not has_max:
            sev = Severity.LOW
            title = "EIP-2612 permit surface (phishing-prone UX)"
            desc = (
                "Token bytecode exposes permit "
                f"({', '.join(permit_hits)}) plus "
                f"{', '.join(pull_hits)}. Legitimate ERC-20 Permit tokens "
                "look like this; phishing sites still abuse permit signatures "
                "to grant allowances without a visible approve tx."
            )
            rec = (
                "Never sign permit/Permit2 payloads from untrusted sites; "
                "verify spender and amount off-band."
            )
        else:
            sev = Severity.MEDIUM
            title = "Permit + transferFrom drain surface"
            why = (
                "hardcoded unlimited-approval constant"
                if has_max
                else "does not look like a plain ERC-20 token interface"
            )
            desc = (
                "Bytecode combines permit "
                f"({', '.join(permit_hits)}) with token-pull selectors "
                f"({', '.join(pull_hits)}) and {why}. This is the classic "
                "gasless-phishing pattern: obtain a signed permit, then "
                "transferFrom the victim's tokens."
            )
            rec = (
                "Treat unknown permit-consuming contracts as high risk. "
                "Verify the spender against an official deployment list."
            )
        findings.append(
            Finding(
                id="APPROVAL_PERMIT_DRAIN_SURFACE",
                title=title,
                severity=sev,
                check="approval_traps",
                description=desc,
                evidence={
                    "permit_selectors": permit_hits,
                    "pull_selectors": pull_hits,
                    "looks_like_erc20": looks_like_erc20,
                    "max_uint256_push32": has_max,
                },
                recommendation=rec,
            )
        )

    return findings
