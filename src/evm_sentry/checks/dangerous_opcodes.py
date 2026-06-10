"""Bytecode-level dangerous-capability checks (work without verified source)."""

from __future__ import annotations

from typing import List

from .. import bytecode as bc
from ..context import ContractContext
from ..models import Finding, Severity


def check_dangerous_opcodes(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract:
        return []
    findings: List[Finding] = []
    ops = bc.present_opcodes(ctx.bytecode)

    if "SELFDESTRUCT" in ops:
        findings.append(
            Finding(
                id="OPCODE_SELFDESTRUCT",
                title="SELFDESTRUCT reachable in bytecode",
                severity=Severity.HIGH,
                check="dangerous_opcodes",
                description=(
                    "The runtime bytecode contains SELFDESTRUCT. The contract "
                    "(or a delegatecall target) may be able to destroy itself, "
                    "wiping code and forwarding its balance."
                ),
                evidence={"opcode": "0xFF"},
            )
        )

    if "DELEGATECALL" in ops:
        findings.append(
            Finding(
                id="OPCODE_DELEGATECALL",
                title="DELEGATECALL present in bytecode",
                severity=Severity.MEDIUM,
                check="dangerous_opcodes",
                description=(
                    "DELEGATECALL executes external code in this contract's "
                    "storage context. Common in proxies/libraries, but it is "
                    "also the primary storage-corruption and takeover vector."
                ),
                evidence={"opcode": "0xF4"},
            )
        )

    if "CALLCODE" in ops:
        findings.append(
            Finding(
                id="OPCODE_CALLCODE",
                title="Deprecated CALLCODE present",
                severity=Severity.LOW,
                check="dangerous_opcodes",
                description="CALLCODE (0xF2) is deprecated and a code smell.",
            )
        )

    if "CREATE2" in ops:
        findings.append(
            Finding(
                id="OPCODE_CREATE2",
                title="CREATE2 present (deterministic deploys)",
                severity=Severity.LOW,
                check="dangerous_opcodes",
                description=(
                    "CREATE2 enables deploying to a precomputed address. Used "
                    "legitimately (factories), but also in metamorphic-contract "
                    "tricks where code at an address changes after selfdestruct."
                ),
            )
        )

    return findings
