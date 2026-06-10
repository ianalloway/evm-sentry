"""Token honeypot / rug-pull signal checks (source-based heuristics)."""

from __future__ import annotations

from typing import List

from ..context import ContractContext
from ..models import Finding, Severity
from .base import source_has


def check_token_traps(ctx: ContractContext) -> List[Finding]:
    if not ctx.is_contract or not ctx.source_code:
        return []
    findings: List[Finding] = []

    if source_has(ctx, r"blacklist|_blacklisted|isBlacklisted|denylist"):
        findings.append(
            Finding(
                id="TOKEN_BLACKLIST",
                title="Address blacklist / denylist mechanism",
                severity=Severity.MEDIUM,
                check="token_traps",
                description=(
                    "Source references a blacklist/denylist. An admin can block "
                    "specific addresses from transferring — a honeypot pattern "
                    "where buyers can purchase but not sell."
                ),
            )
        )

    if source_has(ctx, r"(canTrade|tradingEnabled|tradingOpen|enableTrading|swapEnabled)"):
        findings.append(
            Finding(
                id="TOKEN_TRADING_TOGGLE",
                title="Trading can be toggled on/off by admin",
                severity=Severity.MEDIUM,
                check="token_traps",
                description=(
                    "A trading on/off switch lets the owner disable transfers "
                    "or selling after launch — a common honeypot lever."
                ),
            )
        )

    if source_has(ctx, r"(maxTxAmount|maxTransactionAmount|maxWallet|_maxSell)"):
        findings.append(
            Finding(
                id="TOKEN_TX_LIMITS",
                title="Per-transaction / max-wallet limits",
                severity=Severity.LOW,
                check="token_traps",
                description=(
                    "Adjustable transfer/wallet caps can be set to ~0 to freeze "
                    "sells. Legitimate for anti-bot launches; verify bounds."
                ),
            )
        )

    # Fee mechanics with an upper bound that is suspiciously high.
    if source_has(ctx, r"(sellTax|sellFee|_sellFee|setFees|setSellTax)"):
        findings.append(
            Finding(
                id="TOKEN_ADJUSTABLE_FEES",
                title="Adjustable buy/sell fees",
                severity=Severity.MEDIUM,
                check="token_traps",
                description=(
                    "Owner-settable trading fees. If unbounded, fees can be "
                    "raised to ~100%, effectively confiscating sells."
                ),
                recommendation="Check for a hard max-fee constant in source.",
            )
        )

    if source_has(ctx, r"function\s+_?mint") and source_has(
        ctx, r"onlyOwner|onlyRole"
    ):
        findings.append(
            Finding(
                id="TOKEN_OWNER_MINT",
                title="Owner-controlled minting",
                severity=Severity.MEDIUM,
                check="token_traps",
                description=(
                    "Privileged mint can inflate supply and dilute holders. "
                    "Confirm whether minting is capped or permanently disabled."
                ),
            )
        )

    return findings
