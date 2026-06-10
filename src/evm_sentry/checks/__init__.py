"""Check registry. Order is cosmetic; severity drives report sorting."""

from __future__ import annotations

from typing import List

from .base import Check
from .dangerous_opcodes import check_dangerous_opcodes
from .freshness import check_freshness
from .ownership import check_ownership
from .proxy import check_proxy
from .token_traps import check_token_traps
from .verification import check_verification

ALL_CHECKS: List[Check] = [
    check_verification,
    check_proxy,
    check_ownership,
    check_dangerous_opcodes,
    check_token_traps,
    check_freshness,
]

__all__ = ["ALL_CHECKS", "Check"]
