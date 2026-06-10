"""Check framework: a Check is a pure function ContractContext -> [Finding]."""

from __future__ import annotations

import re
from typing import Callable, List

from ..context import ContractContext
from ..models import Finding

Check = Callable[[ContractContext], List[Finding]]


def source_has(ctx: ContractContext, pattern: str) -> bool:
    """Case-insensitive regex search over verified source (if any)."""
    if not ctx.source_code:
        return False
    return re.search(pattern, ctx.source_code, re.IGNORECASE) is not None


def abi_function_names(ctx: ContractContext) -> List[str]:
    return [
        item.get("name", "")
        for item in ctx.abi
        if isinstance(item, dict) and item.get("type") == "function"
    ]


def abi_has_function(ctx: ContractContext, *names: str) -> bool:
    have = {n.lower() for n in abi_function_names(ctx)}
    return any(n.lower() in have for n in names)
