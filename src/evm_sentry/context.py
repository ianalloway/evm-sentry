"""ContractContext — the gathered on-chain state a scan reasons about.

Checks are pure functions of a ContractContext, so they can be unit-tested
with hand-built fixtures and never need network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ContractContext:
    address: str
    chain: str
    chain_id: int

    # Runtime state
    bytecode: str = ""                 # hex, "0x" or empty if EOA
    balance_wei: int = 0

    # Explorer-sourced (only present with an API key + verified contract)
    verified: bool = False
    contract_name: str = ""
    compiler_version: str = ""
    source_code: str = ""
    abi: List[Dict[str, Any]] = field(default_factory=list)

    # Proxy / upgradeability
    proxy_implementation: str = ""     # from explorer or EIP-1967 slot
    proxy_admin: str = ""
    proxy_kind: str = ""               # "eip1967", "minimal", "explorer", ...

    # Provenance
    creator: str = ""
    creation_tx: str = ""
    creation_block: Optional[int] = None
    creation_timestamp: Optional[int] = None

    # Bookkeeping
    data_sources: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def is_contract(self) -> bool:
        from .bytecode import has_code
        return has_code(self.bytecode)

    @property
    def source_lower(self) -> str:
        return self.source_code.lower()
