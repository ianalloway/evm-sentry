"""Chain configuration for RPC and Etherscan-compatible explorer access."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ChainConfig:
    name: str
    chain_id: int
    default_rpc: str
    explorer_api: str
    explorer_url: str
    native_symbol: str = "ETH"

    @property
    def rpc_url(self) -> str:
        return os.environ.get(f"EVM_SENTRY_RPC_{self.name.upper()}") or self.default_rpc


_EXPLORER_API = "https://api.etherscan.io/v2/api"

CHAINS: dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        name="ethereum",
        chain_id=1,
        default_rpc="https://eth.llamarpc.com",
        explorer_api=_EXPLORER_API,
        explorer_url="https://etherscan.io",
    ),
    "base": ChainConfig(
        name="base",
        chain_id=8453,
        default_rpc="https://mainnet.base.org",
        explorer_api=_EXPLORER_API,
        explorer_url="https://basescan.org",
    ),
    "optimism": ChainConfig(
        name="optimism",
        chain_id=10,
        default_rpc="https://mainnet.optimism.io",
        explorer_api=_EXPLORER_API,
        explorer_url="https://optimistic.etherscan.io",
    ),
    "arbitrum": ChainConfig(
        name="arbitrum",
        chain_id=42161,
        default_rpc="https://arb1.arbitrum.io/rpc",
        explorer_api=_EXPLORER_API,
        explorer_url="https://arbiscan.io",
    ),
}

ALIASES = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "op": "optimism",
    "arb": "arbitrum",
}


def resolve_chain(name: str) -> ChainConfig:
    key = ALIASES.get(name.strip().lower(), name.strip().lower())
    if key not in CHAINS:
        raise ValueError(f"Unknown chain '{name}'. Supported: {', '.join(CHAINS)}")
    return CHAINS[key]


def explorer_api_key() -> str | None:
    return os.environ.get("ETHERSCAN_API_KEY") or None
