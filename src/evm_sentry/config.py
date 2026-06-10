"""Chain configuration.

Etherscan's V2 API is multichain: a single API key works across Ethereum,
Base, Optimism, Arbitrum, etc. by passing ``chainid``. We default to public
RPC endpoints so the tool runs with zero configuration, and use the explorer
API only when an API key is available (for verified source + creation data).

Override RPC URLs with env vars: EVM_SENTRY_RPC_<CHAIN> (e.g.
EVM_SENTRY_RPC_BASE). Provide an explorer key with ETHERSCAN_API_KEY.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class ChainConfig:
    name: str
    chain_id: int
    default_rpc: str
    explorer_api: str          # Etherscan V2 unified endpoint
    explorer_url: str          # human browse URL
    native_symbol: str = "ETH"

    @property
    def rpc_url(self) -> str:
        env = os.environ.get(f"EVM_SENTRY_RPC_{self.name.upper()}")
        return env or self.default_rpc


CHAINS: Dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        name="ethereum",
        chain_id=1,
        default_rpc="https://eth.llamarpc.com",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_url="https://etherscan.io",
    ),
    "base": ChainConfig(
        name="base",
        chain_id=8453,
        default_rpc="https://mainnet.base.org",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_url="https://basescan.org",
    ),
    "optimism": ChainConfig(
        name="optimism",
        chain_id=10,
        default_rpc="https://mainnet.optimism.io",
        explorer_api="https://api.etherscan.io/v2/api",
        explorer_url="https://optimistic.etherscan.io",
    ),
}

# Friendly aliases
ALIASES = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "op": "optimism",
}


def resolve_chain(name: str) -> ChainConfig:
    key = name.strip().lower()
    key = ALIASES.get(key, key)
    if key not in CHAINS:
        raise ValueError(
            f"Unknown chain '{name}'. Supported: {', '.join(CHAINS)}"
        )
    return CHAINS[key]


def explorer_api_key() -> Optional[str]:
    return os.environ.get("ETHERSCAN_API_KEY") or None
