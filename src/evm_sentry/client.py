"""Network client for JSON-RPC and the Etherscan V2 explorer API.

The scanner degrades gracefully when either network source is unavailable:
RPC-only scans still produce bytecode/proxy findings, while an explorer key adds
verified source, ABI, and deployment provenance.
"""

from __future__ import annotations

import json
import re
from typing import Any

import requests

from . import bytecode as bc
from .config import ChainConfig, explorer_api_key
from .context import ContractContext

_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_address(value: str) -> bool:
    return bool(_ADDRESS_RE.fullmatch(value.strip()))


class EVMClient:
    def __init__(
        self,
        chain: ChainConfig,
        api_key: str | None = None,
        timeout: float = 20.0,
        session: requests.Session | None = None,
    ):
        self.chain = chain
        self.api_key = api_key if api_key is not None else explorer_api_key()
        self.timeout = timeout
        self.session = session or requests.Session()
        self._rpc_id = 0

    # ---- low-level JSON-RPC ------------------------------------------------
    def rpc(self, method: str, params: list[Any]) -> Any:
        self._rpc_id += 1
        response = self.session.post(
            self.chain.rpc_url,
            json={
                "jsonrpc": "2.0",
                "id": self._rpc_id,
                "method": method,
                "params": params,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        if "error" in data:
            raise RuntimeError(f"RPC error for {method}: {data['error']}")
        return data.get("result")

    def get_code(self, address: str) -> str:
        return self.rpc("eth_getCode", [address, "latest"]) or "0x"

    def get_balance(self, address: str) -> int:
        return int(self.rpc("eth_getBalance", [address, "latest"]) or "0x0", 16)

    def get_storage_at(self, address: str, slot: str) -> str:
        return self.rpc("eth_getStorageAt", [address, slot, "latest"]) or "0x0"

    def get_block_number(self) -> int:
        return int(self.rpc("eth_blockNumber", []) or "0x0", 16)

    def get_logs(
        self,
        *,
        address: str,
        topics: list[str],
        from_block: int,
        to_block: int,
    ) -> list[dict[str, Any]]:
        return self.rpc(
            "eth_getLogs",
            [
                {
                    "address": address,
                    "fromBlock": hex(from_block),
                    "toBlock": hex(to_block),
                    "topics": [topics],
                }
            ],
        ) or []

    # ---- explorer (Etherscan V2 multichain) -------------------------------
    def explorer(self, params: dict[str, Any]) -> dict[str, Any] | None:
        if not self.api_key:
            return None
        query = dict(params)
        query["chainid"] = self.chain.chain_id
        query["apikey"] = self.api_key
        response = self.session.get(
            self.chain.explorer_api,
            params=query,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_source(self, address: str) -> dict[str, Any] | None:
        return self.explorer(
            {"module": "contract", "action": "getsourcecode", "address": address}
        )

    def get_creation(self, address: str) -> dict[str, Any] | None:
        return self.explorer(
            {
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address,
            }
        )

    def get_block_timestamp(self, block_number: int) -> int | None:
        result = self.rpc("eth_getBlockByNumber", [hex(block_number), False])
        if result and result.get("timestamp"):
            return int(result["timestamp"], 16)
        return None

    # ---- orchestration -----------------------------------------------------
    def build_context(self, address: str) -> ContractContext:
        address = address.strip()
        context = ContractContext(
            address=address,
            chain=self.chain.name,
            chain_id=self.chain.chain_id,
        )

        try:
            context.bytecode = self.get_code(address)
            context.data_sources.append("rpc:eth_getCode")
        except Exception as exc:  # noqa: BLE001
            context.warnings.append(f"Could not fetch bytecode: {exc}")
            return context

        try:
            context.balance_wei = self.get_balance(address)
        except Exception as exc:  # noqa: BLE001
            context.warnings.append(f"Could not fetch balance: {exc}")

        if not context.is_contract:
            return context

        self._detect_proxy(context)
        self._enrich_from_explorer(context)
        return context

    def _detect_proxy(self, context: ContractContext) -> None:
        if bc.is_minimal_proxy(context.bytecode):
            context.proxy_kind = "minimal"
            context.proxy_implementation = bc.minimal_proxy_target(context.bytecode)
            return

        try:
            implementation = bc.slot_to_address(
                self.get_storage_at(context.address, bc.SLOT_IMPLEMENTATION)
            )
            if not implementation:
                return
            context.proxy_kind = "eip1967"
            context.proxy_implementation = implementation
            context.data_sources.append("rpc:eip1967-slot")
            context.proxy_admin = bc.slot_to_address(
                self.get_storage_at(context.address, bc.SLOT_ADMIN)
            )
        except Exception as exc:  # noqa: BLE001
            context.warnings.append(f"Proxy slot read failed: {exc}")

    def _enrich_from_explorer(self, context: ContractContext) -> None:
        try:
            source = self.get_source(context.address)
        except Exception as exc:  # noqa: BLE001
            context.warnings.append(f"Explorer source lookup failed: {exc}")
            source = None

        if source is None:
            context.warnings.append(
                "No explorer API key set (ETHERSCAN_API_KEY) — "
                "source/ABI heuristics skipped, bytecode analysis only."
            )
            return

        if str(source.get("status")) != "1" or not source.get("result"):
            context.warnings.append("Explorer returned no source record.")
            return

        context.data_sources.append("explorer:getsourcecode")
        result = source["result"]
        record = result[0] if isinstance(result, list) else result
        source_code = record.get("SourceCode", "") or ""
        context.verified = bool(source_code.strip())
        context.contract_name = record.get("ContractName", "") or ""
        context.compiler_version = record.get("CompilerVersion", "") or ""
        context.source_code = _clean_source(source_code)

        abi_raw = record.get("ABI", "")
        if abi_raw and abi_raw != "Contract source code not verified":
            try:
                context.abi = json.loads(abi_raw)
            except (json.JSONDecodeError, TypeError):
                pass

        if not context.proxy_implementation:
            implementation = (record.get("Implementation") or "").strip()
            if record.get("Proxy") in ("1", 1) and is_address(implementation):
                context.proxy_kind = context.proxy_kind or "explorer"
                context.proxy_implementation = implementation

        try:
            creation = self.get_creation(context.address)
            if creation and str(creation.get("status")) == "1":
                creation_record = creation["result"][0]
                context.creator = creation_record.get("contractCreator", "")
                context.creation_tx = creation_record.get("txHash", "")
                block = creation_record.get("blockNumber")
                if block:
                    context.creation_block = int(block)
                    context.creation_timestamp = self.get_block_timestamp(
                        context.creation_block
                    )
                context.data_sources.append("explorer:getcontractcreation")
        except Exception as exc:  # noqa: BLE001
            context.warnings.append(f"Creation lookup failed: {exc}")


def _clean_source(raw: str) -> str:
    """Unwrap Etherscan's multi-file source format into one source string."""
    source = raw.strip()
    if source.startswith("{{") and source.endswith("}}"):
        source = source[1:-1]
    if source.startswith("{") and '"sources"' in source:
        try:
            obj = json.loads(source)
            return "\n\n".join(
                value.get("content", "")
                for value in obj.get("sources", {}).values()
            )
        except json.JSONDecodeError:
            return raw
    return raw
