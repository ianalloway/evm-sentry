"""Network client: JSON-RPC + Etherscan V2 explorer API.

Designed to degrade gracefully:
  * No network        -> warnings, empty context (scan still returns).
  * No explorer key    -> bytecode-only analysis (still useful).
  * Verified source    -> full source + ABI heuristics unlocked.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import requests

from . import bytecode as bc
from .config import ChainConfig, explorer_api_key
from .context import ContractContext

_RE_ADDRESS = None

# Query-string credentials (Etherscan ``apikey=``, ``api_key=``, ``token=`` …).
_RE_SECRET_PARAM = re.compile(
    r"(?i)\b(apikey|api_key|api-key|key|token|access_token|auth|secret)=([^&\s'\"#)]+)"
)
# ``scheme://user:pass@host`` credentials embedded in any URL.
_RE_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@'\"]+@")
# RPC providers (Alchemy ``/v2/<key>``, Infura ``/v3/<key>``, …) put the key
# in a path segment; treat any segment this long as a credential.
_MIN_PATH_SECRET_LEN = 16
REDACTED = "***REDACTED***"


def url_secrets(url: Optional[str]) -> List[str]:
    """Credential-bearing parts of a URL: userinfo and key-like path segments.

    Returned separately from the full URL because requests often reports only
    part of it (e.g. ``Max retries exceeded with url: /v2/<key>``).
    """
    if not url:
        return []
    try:
        parts = urlsplit(url)
        found = [parts.username, parts.password]
    except ValueError:
        return []
    found += [seg for seg in parts.path.split("/") if len(seg) >= _MIN_PATH_SECRET_LEN]
    return [p for p in found if p]


def redact_secrets(text: object, secrets: Iterable[Optional[str]] = ()) -> str:
    """Strip API keys from text destined for warnings, reports, or stderr.

    Masks key-like query parameters (``apikey=…``), URL userinfo, any literal
    secret passed in, the ``ETHERSCAN_API_KEY`` env value, and custom RPC URLs
    from ``EVM_SENTRY_RPC_*`` along with their credential-bearing parts.
    """
    out = str(text)
    literals = [s for s in secrets if s]
    env_key = os.environ.get("ETHERSCAN_API_KEY")
    if env_key:
        literals.append(env_key)
    for name, value in os.environ.items():
        if name.startswith("EVM_SENTRY_RPC_") and value:
            out = out.replace(value, f"${name}")
            literals.extend(url_secrets(value))
    # Longest first so a key that contains another key is fully masked.
    for secret in sorted(set(literals), key=len, reverse=True):
        out = out.replace(secret, REDACTED)
    out = _RE_URL_USERINFO.sub(lambda m: f"{m.group(1)}{REDACTED}@", out)
    return _RE_SECRET_PARAM.sub(lambda m: f"{m.group(1)}={REDACTED}", out)


def is_address(value: str) -> bool:
    import re
    global _RE_ADDRESS
    if _RE_ADDRESS is None:
        _RE_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
    return bool(_RE_ADDRESS.match(value.strip()))


class EVMClient:
    def __init__(
        self,
        chain: ChainConfig,
        api_key: Optional[str] = None,
        timeout: float = 20.0,
        session: Optional[requests.Session] = None,
    ):
        self.chain = chain
        self.api_key = api_key if api_key is not None else explorer_api_key()
        self.timeout = timeout
        self.session = session or requests.Session()
        self._rpc_id = 0

    # ---- low-level JSON-RPC ------------------------------------------------
    def rpc(self, method: str, params: List[Any]) -> Any:
        self._rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": method,
            "params": params,
        }
        resp = self.session.post(
            self.chain.rpc_url, json=payload, timeout=self.timeout
        )
        resp.raise_for_status()
        data = resp.json()
        if "error" in data:
            raise RuntimeError(f"RPC error for {method}: {data['error']}")
        return data.get("result")

    def get_code(self, address: str) -> str:
        return self.rpc("eth_getCode", [address, "latest"]) or "0x"

    def get_balance(self, address: str) -> int:
        result = self.rpc("eth_getBalance", [address, "latest"]) or "0x0"
        return int(result, 16)

    def get_storage_at(self, address: str, slot: str) -> str:
        return self.rpc("eth_getStorageAt", [address, slot, "latest"]) or "0x0"

    # ---- explorer (Etherscan V2 multichain) --------------------------------
    def explorer(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.api_key:
            return None
        q = dict(params)
        q["chainid"] = self.chain.chain_id
        q["apikey"] = self.api_key
        resp = self.session.get(
            self.chain.explorer_api, params=q, timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json()

    def get_source(self, address: str) -> Optional[Dict[str, Any]]:
        return self.explorer(
            {"module": "contract", "action": "getsourcecode", "address": address}
        )

    def get_creation(self, address: str) -> Optional[Dict[str, Any]]:
        return self.explorer(
            {
                "module": "contract",
                "action": "getcontractcreation",
                "contractaddresses": address,
            }
        )

    def get_block_number(self) -> int:
        result = self.rpc("eth_blockNumber", []) or "0x0"
        return int(result, 16)

    def get_logs(
        self,
        *,
        address: str,
        topics: List[str],
        from_block: int,
        to_block: int,
    ) -> List[Dict[str, Any]]:
        """Fetch logs. ``topics`` is OR'd at topic0 (common proxy events)."""
        result = self.rpc(
            "eth_getLogs",
            [
                {
                    "address": address,
                    "fromBlock": hex(from_block),
                    "toBlock": hex(to_block),
                    "topics": [topics],
                }
            ],
        )
        return result or []

    def get_block_timestamp(self, block_number: int) -> Optional[int]:
        result = self.rpc(
            "eth_getBlockByNumber", [hex(block_number), False]
        )
        if result and result.get("timestamp"):
            return int(result["timestamp"], 16)
        return None

    def redact(self, text: object) -> str:
        """Text with the explorer key, RPC URL credentials and other secrets masked."""
        return redact_secrets(text, [self.api_key, *url_secrets(self.chain.rpc_url)])

    def _safe(self, exc: object) -> str:
        return self.redact(exc)

    # ---- orchestration -----------------------------------------------------
    def build_context(self, address: str) -> ContractContext:
        address = address.strip()
        ctx = ContractContext(
            address=address,
            chain=self.chain.name,
            chain_id=self.chain.chain_id,
        )

        # 1. Bytecode + balance via RPC.
        try:
            ctx.bytecode = self.get_code(address)
            ctx.data_sources.append("rpc:eth_getCode")
        except Exception as exc:  # noqa: BLE001
            ctx.warnings.append(f"Could not fetch bytecode: {self._safe(exc)}")
            return ctx

        try:
            ctx.balance_wei = self.get_balance(address)
        except Exception as exc:  # noqa: BLE001
            ctx.warnings.append(f"Could not fetch balance: {self._safe(exc)}")

        if not ctx.is_contract:
            return ctx

        # 2. EIP-1967 / minimal-proxy detection from raw chain state.
        self._detect_proxy(ctx)

        # 3. Verified source + ABI (needs explorer key).
        self._enrich_from_explorer(ctx)

        return ctx

    def _detect_proxy(self, ctx: ContractContext) -> None:
        if bc.is_minimal_proxy(ctx.bytecode):
            ctx.proxy_kind = "minimal"
            ctx.proxy_implementation = bc.minimal_proxy_target(ctx.bytecode)
            return
        try:
            impl = bc.slot_to_address(
                self.get_storage_at(ctx.address, bc.SLOT_IMPLEMENTATION)
            )
            if impl:
                ctx.proxy_kind = "eip1967"
                ctx.proxy_implementation = impl
                ctx.data_sources.append("rpc:eip1967-slot")
                admin = bc.slot_to_address(
                    self.get_storage_at(ctx.address, bc.SLOT_ADMIN)
                )
                if admin:
                    ctx.proxy_admin = admin
        except Exception as exc:  # noqa: BLE001
            ctx.warnings.append(f"Proxy slot read failed: {self._safe(exc)}")

    def _enrich_from_explorer(self, ctx: ContractContext) -> None:
        if not self.api_key:
            ctx.warnings.append(
                "No explorer API key set (ETHERSCAN_API_KEY) — "
                "source/ABI heuristics skipped, bytecode analysis only."
            )
            return

        try:
            src = self.get_source(ctx.address)
        except Exception as exc:  # noqa: BLE001
            ctx.warnings.append(
                f"Explorer source lookup failed: {self._safe(exc)} — "
                "source/ABI heuristics skipped, bytecode analysis only."
            )
            return

        if not src:
            ctx.warnings.append("Explorer returned no source record.")
            return

        if str(src.get("status")) != "1" or not src.get("result"):
            ctx.warnings.append("Explorer returned no source record.")
            return

        ctx.data_sources.append("explorer:getsourcecode")
        rec = src["result"][0] if isinstance(src["result"], list) else src["result"]
        source_code = rec.get("SourceCode", "") or ""
        ctx.verified = bool(source_code.strip())
        ctx.contract_name = rec.get("ContractName", "") or ""
        ctx.compiler_version = rec.get("CompilerVersion", "") or ""
        ctx.source_code = _clean_source(source_code)

        abi_raw = rec.get("ABI", "")
        if abi_raw and abi_raw != "Contract source code not verified":
            try:
                ctx.abi = json.loads(abi_raw)
            except (json.JSONDecodeError, TypeError):
                pass

        # Explorer's own proxy flags
        if not ctx.proxy_implementation:
            impl = (rec.get("Implementation") or "").strip()
            if rec.get("Proxy") in ("1", 1) and is_address(impl):
                ctx.proxy_kind = ctx.proxy_kind or "explorer"
                ctx.proxy_implementation = impl

        # Creation provenance
        try:
            creation = self.get_creation(ctx.address)
            if creation and str(creation.get("status")) == "1":
                c = creation["result"][0]
                ctx.creator = c.get("contractCreator", "")
                ctx.creation_tx = c.get("txHash", "")
                blk = c.get("blockNumber")
                if blk:
                    ctx.creation_block = int(blk)
                    ts = self.get_block_timestamp(ctx.creation_block)
                    ctx.creation_timestamp = ts
                ctx.data_sources.append("explorer:getcontractcreation")
        except Exception as exc:  # noqa: BLE001
            ctx.warnings.append(f"Creation lookup failed: {self._safe(exc)}")


def _clean_source(raw: str) -> str:
    """Etherscan wraps multi-file source in a doubled-brace JSON blob."""
    s = raw.strip()
    if s.startswith("{{") and s.endswith("}}"):
        s = s[1:-1]
    if s.startswith("{") and '"sources"' in s:
        try:
            obj = json.loads(s)
            sources = obj.get("sources", {})
            return "\n\n".join(
                v.get("content", "") for v in sources.values()
            )
        except json.JSONDecodeError:
            return raw
    return raw
