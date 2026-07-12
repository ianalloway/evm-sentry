"""Deterministic integration tests for the RPC/explorer client boundary."""

from evm_sentry import bytecode
from evm_sentry.client import EVMClient
from evm_sentry.config import resolve_chain


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self):
        self.posts = []
        self.gets = []

    def post(self, url, *, json, timeout):
        self.posts.append((url, json, timeout))
        method = json["method"]
        if method == "eth_getCode":
            result = "0x6001"
        elif method == "eth_getBalance":
            result = hex(123)
        elif method == "eth_getStorageAt":
            slot = json["params"][1]
            address = "11" * 20 if slot == bytecode.SLOT_IMPLEMENTATION else "22" * 20
            result = "0x" + "0" * 24 + address
        elif method == "eth_getBlockByNumber":
            result = {"timestamp": hex(1_700_000_000)}
        else:  # pragma: no cover - fails loudly for a new unexpected RPC call
            raise AssertionError(f"unexpected RPC method: {method}")
        return FakeResponse({"jsonrpc": "2.0", "id": json["id"], "result": result})

    def get(self, url, *, params, timeout):
        self.gets.append((url, params, timeout))
        if params["action"] == "getsourcecode":
            return FakeResponse(
                {
                    "status": "1",
                    "result": [
                        {
                            "SourceCode": "contract Demo {}",
                            "ContractName": "Demo",
                            "CompilerVersion": "v0.8.20",
                            "ABI": "[]",
                            "Proxy": "0",
                            "Implementation": "",
                        }
                    ],
                }
            )
        if params["action"] == "getcontractcreation":
            return FakeResponse(
                {
                    "status": "1",
                    "result": [
                        {
                            "contractCreator": "0x" + "33" * 20,
                            "txHash": "0xabc",
                            "blockNumber": "123",
                        }
                    ],
                }
            )
        raise AssertionError(f"unexpected explorer action: {params['action']}")


def test_build_context_crosses_rpc_and_explorer_boundaries():
    session = FakeSession()
    client = EVMClient(resolve_chain("base"), api_key="test-key", session=session)

    ctx = client.build_context("0x" + "aa" * 20)

    assert ctx.is_contract
    assert ctx.balance_wei == 123
    assert ctx.contract_name == "Demo"
    assert ctx.verified is True
    assert ctx.abi == []
    assert ctx.proxy_kind == "eip1967"
    assert ctx.proxy_implementation == "0x" + "11" * 20
    assert ctx.proxy_admin == "0x" + "22" * 20
    assert ctx.creator == "0x" + "33" * 20
    assert ctx.creation_block == 123
    assert ctx.creation_timestamp == 1_700_000_000
    assert "rpc:eth_getCode" in ctx.data_sources
    assert "rpc:eip1967-slot" in ctx.data_sources
    assert "explorer:getsourcecode" in ctx.data_sources
    assert "explorer:getcontractcreation" in ctx.data_sources
    assert len(session.posts) == 5
    assert len(session.gets) == 2


def test_build_context_skips_explorer_without_key():
    session = FakeSession()
    client = EVMClient(resolve_chain("ethereum"), api_key="", session=session)

    ctx = client.build_context("0x" + "bb" * 20)

    assert ctx.is_contract
    assert session.gets == []
    assert any("No explorer API key" in warning for warning in ctx.warnings)
