"""Malformed explorer responses must warn, never swallow or crash (C1, C2)."""

from evm_sentry.client import EVMClient
from evm_sentry.config import resolve_chain

ADDR = "0x" + "ab" * 20
KEY = "TESTKEY123"


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeSession:
    """RPC returns a tiny contract; explorer GETs return a canned payload."""

    def __init__(self, source_payload):
        self._source_payload = source_payload

    def post(self, url, json=None, timeout=None):
        method = json["method"]
        result = {
            "eth_getCode": "0x6001600055",
            "eth_getBalance": "0x0",
            "eth_getStorageAt": "0x" + "00" * 32,
        }.get(method)
        return _FakeResp({"jsonrpc": "2.0", "id": json["id"], "result": result})

    def get(self, url, params=None, timeout=None):
        if params and params.get("action") == "getsourcecode":
            return _FakeResp(self._source_payload)
        # No creation data; the scan must not depend on it.
        return _FakeResp({"status": "0", "message": "No records found", "result": []})


def _client(source_payload):
    return EVMClient(
        chain=resolve_chain("ethereum"),
        api_key=KEY,
        session=_FakeSession(source_payload),
    )


def _verified_record(**overrides):
    record = {
        "SourceCode": "contract Foo { function foo() public {} }",
        "ContractName": "Foo",
        "CompilerVersion": "v0.8.0+commit.c7dfd78e",
        "ABI": "[]",
        "Proxy": "0",
        "Implementation": "",
    }
    record.update(overrides)
    return {"status": "1", "message": "OK", "result": [record]}


def test_malformed_abi_warns_instead_of_silently_skipping():
    # C1: the ABI is not valid JSON. Previously this was swallowed by
    # `except (JSONDecodeError, TypeError): pass` and the contract was
    # still reported verified with no trace that ABI checks never ran.
    payload = _verified_record(ABI="{not valid json")
    ctx = _client(payload).build_context(ADDR)

    assert ctx.verified is True
    assert ctx.abi == []
    assert any("malformed ABI" in w for w in ctx.warnings)


def test_malformed_source_record_warns_instead_of_crashing():
    # C2: the explorer source record is a string, not an object, so
    # `rec.get(...)` used to raise AttributeError and kill the scan.
    payload = {"status": "1", "message": "OK", "result": ["not-a-record"]}
    ctx = _client(payload).build_context(ADDR)

    assert ctx.verified is False
    assert any("malformed source record" in w for w in ctx.warnings)
