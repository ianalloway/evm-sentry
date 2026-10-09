"""Explorer API keys must never leak into warnings, reports, or errors."""

import requests

from evm_sentry import report
from evm_sentry.client import REDACTED, EVMClient, redact_secrets
from evm_sentry.config import resolve_chain
from evm_sentry.engine import Scanner

KEY = "SUPERSECRETKEY123"
ADDR = "0x" + "ab" * 20
LEAKY_URL = (
    "https://api.etherscan.io/v2/api?module=contract&action=getsourcecode"
    f"&address={ADDR}&chainid=1&apikey={KEY}"
)


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class _FakeSession:
    """RPC returns a tiny contract; every explorer GET fails with the URL in the text."""

    def post(self, url, json=None, timeout=None):
        method = json["method"]
        result = {
            "eth_getCode": "0x6001600055",
            "eth_getBalance": "0x0",
            "eth_getStorageAt": "0x" + "00" * 32,
        }.get(method)
        return _FakeResp({"jsonrpc": "2.0", "id": json["id"], "result": result})

    def get(self, url, params=None, timeout=None):
        raise requests.HTTPError(f"500 Server Error: Internal Server Error for url: {LEAKY_URL}")


def _client(api_key):
    return EVMClient(chain=resolve_chain("ethereum"), api_key=api_key, session=_FakeSession())


def test_redact_secrets_masks_query_params_and_literals():
    text = f"boom for url: {LEAKY_URL} (key {KEY})"
    out = redact_secrets(text, [KEY])
    assert KEY not in out
    assert f"apikey={REDACTED}" in out
    assert redact_secrets("x?api_key=abc&token=def") == (
        f"x?api_key={REDACTED}&token={REDACTED}"
    )


def test_explorer_failure_warning_is_redacted_and_not_misreported(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    ctx = _client(KEY).build_context(ADDR)

    joined = "\n".join(ctx.warnings)
    assert KEY not in joined
    assert "Explorer source lookup failed" in joined
    # A key *is* configured, so we must not claim it is missing.
    assert "No explorer API key set" not in joined

    result = Scanner(chain="ethereum", client=_client(KEY)).scan_context(ctx)
    for rendered in (report.to_json(result), report.to_markdown(result), report.to_terminal(result)):
        assert KEY not in rendered


def test_report_redacts_env_key_in_warnings(monkeypatch):
    monkeypatch.setenv("ETHERSCAN_API_KEY", KEY)
    ctx = _client(None).build_context(ADDR)  # picks up env key
    ctx.warnings.append(f"some upstream error mentioning {KEY}")
    result = Scanner(chain="ethereum", client=_client(None)).scan_context(ctx)
    for rendered in (report.to_json(result), report.to_markdown(result), report.to_terminal(result)):
        assert KEY not in rendered


def test_missing_key_warning_only_when_no_key(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    ctx = _client(None).build_context(ADDR)
    assert any("No explorer API key set" in w for w in ctx.warnings)
    assert not any("Explorer source lookup failed" in w for w in ctx.warnings)


RPC_KEY = "alchemyKey0123456789abcdef"
RPC_URL = f"https://eth-mainnet.g.alchemy.com/v2/{RPC_KEY}"


class _ExplorerHTTP4xxSession(_FakeSession):
    """Explorer answers 401; requests' real raise_for_status builds the error text."""

    def get(self, url, params=None, timeout=None):
        resp = requests.Response()
        resp.status_code = 401
        resp.reason = "Unauthorized"
        resp.url = requests.Request("GET", url, params=params).prepare().url
        return resp


class _RPCDownSession(_FakeSession):
    """RPC connection failure: requests reports only the path, which holds the key."""

    def post(self, url, json=None, timeout=None):
        raise requests.ConnectionError(
            "HTTPSConnectionPool(host='eth-mainnet.g.alchemy.com', port=443): "
            f"Max retries exceeded with url: /v2/{RPC_KEY} (Caused by NewConnectionError)"
        )


def _render_all(result):
    return (report.to_json(result), report.to_markdown(result), report.to_terminal(result))


def test_explorer_4xx_with_apikey_in_url_produces_report_without_key(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    client = EVMClient(
        chain=resolve_chain("ethereum"), api_key=KEY, session=_ExplorerHTTP4xxSession()
    )
    ctx = client.build_context(ADDR)
    assert any("401 Client Error" in w for w in ctx.warnings)
    assert KEY not in "\n".join(ctx.warnings)
    result = Scanner(chain="ethereum", client=client).scan_context(ctx)
    for rendered in _render_all(result):
        assert KEY not in rendered


def test_rpc_error_with_key_in_url_path_is_redacted(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    monkeypatch.setenv("EVM_SENTRY_RPC_ETHEREUM", RPC_URL)
    client = EVMClient(chain=resolve_chain("ethereum"), api_key=None, session=_RPCDownSession())
    ctx = client.build_context(ADDR)
    assert any("Could not fetch bytecode" in w for w in ctx.warnings)
    assert RPC_KEY not in "\n".join(ctx.warnings)
    # Reports also redact on their own, even for warnings that bypassed the client.
    ctx.warnings.append(f"upstream: Max retries exceeded with url: /v2/{RPC_KEY}")
    result = Scanner(chain="ethereum", client=client).scan_context(ctx)
    for rendered in _render_all(result):
        assert RPC_KEY not in rendered


def test_redact_secrets_masks_url_userinfo():
    out = redact_secrets("failed for url: https://user:hunter2pass@rpc.example.org/x")
    assert "hunter2pass" not in out
    assert f"https://{REDACTED}@rpc.example.org/x" in out


def test_check_exception_text_is_redacted_before_entering_warnings(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)

    def leaky_check(ctx):
        raise RuntimeError(f"lookup failed for url: {LEAKY_URL}")

    client = _client(KEY)
    ctx = client.build_context(ADDR)
    result = Scanner(chain="ethereum", client=client, checks=[leaky_check]).scan_context(ctx)
    joined = "\n".join(result.warnings)
    assert "leaky_check" in joined
    assert KEY not in joined
