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
