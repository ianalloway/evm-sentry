"""Missing RPC data must not look like a successful zero-risk scan."""

import json

import pytest
import requests

from evm_sentry import cli, report
from evm_sentry.client import EVMClient
from evm_sentry.config import resolve_chain
from evm_sentry.engine import Scanner

ADDRESS = "0x" + "11" * 20


class _UnavailableSession:
    def post(self, *args, **kwargs):
        raise requests.ConnectionError("RPC unavailable")


def unavailable_client():
    return EVMClient(resolve_chain("base"), api_key="", session=_UnavailableSession())


def test_failed_lookup_does_not_classify_address_or_assign_risk():
    result = Scanner(chain="base", client=unavailable_client()).scan_address(ADDRESS)

    assert result.is_contract is None
    assert result.risk_score is None
    assert result.risk_band == "Unknown"
    assert result.metadata["bytecode_available"] is False
    assert [finding.id for finding in result.findings] == ["SCAN_INCOMPLETE"]
    payload = json.loads(report.to_json(result))
    assert payload["is_contract"] is None
    assert payload["risk_score"] is None
    for rendered in (report.to_markdown(result), report.to_terminal(result)):
        assert "Unassessed" in rendered
        assert "Unknown" in rendered
        assert "EOA" not in rendered
        assert "0/100" not in rendered


@pytest.mark.parametrize("value", [None, "", "0x0", "0xGG", 0, [], {}])
def test_invalid_rpc_bytecode_is_unavailable(monkeypatch, value):
    client = unavailable_client()
    monkeypatch.setattr(client, "rpc", lambda *args: value)

    result = Scanner(chain="base", client=client).scan_address(ADDRESS)

    assert result.risk_band == "Unknown"
    assert result.is_contract is None
    assert any("invalid bytecode" in warning for warning in result.warnings)


def test_successful_empty_bytecode_still_identifies_no_code(monkeypatch):
    client = unavailable_client()
    monkeypatch.setattr(client, "rpc", lambda *args: "0x")
    monkeypatch.setattr(client, "get_balance", lambda *args: 0)

    result = Scanner(chain="base", client=client).scan_address(ADDRESS)

    assert result.is_contract is False
    assert result.risk_band == "N/A"
    assert result.risk_score == 0


@pytest.mark.parametrize("extra", [[], ["--fail-on", "critical"]])
def test_incomplete_scan_exits_two_even_with_risk_threshold(monkeypatch, capsys, extra):
    scanner = Scanner(chain="base", client=unavailable_client())
    monkeypatch.setattr(cli, "Scanner", lambda **kwargs: scanner)

    assert cli.main([ADDRESS, "--format", "json", *extra]) == 2
    assert json.loads(capsys.readouterr().out)["risk_band"] == "Unknown"
