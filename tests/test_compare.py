"""Regression coverage for the offline saved-report CLI."""
import json

import pytest

from evm_sentry.cli import main
from evm_sentry.models import Finding, ScanResult, Severity


def test_compare_saved_reports(tmp_path, capsys):
    address = "0x" + "ab" * 20
    result = ScanResult(address, "base", True, 0, "Minimal")
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(result.to_dict()))
    result.address = address.upper()
    result.add(Finding("NOTICE", "Notice", Severity.LOW, "example"))
    result.risk_score, result.risk_band = 5, "Low"
    after.write_text(json.dumps(result.to_dict()))
    assert main(["compare", str(before), str(after)]) == 0
    text = capsys.readouterr().out
    assert "0 -> 5 (+5)" in text
    assert "Low      0 -> 1 (+1)" in text

    result.risk_score, result.risk_band, result.is_contract = None, "Unknown", None
    after.write_text(json.dumps(result.to_dict()))
    assert main(["compare", str(before), str(after)]) == 0
    text = capsys.readouterr().out
    assert "Minimal -> Unknown" in text
    assert "change unavailable" in text
    assert "by severity" not in text


@pytest.mark.parametrize("change", [{"chain": "ethereum"}, {"address": "different"},
                                    {"counts": {}}, {"risk_score": True}])
def test_compare_rejects_incompatible_reports(tmp_path, capsys, change):
    a, b = tmp_path / "a", tmp_path / "b"
    data = ScanResult("0x" + "1" * 40, "base", True, 0, "Minimal").to_dict()
    a.write_text(json.dumps(data))
    b.write_text(json.dumps({**data, **change}))
    with pytest.raises(SystemExit) as error:
        main(["compare", str(a), str(b)])
    assert error.value.code == 2
    assert capsys.readouterr().out == ""
