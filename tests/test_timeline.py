from __future__ import annotations

import json

import pytest

from evm_sentry.cli import main
from evm_sentry.config import CHAINS
from evm_sentry.timeline import TimelineEvent, TimelineReport, decode_log, scan_timeline, topic_address

ADDRESS = "0x" + "a" * 40
UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
ADMIN_TOPIC = "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f"


def test_topic_address_decodes_indexed_address() -> None:
    topic = "0x" + "0" * 24 + "1234567890abcdef1234567890abcdef12345678"
    assert topic_address(topic) == "0x1234567890abcdef1234567890abcdef12345678"


def test_topic_address_rejects_malformed_topic() -> None:
    assert topic_address("0x1234") is None


def test_decode_upgrade_and_admin_events() -> None:
    upgraded = decode_log(
        {
            "topics": [UPGRADED_TOPIC, "0x" + "0" * 24 + "1" * 40],
            "blockNumber": "0x10",
            "transactionHash": "0xabc",
            "logIndex": "0x2",
            "data": "0x",
        }
    )
    assert upgraded is not None
    assert upgraded.block_number == 16
    assert upgraded.values["implementation"] == "0x" + "1" * 40

    admin = decode_log(
        {
            "topics": [ADMIN_TOPIC],
            "blockNumber": "0x20",
            "transactionHash": "0xdef",
            "logIndex": "0x0",
            "data": "0x" + "0" * 24 + "2" * 40 + "0" * 24 + "3" * 40,
        }
    )
    assert admin is not None
    assert admin.values == {
        "previous_admin": "0x" + "2" * 40,
        "new_admin": "0x" + "3" * 40,
    }


class FakeClient:
    def __init__(self) -> None:
        self.request = None

    def get_block_number(self) -> int:
        return 10_000

    def get_logs(self, **kwargs):
        self.request = kwargs
        return [
            {
                "topics": [UPGRADED_TOPIC, "0x" + "0" * 24 + "1" * 40],
                "blockNumber": "0x2329",
                "transactionHash": "0xlate",
                "logIndex": "0x2",
                "data": "0x",
            },
            {
                "topics": [UPGRADED_TOPIC, "0x" + "0" * 24 + "2" * 40],
                "blockNumber": "0x2328",
                "transactionHash": "0xearly",
                "logIndex": "0x1",
                "data": "0x",
            },
        ]


def test_scan_timeline_bounds_range_and_sorts_events() -> None:
    client = FakeClient()
    report = scan_timeline(ADDRESS, CHAINS["base"], client=client, lookback=1_000)

    assert report.from_block == 9_000
    assert report.to_block == 10_000
    assert [event.transaction_hash for event in report.events] == ["0xearly", "0xlate"]
    assert client.request["from_block"] == 9_000
    assert client.request["to_block"] == 10_000


def test_scan_timeline_validates_range() -> None:
    with pytest.raises(ValueError, match="from_block"):
        scan_timeline(
            ADDRESS,
            CHAINS["base"],
            client=FakeClient(),
            from_block=10_001,
            to_block=10_000,
        )


def test_timeline_cli_json(monkeypatch, capsys) -> None:
    report = TimelineReport(
        chain="base",
        chain_id=8453,
        address=ADDRESS,
        explorer_url=f"https://basescan.org/address/{ADDRESS}",
        from_block=1,
        to_block=2,
        events=[
            TimelineEvent(
                event="Upgraded(address)",
                block_number=2,
                transaction_hash="0xabc",
                log_index=0,
                values={"implementation": "0x" + "1" * 40},
            )
        ],
    )
    monkeypatch.setattr("evm_sentry.cli.scan_timeline", lambda *args, **kwargs: report)

    assert main(["timeline", ADDRESS, "--chain", "base", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["events"][0]["event"] == "Upgraded(address)"


def test_scan_cli_remains_backward_compatible(monkeypatch, capsys) -> None:
    class Result:
        risk_band = "Minimal"

    monkeypatch.setattr("evm_sentry.cli.Scanner.scan_address", lambda self, address: Result())
    monkeypatch.setattr("evm_sentry.cli.to_terminal", lambda result: "ok")

    assert main([ADDRESS, "--chain", "base"]) == 0
    assert capsys.readouterr().out == "ok\n"
