"""Upgrade/admin event timelines for common EIP-1967 proxy events."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from .client import EVMClient, is_address
from .config import ChainConfig

EVENT_TOPICS = {
    "Upgraded(address)": "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
    "AdminChanged(address,address)": "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
    "BeaconUpgraded(address)": "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e",
}
_TOPIC_TO_EVENT = {topic: event for event, topic in EVENT_TOPICS.items()}


@dataclass(frozen=True)
class TimelineEvent:
    event: str
    block_number: int
    transaction_hash: str
    log_index: int
    values: dict[str, str]


@dataclass(frozen=True)
class TimelineReport:
    chain: str
    chain_id: int
    address: str
    explorer_url: str
    from_block: int
    to_block: int
    events: list[TimelineEvent]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def topic_address(topic: str | None) -> str | None:
    if not topic:
        return None
    raw = topic.removeprefix("0x")
    if len(raw) != 64:
        return None
    return "0x" + raw[-40:]


def _data_addresses(data: str) -> list[str]:
    raw = data.removeprefix("0x")
    return [
        "0x" + raw[offset + 24 : offset + 64]
        for offset in range(0, len(raw), 64)
        if len(raw[offset : offset + 64]) == 64
    ]


def decode_log(log: dict[str, Any]) -> TimelineEvent | None:
    topics = [str(topic).lower() for topic in log.get("topics", [])]
    if not topics:
        return None
    event = _TOPIC_TO_EVENT.get(topics[0])
    if not event:
        return None

    values: dict[str, str] = {}
    if event == "Upgraded(address)":
        implementation = topic_address(topics[1] if len(topics) > 1 else None)
        if implementation:
            values["implementation"] = implementation
    elif event == "BeaconUpgraded(address)":
        beacon = topic_address(topics[1] if len(topics) > 1 else None)
        if beacon:
            values["beacon"] = beacon
    else:
        addresses = _data_addresses(str(log.get("data", "0x")))
        if len(addresses) >= 2:
            values["previous_admin"] = addresses[0]
            values["new_admin"] = addresses[1]

    return TimelineEvent(
        event=event,
        block_number=int(str(log.get("blockNumber", "0x0")), 16),
        transaction_hash=str(log.get("transactionHash", "")),
        log_index=int(str(log.get("logIndex", "0x0")), 16),
        values=values,
    )


def scan_timeline(
    address: str,
    chain: ChainConfig,
    *,
    client: EVMClient | None = None,
    from_block: int | None = None,
    to_block: int | None = None,
    lookback: int = 1_000,
) -> TimelineReport:
    """Fetch and decode proxy upgrade/admin events for a bounded block range."""
    if not is_address(address):
        raise ValueError("address must be a 20-byte hex address")
    if lookback < 1:
        raise ValueError("lookback must be positive")

    rpc = client or EVMClient(chain)
    latest = rpc.get_block_number()
    end = min(latest, latest if to_block is None else to_block)
    start = max(0, end - lookback if from_block is None else from_block)
    if start > end:
        raise ValueError("from_block must be less than or equal to to_block")

    logs = rpc.get_logs(
        address=address,
        topics=list(EVENT_TOPICS.values()),
        from_block=start,
        to_block=end,
    )
    events = [event for event in map(decode_log, logs) if event is not None]
    events.sort(key=lambda item: (item.block_number, item.log_index))

    return TimelineReport(
        chain=chain.name,
        chain_id=chain.chain_id,
        address=address,
        explorer_url=f"{chain.explorer_url}/address/{address}",
        from_block=start,
        to_block=end,
        events=events,
    )


def to_json(report: TimelineReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)


def to_markdown(report: TimelineReport) -> str:
    lines = [
        f"# Upgrade/Admin Timeline: `{report.address}`",
        "",
        f"- Chain: `{report.chain}` ({report.chain_id})",
        f"- Explorer: {report.explorer_url}",
        f"- Block range: `{report.from_block}` to `{report.to_block}`",
        f"- Events found: `{len(report.events)}`",
        "",
        "## Events",
        "",
    ]

    if not report.events:
        lines.append("No tracked upgrade/admin events were found in this block range.")
    else:
        for event in report.events:
            values = ", ".join(
                f"`{key}`: `{value}`" for key, value in event.values.items()
            )
            lines.extend(
                [
                    f"### {event.event}",
                    "",
                    f"- Block: `{event.block_number}`",
                    f"- Transaction: `{event.transaction_hash}`",
                    f"- Values: {values or '`not decoded`'}",
                    "",
                ]
            )

    lines.extend(
        [
            "## Notes",
            "",
            "- Uses public `eth_getLogs` data for common EIP-1967/OpenZeppelin events.",
            "- The default 1,000-block lookback avoids common public-RPC range limits.",
            "- No matching events does not prove a contract is immutable or safe.",
        ]
    )
    return "\n".join(lines) + "\n"
