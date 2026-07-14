"""Proxy upgrade / admin timeline from eth_getLogs (ported from onchain-risk-scanner)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from .client import EVMClient
from .config import ChainConfig

EVENT_TOPICS = {
    "Upgraded(address)": "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
    "AdminChanged(address,address)": "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
    "BeaconUpgraded(address)": "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e",
}

TOPIC_TO_EVENT = {topic: event for event, topic in EVENT_TOPICS.items()}


@dataclass(frozen=True)
class TimelineEvent:
    event: str
    block_number: int
    transaction_hash: str
    log_index: int
    values: Dict[str, str]


@dataclass
class TimelineReport:
    chain: str
    chain_id: int
    address: str
    explorer_url: str
    from_block: int
    to_block: int
    events: List[TimelineEvent]
    notes: List[str]

    def to_dict(self) -> dict:
        return asdict(self)


def topic_address(topic: Optional[str]) -> Optional[str]:
    if not topic:
        return None
    raw = topic[2:] if topic.startswith("0x") else topic
    if len(raw) < 40:
        return None
    return "0x" + raw[-40:]


def data_addresses(data: str) -> List[str]:
    raw = data[2:] if data.startswith("0x") else data
    if not raw:
        return []
    return [
        "0x" + raw[i + 24 : i + 64]
        for i in range(0, len(raw), 64)
        if len(raw[i : i + 64]) == 64
    ]


def decode_log(log: dict) -> Optional[TimelineEvent]:
    topics = [str(topic).lower() for topic in log.get("topics", [])]
    if not topics:
        return None
    event = TOPIC_TO_EVENT.get(topics[0])
    if not event:
        return None

    values: Dict[str, str] = {}
    if event == "Upgraded(address)":
        implementation = topic_address(topics[1] if len(topics) > 1 else None)
        if implementation:
            values["implementation"] = implementation
    elif event == "BeaconUpgraded(address)":
        beacon = topic_address(topics[1] if len(topics) > 1 else None)
        if beacon:
            values["beacon"] = beacon
    elif event == "AdminChanged(address,address)":
        decoded = data_addresses(str(log.get("data", "0x")))
        if len(decoded) >= 2:
            values["previous_admin"] = decoded[0]
            values["new_admin"] = decoded[1]

    return TimelineEvent(
        event=event,
        block_number=int(str(log.get("blockNumber", "0x0")), 16),
        transaction_hash=str(log.get("transactionHash", "")),
        log_index=int(str(log.get("logIndex", "0x0")), 16),
        values=values,
    )


def scan_timeline(
    client: EVMClient,
    address: str,
    *,
    from_block: Optional[int] = None,
    to_block: Optional[int] = None,
    lookback: int = 1_000,
) -> TimelineReport:
    chain: ChainConfig = client.chain
    latest = client.get_block_number()
    end = min(to_block if to_block is not None else latest, latest)
    start = max(0, from_block if from_block is not None else end - lookback)

    logs = client.get_logs(
        address=address,
        topics=list(EVENT_TOPICS.values()),
        from_block=start,
        to_block=end,
    )
    events = [e for e in (decode_log(log) for log in logs) if e is not None]
    events.sort(key=lambda e: (e.block_number, e.log_index))

    return TimelineReport(
        chain=chain.name,
        chain_id=chain.chain_id,
        address=address,
        explorer_url=f"{chain.explorer_url}/address/{address}",
        from_block=start,
        to_block=end,
        events=events,
        notes=[
            "Timeline uses public eth_getLogs for common EIP-1967/OpenZeppelin proxy events.",
            f"Default lookback is {lookback} blocks to stay within public RPC limits.",
            "No events in range does not prove a contract is immutable or safe.",
        ],
    )


def render_timeline_markdown(report: TimelineReport) -> str:
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
            values = ", ".join(f"`{key}`: `{value}`" for key, value in event.values.items())
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
    lines.extend(["", "## Notes", ""])
    for note in report.notes:
        lines.append(f"- {note}")
    return "\n".join(lines) + "\n"


def render_timeline_terminal(report: TimelineReport) -> str:
    lines = [
        f"Timeline {report.address} on {report.chain}",
        f"Blocks {report.from_block}..{report.to_block} — {len(report.events)} event(s)",
        "",
    ]
    if not report.events:
        lines.append("(no Upgraded / AdminChanged / BeaconUpgraded events in range)")
    for event in report.events:
        values = ", ".join(f"{k}={v}" for k, v in event.values.items()) or "—"
        lines.append(
            f"  blk {event.block_number}  {event.event}  {values}  tx={event.transaction_hash[:18]}…"
        )
    return "\n".join(lines)
