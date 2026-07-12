"""Command-line interface for EVM Sentry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import CHAINS, resolve_chain
from .engine import Scanner
from .report import to_json, to_markdown, to_terminal
from .timeline import (
    scan_timeline,
    to_json as timeline_json,
    to_markdown as timeline_markdown,
)

_BAND_ORDER = {
    "Minimal": 0,
    "N/A": 0,
    "Low": 1,
    "Elevated": 2,
    "High": 3,
    "Critical": 4,
}
_FAIL_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def build_parser() -> argparse.ArgumentParser:
    """Build the backward-compatible contract scan parser."""
    parser = argparse.ArgumentParser(
        prog="evm-sentry",
        description="On-chain anomaly & risk scanner for EVM contracts.",
    )
    parser.add_argument("address", help="0x contract address to scan")
    parser.add_argument(
        "-c",
        "--chain",
        default="ethereum",
        help=f"Chain to scan. One of: {', '.join(CHAINS)} (default: ethereum)",
    )
    parser.add_argument(
        "-f",
        "--format",
        default="terminal",
        choices=["terminal", "json", "markdown", "md"],
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the report instead of printing it",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Etherscan V2 API key (or set ETHERSCAN_API_KEY)",
    )
    parser.add_argument(
        "--fail-on",
        default=None,
        choices=list(_FAIL_MAP),
        help="Exit non-zero if the risk band meets or exceeds this level",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"evm-sentry {__version__}",
    )
    return parser


def build_timeline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evm-sentry timeline",
        description="Build a proxy upgrade/admin event timeline.",
    )
    parser.add_argument("address", help="0x contract address to inspect")
    parser.add_argument(
        "-c",
        "--chain",
        default="ethereum",
        help=f"Chain to scan. One of: {', '.join(CHAINS)} (default: ethereum)",
    )
    parser.add_argument("--from-block", type=int)
    parser.add_argument("--to-block", type=int)
    parser.add_argument("--lookback", type=int, default=1_000)
    parser.add_argument(
        "-f",
        "--format",
        choices=["markdown", "md", "json"],
        default="markdown",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the timeline instead of printing it",
    )
    return parser


def _write(text: str, output: str | None, label: str) -> None:
    if output:
        suffix = "" if text.endswith("\n") else "\n"
        Path(output).write_text(text + suffix, encoding="utf-8")
        print(f"Wrote {label} to {output}", file=sys.stderr)
    else:
        print(text, end="" if text.endswith("\n") else "\n")


def _scan(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = Scanner(chain=args.chain, api_key=args.api_key).scan_address(
            args.address
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 2

    if args.format in ("markdown", "md"):
        text = to_markdown(result)
    elif args.format == "json":
        text = to_json(result)
    else:
        text = to_terminal(result)
    _write(text, args.output, f"{args.format} report")

    threshold = _FAIL_MAP.get(args.fail_on)
    if threshold is not None and _BAND_ORDER.get(result.risk_band, 0) >= threshold:
        return 1
    return 0


def _timeline(argv: list[str]) -> int:
    args = build_timeline_parser().parse_args(argv)
    try:
        report = scan_timeline(
            args.address,
            resolve_chain(args.chain),
            from_block=args.from_block,
            to_block=args.to_block,
            lookback=args.lookback,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: timeline failed: {exc}", file=sys.stderr)
        return 2

    text = (
        timeline_json(report)
        if args.format == "json"
        else timeline_markdown(report)
    )
    _write(text, args.output, f"{args.format} timeline")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:1] == ["timeline"]:
        return _timeline(raw[1:])
    return _scan(raw)


if __name__ == "__main__":
    raise SystemExit(main())
