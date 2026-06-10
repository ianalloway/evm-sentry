"""Command-line interface for EVM Sentry."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .config import CHAINS
from .engine import Scanner
from .report import to_json, to_markdown, to_terminal


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="evm-sentry",
        description="On-chain anomaly & risk scanner for Base and Ethereum contracts.",
    )
    p.add_argument("address", help="0x contract address to scan")
    p.add_argument(
        "-c", "--chain", default="ethereum",
        help=f"Chain to scan. One of: {', '.join(CHAINS)} (default: ethereum)",
    )
    p.add_argument(
        "-f", "--format", default="terminal",
        choices=["terminal", "json", "markdown", "md"],
        help="Output format (default: terminal)",
    )
    p.add_argument(
        "-o", "--output", help="Write report to this file instead of stdout",
    )
    p.add_argument(
        "--api-key", default=None,
        help="Etherscan V2 API key (or set ETHERSCAN_API_KEY).",
    )
    p.add_argument(
        "--fail-on", default=None,
        choices=["low", "medium", "high", "critical"],
        help="Exit non-zero if risk band meets/exceeds this (for CI).",
    )
    p.add_argument("--version", action="version", version=f"evm-sentry {__version__}")
    return p


_BAND_ORDER = {"Minimal": 0, "N/A": 0, "Low": 1, "Elevated": 2, "High": 3, "Critical": 4}
_FAIL_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scanner = Scanner(chain=args.chain, api_key=args.api_key)
        result = scanner.scan_address(args.address)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: scan failed: {exc}", file=sys.stderr)
        return 2

    fmt = args.format
    if fmt in ("markdown", "md"):
        text = to_markdown(result)
    elif fmt == "json":
        text = to_json(result)
    else:
        text = to_terminal(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"Wrote {fmt} report to {args.output}", file=sys.stderr)
    else:
        print(text)

    if args.fail_on:
        if _BAND_ORDER.get(result.risk_band, 0) >= _FAIL_MAP[args.fail_on]:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
