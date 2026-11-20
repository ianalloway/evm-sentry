"""Compare the aggregate results of two previously exported JSON scans, offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from .models import Severity


def _summary(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(report, dict) or not all(
        isinstance(report.get(k), str) and report[k] and report[k].isprintable()
        for k in ("address", "chain", "risk_band")
    ):
        raise ValueError(f"{path}: expected a JSON scan report with address, chain and risk_band")
    score = report.get("risk_score")
    if "risk_score" not in report or (
        score is not None and (type(score) is not int or not 0 <= score <= 100)
    ):
        raise ValueError(f"{path}: risk_score must be an integer from 0 to 100 or null")
    counts = report.get("counts")
    if not isinstance(counts, dict) or not all(
        type(counts.get(s.label)) is int and counts[s.label] >= 0 for s in Severity
    ):
        raise ValueError(f"{path}: expected nonnegative counts for all severity levels")
    return report


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="evm-sentry compare", description="Compare two saved JSON scans for one address."
    )
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    try:
        old, new = _summary(args.before), _summary(args.after)
    except ValueError as exc:
        parser.exit(2, f"error: {exc}\n")
    if (old["chain"].lower(), old["address"].lower()) != (
        new["chain"].lower(), new["address"].lower()
    ):
        parser.exit(2, "error: both scans must describe the same chain and address\n")

    before, after = old["risk_score"], new["risk_score"]
    print(f"{new['chain']} · {new['address']}")
    print(f"Risk band: {old['risk_band']} -> {new['risk_band']}")
    if before is None or after is None:
        print("Score change unavailable: at least one scan is unassessed.")
        return 0
    print(f"Risk score: {before} -> {after} ({after - before:+d})")
    print("Observed findings by severity (before -> after)")
    for severity in reversed(list(Severity)):
        label = severity.label
        a, b = old["counts"][label], new["counts"][label]
        print(f"  {label:<8} {a} -> {b} ({b - a:+d})")
    return 0
