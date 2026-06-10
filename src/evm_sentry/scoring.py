"""Risk scoring: convert findings into a 0-100 score and a band label."""

from __future__ import annotations

from typing import List, Tuple

from .models import SEVERITY_WEIGHT, Finding

BANDS: List[Tuple[int, str]] = [
    (75, "Critical"),
    (50, "High"),
    (25, "Elevated"),
    (1, "Low"),
    (0, "Minimal"),
]


def score(findings: List[Finding]) -> Tuple[int, str]:
    total = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    total = max(0, min(100, total))
    band = next(name for threshold, name in BANDS if total >= threshold)
    return total, band
