"""Core data models for EVM Sentry."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value = more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


# Risk-score weight contributed by a single finding of each severity.
SEVERITY_WEIGHT: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


@dataclass
class Finding:
    """A single risk signal produced by a check."""

    id: str                       # stable machine id, e.g. "PROXY_UPGRADEABLE"
    title: str                    # human-readable summary
    severity: Severity
    check: str                    # name of the check that produced this
    description: str = ""         # what it means / why it matters
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d


@dataclass
class ScanResult:
    """Aggregated output of a full scan."""

    address: str
    chain: str
    is_contract: bool
    risk_score: int = 0           # 0-100, clamped
    risk_band: str = "Unknown"    # Minimal / Low / Elevated / High / Critical
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def add(self, finding: Optional[Finding]) -> None:
        if finding is not None:
            self.findings.append(finding)

    @property
    def counts(self) -> Dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "chain": self.chain,
            "is_contract": self.is_contract,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "counts": self.counts,
            "findings": [f.to_dict() for f in sorted(
                self.findings, key=lambda x: x.severity, reverse=True)],
            "metadata": self.metadata,
            "warnings": self.warnings,
        }
