"""EVM Sentry — on-chain anomaly & risk scanner for Base and Ethereum contracts."""

from .engine import Scanner
from .models import Finding, ScanResult, Severity

__version__ = "0.1.0"
__all__ = ["Finding", "ScanResult", "Severity", "Scanner", "__version__"]
