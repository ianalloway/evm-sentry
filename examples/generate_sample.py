"""Generate the illustrative reports under ``examples/``.

The sample uses a hand-built ``ContractContext`` and never touches the network.
Run it after installing the package:

    python examples/generate_sample.py
"""

from pathlib import Path
import time

from evm_sentry import report
from evm_sentry.context import ContractContext
from evm_sentry.engine import Scanner

EXAMPLES_DIR = Path(__file__).resolve().parent

RISKY_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract MoonRocketToken is Ownable, UUPSUpgradeable {
    mapping(address => bool) public isBlacklisted;
    bool public tradingEnabled;
    uint256 public sellFee;
    uint256 public maxTxAmount;

    function setSellFee(uint256 f) external onlyOwner { sellFee = f; }
    function enableTrading() external onlyOwner { tradingEnabled = true; }
    function blacklist(address a) external onlyOwner { isBlacklisted[a] = true; }
    function mint(address to, uint256 amt) external onlyOwner { /* ... */ }
    function withdraw() external onlyOwner { /* ... */ }
}
"""


def build_context() -> ContractContext:
    """Return a representative risky token context."""
    return ContractContext(
        address="0x0000000000000000000000000000000000000bad",
        chain="base",
        chain_id=8453,
        bytecode="0x60806040ff",  # toy bytecode containing SELFDESTRUCT
        balance_wei=12_500_000_000_000_000,
        verified=True,
        contract_name="MoonRocketToken",
        compiler_version="v0.8.20+commit.a1b79de6",
        source_code=RISKY_SOURCE,
        proxy_kind="eip1967",
        proxy_implementation="0x000000000000000000000000000000000000cafe",
        proxy_admin="0x000000000000000000000000000000000000ad01",
        creator="0x000000000000000000000000000000000000de10",
        creation_timestamp=int(time.time()) - 18 * 3600,
        data_sources=[
            "rpc:eth_getCode",
            "rpc:eip1967-slot",
            "explorer:getsourcecode",
            "explorer:getcontractcreation",
        ],
    )


def main() -> None:
    result = Scanner(chain="base").scan_context(build_context())
    (EXAMPLES_DIR / "sample_report.md").write_text(
        report.to_markdown(result) + "\n", encoding="utf-8"
    )
    (EXAMPLES_DIR / "sample_report.json").write_text(
        report.to_json(result) + "\n", encoding="utf-8"
    )
    print(report.to_terminal(result))
    print(f"\nScore: {result.risk_score}/100 ({result.risk_band})")


if __name__ == "__main__":
    main()
