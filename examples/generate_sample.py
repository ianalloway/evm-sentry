"""Generate the illustrative sample reports committed under examples/.

Uses a hand-built ContractContext so it runs offline and deterministically.
On a machine with network access you'd instead run:

    evm-sentry 0x... --chain base --format markdown -o report.md
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from evm_sentry import report
from evm_sentry.context import ContractContext
from evm_sentry.engine import Scanner

# A representative "risky token" context (illustrative, not a real address).
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
    return ContractContext(
        address="0xEXAMPLE000000000000000000000000000000bAd",
        chain="base",
        chain_id=8453,
        bytecode="0x60806040" + "ff",  # toy bytecode incl. SELFDESTRUCT
        balance_wei=12_500_000_000_000_000,  # 0.0125 ETH
        verified=True,
        contract_name="MoonRocketToken",
        compiler_version="v0.8.20+commit.a1b79de6",
        source_code=RISKY_SOURCE,
        proxy_kind="eip1967",
        proxy_implementation="0xC0ffee000000000000000000000000000000Cafe",
        proxy_admin="0xAdm1n0000000000000000000000000000000000",
        creator="0xDep10y3r00000000000000000000000000000000",
        creation_timestamp=int(time.time()) - 18 * 3600,  # 18h old
        data_sources=["rpc:eth_getCode", "rpc:eip1967-slot",
                      "explorer:getsourcecode", "explorer:getcontractcreation"],
    )


def main():
    here = os.path.dirname(__file__)
    scanner = Scanner(chain="base", client=_Offline())
    result = scanner.scan_context(build_context())

    with open(os.path.join(here, "sample_report.md"), "w") as f:
        f.write(report.to_markdown(result) + "\n")
    with open(os.path.join(here, "sample_report.json"), "w") as f:
        f.write(report.to_json(result) + "\n")
    print(report.to_terminal(result))
    print(f"\nScore: {result.risk_score}/100 ({result.risk_band})")


class _Offline:
    """No-op client so Scanner() builds without a network client."""


if __name__ == "__main__":
    main()
