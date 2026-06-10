from evm_sentry import report
from evm_sentry.context import ContractContext
from evm_sentry.engine import Scanner


def make_scanner():
    # client=None is fine; we only call scan_context (no network).
    return Scanner(chain="base", client=_NoNetClient())


class _NoNetClient:
    """Stand-in so Scanner() doesn't construct a real HTTP client."""


def test_eoa_scores_zero():
    s = make_scanner()
    ctx = ContractContext(address="0x" + "11" * 20, chain="base",
                          chain_id=8453, bytecode="0x")
    res = s.scan_context(ctx)
    assert not res.is_contract
    assert res.risk_score == 0
    assert any(f.id == "NOT_A_CONTRACT" for f in res.findings)


def test_risky_contract_scores_high():
    s = make_scanner()
    src = """
    contract Rug is Ownable, UUPSUpgradeable {
        mapping(address=>bool) isBlacklisted;
        bool tradingEnabled;
        uint sellFee;
        function mint(address a, uint v) external onlyOwner {}
        function withdraw() external onlyOwner {}
    }
    """
    ctx = ContractContext(
        address="0x" + "22" * 20, chain="base", chain_id=8453,
        bytecode="0x60016000ff",  # has SELFDESTRUCT
        verified=True, contract_name="Rug", source_code=src,
        proxy_kind="eip1967", proxy_implementation="0x" + "33" * 20,
        data_sources=["explorer:getsourcecode"],
    )
    res = s.scan_context(ctx)
    assert res.is_contract
    assert res.risk_score >= 50
    assert res.risk_band in ("High", "Critical")
    ids = {f.id for f in res.findings}
    assert "PROXY_UPGRADEABLE" in ids
    assert "OPCODE_SELFDESTRUCT" in ids
    assert "TOKEN_BLACKLIST" in ids

    # Reports render without error.
    assert "Risk score" in report.to_markdown(res)
    assert '"risk_score"' in report.to_json(res)
    assert "Score" in report.to_terminal(res)


def test_clean_verified_contract_low():
    s = make_scanner()
    ctx = ContractContext(
        address="0x" + "44" * 20, chain="base", chain_id=8453,
        bytecode="0x6001", verified=True, contract_name="Clean",
        source_code="contract Clean { function foo() public {} }",
        data_sources=["explorer:getsourcecode"],
    )
    res = s.scan_context(ctx)
    assert res.risk_band in ("Minimal", "Low")
