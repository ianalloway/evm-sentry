import time

from evm_sentry.checks.dangerous_opcodes import check_dangerous_opcodes
from evm_sentry.checks.freshness import check_freshness
from evm_sentry.checks.ownership import check_ownership
from evm_sentry.checks.proxy import check_proxy
from evm_sentry.checks.token_traps import check_token_traps
from evm_sentry.checks.verification import check_verification
from evm_sentry.context import ContractContext


def ctx(**kw):
    base = dict(address="0x" + "ab" * 20, chain="base", chain_id=8453, bytecode="0x6001")
    base.update(kw)
    return ContractContext(**base)


def ids(findings):
    return {f.id for f in findings}


def test_unverified_only_flagged_when_explorer_queried():
    # No explorer query -> no claim.
    assert check_verification(ctx()) == []
    # Explorer queried, unverified -> MEDIUM.
    c = ctx(data_sources=["explorer:getsourcecode"], verified=False)
    assert "SOURCE_UNVERIFIED" in ids(check_verification(c))
    # Verified -> info only.
    c2 = ctx(data_sources=["explorer:getsourcecode"], verified=True,
             contract_name="Foo")
    assert "SOURCE_VERIFIED" in ids(check_verification(c2))


def test_proxy_detected():
    c = ctx(proxy_kind="eip1967", proxy_implementation="0x" + "cd" * 20)
    assert "PROXY_UPGRADEABLE" in ids(check_proxy(c))


def test_uups_without_guard():
    c = ctx(source_code="contract X is UUPSUpgradeable { }")
    assert "UUPS_NO_AUTH_GUARD" in ids(check_proxy(c))
    c2 = ctx(source_code="contract X is UUPSUpgradeable { function _authorizeUpgrade(address) internal override onlyOwner {} }")
    assert "UUPS_NO_AUTH_GUARD" not in ids(check_proxy(c2))


def test_ownership_single_owner_and_powers():
    src = "contract T is Ownable { function mint(address a,uint v) external onlyOwner {} }"
    f = check_ownership(ctx(source_code=src))
    assert "SINGLE_OWNER" in ids(f)
    assert "PRIVILEGED_POWERS" in ids(f)


def test_token_traps():
    src = "function _transfer() { require(!isBlacklisted[from]); } bool tradingEnabled; uint sellFee;"
    f = check_token_traps(ctx(source_code=src))
    got = ids(f)
    assert "TOKEN_BLACKLIST" in got
    assert "TOKEN_TRADING_TOGGLE" in got
    assert "TOKEN_ADJUSTABLE_FEES" in got


def test_dangerous_opcodes():
    c = ctx(bytecode="0x60016000ff")  # SELFDESTRUCT
    assert "OPCODE_SELFDESTRUCT" in ids(check_dangerous_opcodes(c))


def test_freshness_recent():
    c = ctx(creation_timestamp=int(time.time()) - 3600)  # 1h old
    assert "FRESH_DEPLOYMENT" in ids(check_freshness(c))
    old = ctx(creation_timestamp=int(time.time()) - 60 * 86400)  # 60d
    assert check_freshness(old) == []


def test_eoa_yields_no_contract_findings():
    c = ctx(bytecode="0x")
    assert check_proxy(c) == []
    assert check_ownership(c) == []
    assert check_dangerous_opcodes(c) == []
