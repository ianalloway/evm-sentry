import time

from evm_sentry.checks.approval_traps import check_approval_traps
from evm_sentry.checks.dangerous_opcodes import check_dangerous_opcodes
from evm_sentry.checks.freshness import check_freshness
from evm_sentry.checks.ownership import check_ownership
from evm_sentry.checks.proxy import check_proxy
from evm_sentry.checks.token_traps import check_token_traps
from evm_sentry.checks.verification import check_verification
from evm_sentry.context import ContractContext
from evm_sentry.models import Severity


def ctx(**kw):
    base = dict(address="0x" + "ab" * 20, chain="base", chain_id=8453, bytecode="0x6001")
    base.update(kw)
    return ContractContext(**base)


def ids(findings):
    return {f.id for f in findings}


def _push4(selector_hex: str) -> str:
    return "63" + selector_hex


def _push32(data_hex: str) -> str:
    return "7f" + data_hex


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


def test_approval_unlimited_constant():
    # PUSH32 max + PUSH4 approve — unlimited-approval fingerprint.
    code = "0x" + _push32("ff" * 32) + _push4("095ea7b3")
    f = check_approval_traps(ctx(bytecode=code))
    assert "APPROVAL_UNLIMITED_CONSTANT" in ids(f)
    finding = next(x for x in f if x.id == "APPROVAL_UNLIMITED_CONSTANT")
    assert finding.severity == Severity.MEDIUM
    assert "approve" in finding.evidence["selectors"]
    assert "unlimited" in finding.description.lower() or "max" in finding.description.lower()


def test_approval_unlimited_requires_both_signals():
    # Max alone or approve alone should not fire the unlimited finding.
    assert "APPROVAL_UNLIMITED_CONSTANT" not in ids(
        check_approval_traps(ctx(bytecode="0x" + _push32("ff" * 32)))
    )
    assert "APPROVAL_UNLIMITED_CONSTANT" not in ids(
        check_approval_traps(ctx(bytecode="0x" + _push4("095ea7b3")))
    )
    # Substring of approve bytes without PUSH4 must not count.
    assert check_approval_traps(ctx(bytecode="0x095ea7b3" + "ff" * 32)) == []


def test_approval_permit_drain_surface_spender():
    # permit + transferFrom without ERC-20 markers → MEDIUM drain surface.
    code = "0x" + _push4("d505accf") + _push4("23b872dd")
    f = check_approval_traps(ctx(bytecode=code))
    assert "APPROVAL_PERMIT_DRAIN_SURFACE" in ids(f)
    finding = next(x for x in f if x.id == "APPROVAL_PERMIT_DRAIN_SURFACE")
    assert finding.severity == Severity.MEDIUM
    assert finding.evidence["looks_like_erc20"] is False


def test_approval_permit_on_erc20_is_low():
    # Standard ERC-20 Permit shape → LOW (phishing UX warning, not a verdict).
    code = "0x" + "".join(
        _push4(s)
        for s in ("d505accf", "23b872dd", "70a08231", "a9059cbb", "18160ddd")
    )
    f = check_approval_traps(ctx(bytecode=code))
    finding = next(x for x in f if x.id == "APPROVAL_PERMIT_DRAIN_SURFACE")
    assert finding.severity == Severity.LOW
    assert finding.evidence["looks_like_erc20"] is True
    assert "APPROVAL_UNLIMITED_CONSTANT" not in ids(f)


def test_approval_permit_plus_max_elevates_even_on_erc20():
    code = "0x" + _push32("ff" * 32) + "".join(
        _push4(s)
        for s in ("d505accf", "23b872dd", "70a08231", "a9059cbb", "18160ddd")
    )
    f = check_approval_traps(ctx(bytecode=code))
    got = ids(f)
    assert "APPROVAL_UNLIMITED_CONSTANT" in got
    permit = next(x for x in f if x.id == "APPROVAL_PERMIT_DRAIN_SURFACE")
    assert permit.severity == Severity.MEDIUM


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
    assert check_approval_traps(c) == []
