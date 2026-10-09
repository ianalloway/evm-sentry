"""CLI parsing and local (no-network) exit-code behaviour."""

from evm_sentry.cli import _FAIL_MAP, build_parser, main


def test_markdown_shorthand():
    args = build_parser().parse_args(["0x" + "11" * 20, "--markdown"])
    assert args.markdown is True
    assert args.format == "terminal"  # shorthand is applied in main(), not argparse


def test_fail_on_elevated_is_alias_of_medium():
    parser = build_parser()
    elevated = parser.parse_args(["0x" + "11" * 20, "--fail-on", "elevated"])
    medium = parser.parse_args(["0x" + "11" * 20, "--fail-on", "medium"])
    assert elevated.fail_on == "elevated"
    assert medium.fail_on == "medium"
    assert _FAIL_MAP["elevated"] == _FAIL_MAP["medium"] == 2


def test_chain_aliases_accepted_by_parser():
    args = build_parser().parse_args(["0x" + "11" * 20, "--chain", "op"])
    assert args.chain == "op"


def test_invalid_address_exits_2():
    assert main(["not-an-address"]) == 2


_RPC_KEY = "alchemyKey0123456789abcdef"
_ADDR = "0x" + "ab" * 20


def test_timeline_malformed_rpc_url_error_does_not_print_key(monkeypatch, capsys):
    # No scheme -> requests raises MissingSchema (a ValueError) quoting the URL.
    monkeypatch.setenv("EVM_SENTRY_RPC_ETHEREUM", f"eth-mainnet.g.alchemy.com/v2/{_RPC_KEY}")
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)

    assert main([_ADDR, "--chain", "ethereum", "--timeline"]) == 2

    out = capsys.readouterr()
    assert out.err.startswith("error: ")
    assert _RPC_KEY not in out.out + out.err


def test_scan_value_error_is_redacted(monkeypatch, capsys):
    import requests

    import evm_sentry.cli as cli

    secret = "EXPLORERKEY123456"
    rpc = f"https://user:hunter2pass@rpc.example.org/{_RPC_KEY}"
    monkeypatch.setenv("EVM_SENTRY_RPC_BASE", rpc)

    class _Boom:
        def __init__(self, *args, **kwargs):
            pass

        def scan_address(self, address):
            raise requests.exceptions.InvalidURL(
                f"Invalid URL {rpc!r} and https://api.etherscan.io/v2/api?apikey={secret}"
            )

    monkeypatch.setattr(cli, "Scanner", _Boom)

    assert main([_ADDR, "--chain", "base", "--api-key", secret]) == 2

    err = capsys.readouterr().err
    assert err.startswith("error: ")
    for leaked in (secret, _RPC_KEY, "hunter2pass"):
        assert leaked not in err
