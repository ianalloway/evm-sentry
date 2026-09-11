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
