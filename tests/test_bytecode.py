from evm_sentry import bytecode as bc


def test_push_data_not_misread_as_opcode():
    # PUSH32 followed by 32 bytes of 0xFF. A naive scanner would see
    # SELFDESTRUCT (0xFF) inside the push data; a correct one must not.
    code = "0x7f" + "ff" * 32 + "00"  # PUSH32 <32xFF> STOP
    ops = bc.present_opcodes(code)
    assert "SELFDESTRUCT" not in ops


def test_real_selfdestruct_detected():
    code = "0x60016000ff"  # PUSH1 1 PUSH1 0 SELFDESTRUCT
    assert "SELFDESTRUCT" in bc.present_opcodes(code)


def test_delegatecall_detected():
    code = "0x60005af4"  # ... DELEGATECALL (0xf4)
    assert "DELEGATECALL" in bc.present_opcodes(code)


def test_minimal_proxy_detection_and_target():
    target = "1234567890abcdef1234567890abcdef12345678"
    code = "0x363d3d373d3d3d363d73" + target + "5af43d82803e903d91602b57fd5bf3"
    assert bc.is_minimal_proxy(code)
    assert bc.minimal_proxy_target(code) == "0x" + target


def test_has_code():
    assert not bc.has_code("0x")
    assert not bc.has_code("")
    assert bc.has_code("0x60")


def test_slot_to_address():
    word = "0x000000000000000000000000" + "ab" * 20
    assert bc.slot_to_address(word) == "0x" + "ab" * 20
    assert bc.slot_to_address("0x0") == ""
