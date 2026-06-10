"""EVM bytecode utilities.

A correct opcode scan must skip PUSH immediate data, otherwise data bytes get
misread as opcodes (a common source of false positives in naive scanners).
"""

from __future__ import annotations

from typing import Dict, Set

# Opcodes we care about for risk analysis.
OPCODES: Dict[int, str] = {
    0xF0: "CREATE",
    0xF1: "CALL",
    0xF2: "CALLCODE",
    0xF4: "DELEGATECALL",
    0xF5: "CREATE2",
    0xFA: "STATICCALL",
    0xFF: "SELFDESTRUCT",
    0x55: "SSTORE",
    0x54: "SLOAD",
}

# EIP-1167 minimal-proxy runtime prefix/suffix (the 0x363d3d37... pattern).
EIP1167_PREFIXES = (
    "363d3d373d3d3d363d73",   # canonical
    "363d3d373d3d3d363d6f",   # vyper / variant push
)


def normalize(code: str) -> str:
    code = code.strip()
    if code.startswith("0x") or code.startswith("0X"):
        code = code[2:]
    return code.lower()


def to_bytes(code: str) -> bytes:
    code = normalize(code)
    if len(code) % 2:
        code = code[:-1]
    try:
        return bytes.fromhex(code)
    except ValueError:
        return b""


def has_code(code: str) -> bool:
    return len(normalize(code)) > 0


def iter_opcodes(data: bytes):
    """Yield (pc, opcode) pairs, skipping PUSH immediate data."""
    i = 0
    n = len(data)
    while i < n:
        op = data[i]
        yield i, op
        if 0x60 <= op <= 0x7F:  # PUSH1..PUSH32
            i += 1 + (op - 0x5F)
        else:
            i += 1


def present_opcodes(code: str) -> Set[str]:
    """Return the set of notable opcode mnemonics actually executed in code."""
    data = to_bytes(code)
    found: Set[str] = set()
    for _, op in iter_opcodes(data):
        name = OPCODES.get(op)
        if name:
            found.add(name)
    return found


def is_minimal_proxy(code: str) -> bool:
    c = normalize(code)
    return any(p in c for p in EIP1167_PREFIXES)


def minimal_proxy_target(code: str) -> str:
    """Extract the implementation address embedded in an EIP-1167 clone."""
    c = normalize(code)
    for p in EIP1167_PREFIXES:
        idx = c.find(p)
        if idx != -1:
            start = idx + len(p)
            addr = c[start:start + 40]
            if len(addr) == 40:
                return "0x" + addr
    return ""


# EIP-1967 storage slots (transparent / UUPS proxies).
SLOT_IMPLEMENTATION = (
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
SLOT_ADMIN = (
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
)
SLOT_BEACON = (
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
)
# OpenZeppelin legacy "org.zeppelinos.proxy.implementation" slot.
SLOT_OZ_LEGACY = (
    "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
)


def slot_to_address(slot_value: str) -> str:
    """Interpret a 32-byte storage word as a right-aligned address."""
    v = normalize(slot_value)
    if not v or set(v) == {"0"}:
        return ""
    v = v.rjust(64, "0")
    return "0x" + v[-40:]
