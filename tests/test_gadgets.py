"""Tests for gadget discovery.

The interesting case is the x86 one. A return opcode can be hidden inside the
immediate of a longer instruction, where a linear sweep will never report it
even though an attacker can jump straight to it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gadgets import (  # noqa: E402
    MAX_BACKWARD_BYTES,
    _backward_gadgets,
    _linear_gadgets,
)

Nyxstone = pytest.importorskip("nyxstone").Nyxstone


@pytest.fixture(scope="module")
def x86():
    return Nyxstone("x86_64-unknown-none")


@pytest.fixture(scope="module")
def hidden_gadget(x86):
    """`movabs rbx, 0xc35fc35f`, the immediate contains 5f c3 = pop rdi ; ret.

    One instruction when decoded from its own start. Two usable gadgets when
    decoded from inside it.
    """
    return bytes(x86.assemble("mov rbx, 0xc35fc35f", 0x1000))


def test_the_immediate_really_does_hide_a_return(hidden_gadget):
    assert 0xC3 in hidden_gadget, "test fixture no longer contains a ret byte"


def test_linear_sweep_misses_the_hidden_gadget(x86, hidden_gadget):
    """A linear decode sees one long instruction and no return at all."""
    found = _linear_gadgets(x86, hidden_gadget, 0x1000, [])
    assert found == []


def test_backward_scan_finds_it(x86, hidden_gadget):
    found = _backward_gadgets(x86, hidden_gadget, 0x1000, [])
    texts = [g.text for g in found]
    assert any("pop rdi" in t and t.endswith("ret") for t in texts), texts


def test_backward_scan_rejects_invalid_starts(x86, hidden_gadget):
    """Every reported gadget must decode to exactly the bytes it claims."""
    for g in _backward_gadgets(x86, hidden_gadget, 0x1000, []):
        insns = x86.disassemble_to_instructions(list(g.raw), g.address)
        assert insns[-1].assembly.startswith("ret")
        rebuilt = b"".join(bytes(i.bytes) for i in insns)
        assert rebuilt == g.raw


def test_gadget_length_is_bounded(x86, hidden_gadget):
    for g in _backward_gadgets(x86, hidden_gadget, 0x1000, []):
        assert len(g.raw) <= MAX_BACKWARD_BYTES + 3


def test_call_in_the_middle_is_rejected(x86):
    """A call before the return means control never reaches the return."""
    code = bytes(x86.assemble("call rax", 0x2000)) + b"\xc3"
    for g in _backward_gadgets(x86, code, 0x2000, []):
        assert "call" not in g.text


def test_symbol_attribution(x86, hidden_gadget):
    funcs = [(0x1000, "victim")]
    for g in _backward_gadgets(x86, hidden_gadget, 0x1000, funcs):
        assert g.symbol == "victim"
        assert g.offset == g.address - 0x1000
