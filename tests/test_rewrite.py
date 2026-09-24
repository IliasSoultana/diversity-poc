"""Tests for the instruction-substitution transform.

The transform is only ever trusted after re-disassembly confirms it, so these
tests check that same property directly: the alternate encoding must decode to
exactly the original instruction, be the same length, and differ in bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rewrite import DUAL, alternate_encoding  # noqa: E402

Nyxstone = pytest.importorskip("nyxstone").Nyxstone


@pytest.fixture(scope="module")
def x86():
    return Nyxstone("x86_64-unknown-none")


def _disasm(x86, b: bytes) -> str:
    return " ; ".join(i.assembly for i in x86.disassemble_to_instructions(list(b), 0x1000))


REG_REG = [
    "mov rax, rbx",
    "mov r8, rbx",       # REX.B on rm only
    "mov rbx, r8",       # REX.R on reg only
    "mov r8, r9",        # REX.R and REX.B both set
    "sub rax, rbx",      # non-commutative: direction must be preserved
    "cmp rcx, rdx",
    "xor r10, r11",
    "add ebx, ecx",      # 32-bit, no REX.W
    "and eax, ebx",      # no REX at all
    "or rsi, rdi",
]


@pytest.mark.parametrize("asm", REG_REG)
def test_alternate_is_equivalent(x86, asm):
    orig = bytes(x86.assemble(asm, 0x1000))
    alt = alternate_encoding(orig)
    assert alt is not None, f"no candidate for {asm} ({orig.hex()})"
    assert len(alt) == len(orig), "length changed"
    assert alt != orig, "bytes unchanged"
    assert _disasm(x86, alt) == _disasm(x86, orig), "semantics changed"


def test_transform_is_an_involution(x86):
    """Applying the swap twice returns the original bytes."""
    orig = bytes(x86.assemble("mov r8, rbx", 0x1000))
    once = alternate_encoding(orig)
    twice = alternate_encoding(once)
    assert twice == orig


def test_memory_operand_is_rejected(x86):
    """A load/store (mod != 11) is not a reg-reg dual and must be skipped."""
    orig = bytes(x86.assemble("mov rax, qword ptr [rbx]", 0x1000))
    assert alternate_encoding(orig) is None


def test_immediate_is_rejected(x86):
    """`mov rax, 1` has no dual encoding of this kind."""
    orig = bytes(x86.assemble("mov rax, 1", 0x1000))
    assert alternate_encoding(orig) is None


def test_control_flow_is_rejected(x86):
    for asm in ("ret", "call rax", "jmp rbx", "nop"):
        assert alternate_encoding(bytes(x86.assemble(asm, 0x1000))) is None


def test_dual_table_is_symmetric():
    for a, b in DUAL.items():
        assert DUAL[b] == a, f"{a:#x}/{b:#x} not symmetric"
