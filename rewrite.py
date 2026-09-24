#!/usr/bin/env python3
"""
rewrite.py — instruction-level diversification on a finished binary.

divcc reorders whole object files, so gadget bodies survive untouched -- the
measurement in gadgets.py shows exactly that. This does the thing that measurement
argued for instead: it edits the linked binary directly, with no source and no
recompilation, swapping individual instructions for equal-length encodings that
mean the same thing.

x86-64 has two encodings for every register-to-register ALU instruction. `mov
rax, rbx` can be `48 89 d8` (opcode 0x89, destination in r/m) or `48 8b c3`
(opcode 0x8b, destination in reg). Same length, same effect, different bytes --
so the third byte of any gadget overlapping that instruction changes, which is
the property divcc could not touch.

Scope, stated plainly:

  * Same-length substitutions only. Changing an instruction's length would move
    everything after it and require relocating every address that refers past
    the edit -- a different and much larger problem. Nyx does that; this does
    not.

  * Register-to-register ALU ops only (mov, add, sub, and, or, xor, cmp). These
    are the instructions with a clean dual encoding.

  * Every candidate is verified by disassembling the replacement and checking it
    means exactly what the original did. A transform this tool cannot prove
    equivalent is skipped, never guessed.

Usage:
    rewrite.py INPUT -o OUTPUT [--seed N] [--dry-run]
"""

from __future__ import annotations

import argparse
import random
import sys

try:
    import lief
except ImportError:
    sys.exit("lief is required:  pip install lief")

try:
    from nyxstone import Nyxstone
except ImportError:
    sys.exit("nyxstone is required:  pip install nyxstone  (needs LLVM 15-20)")


# opcode <-> its reverse-direction dual (MR form <-> RM form)
DUAL = {
    0x89: 0x8B, 0x8B: 0x89,   # mov
    0x01: 0x03, 0x03: 0x01,   # add
    0x29: 0x2B, 0x2B: 0x29,   # sub
    0x21: 0x23, 0x23: 0x21,   # and
    0x09: 0x0B, 0x0B: 0x09,   # or
    0x31: 0x33, 0x33: 0x31,   # xor
    0x39: 0x3B, 0x3B: 0x39,   # cmp
}


def alternate_encoding(b: bytes) -> bytes | None:
    """The same-length dual encoding of one reg-reg instruction, or None.

    Structural transform only; correctness is confirmed by the caller through
    re-disassembly, so a mistake here becomes a skipped instruction, never a
    corrupted one.
    """
    i = 0
    prefix = b""
    if i < len(b) and b[i] == 0x66:            # operand-size prefix
        prefix += b[i:i + 1]
        i += 1
    rex = None
    if i < len(b) and 0x40 <= b[i] <= 0x4F:
        rex = b[i]
        i += 1
    if i + 1 >= len(b):
        return None
    op, modrm = b[i], b[i + 1]
    if op not in DUAL:
        return None
    if (modrm & 0xC0) != 0xC0:                  # need mod=11: both operands registers
        return None
    if i + 2 != len(b):                         # exactly opcode + modrm, nothing trailing
        return None

    reg, rm = (modrm >> 3) & 7, modrm & 7
    new_modrm = 0xC0 | (rm << 3) | reg          # swap reg and rm
    new_rex = rex
    if rex is not None:
        R, B = (rex >> 2) & 1, rex & 1
        new_rex = (rex & ~0x05) | (B << 2) | R  # swap REX.R and REX.B to match

    out = bytearray(prefix)
    if new_rex is not None:
        out.append(new_rex)
    out += bytes([DUAL[op], new_modrm])
    result = bytes(out)
    return result if result != b else None


def _vaddr_to_offset(binary, vaddr: int) -> int | None:
    for s in binary.sections:
        if s.virtual_address <= vaddr < s.virtual_address + s.size and s.offset:
            return s.offset + (vaddr - s.virtual_address)
    return None


def rewrite(in_path: str, out_path: str, seed: int = 0, dry_run: bool = False) -> dict:
    binary = lief.parse(in_path)
    if binary is None:
        raise SystemExit(f"could not parse {in_path}")

    arch = str(getattr(binary.header, "machine_type", "")).lower()
    if "x86_64" not in arch and "amd64" not in arch:
        raise SystemExit(f"only x86-64 is supported; got {arch}")

    nyx = Nyxstone("x86_64-unknown-none")
    rng = random.Random(seed)

    with open(in_path, "rb") as f:
        data = bytearray(f.read())

    candidates = 0
    applied = 0
    verified_equivalent = 0

    for section in binary.sections:
        if (section.name or "") not in (".text",):
            continue
        base = section.virtual_address
        blob = bytes(section.content)

        try:
            insns = nyx.disassemble_to_instructions(list(blob), base)
        except Exception:
            continue

        for insn in insns:
            orig = bytes(insn.bytes)
            alt = alternate_encoding(orig)
            if alt is None:
                continue
            candidates += 1

            # Prove equivalence: the replacement must disassemble to exactly the
            # original instruction, and be exactly as long.
            try:
                back = nyx.disassemble_to_instructions(list(alt), insn.address)
            except Exception:
                continue
            if len(back) != 1 or len(alt) != len(orig):
                continue
            if back[0].assembly != insn.assembly:
                continue
            verified_equivalent += 1

            # A seed lets a fleet get per-device variants; seed 0 rewrites all.
            if seed and rng.random() < 0.5:
                continue

            off = _vaddr_to_offset(binary, insn.address)
            if off is None or data[off:off + len(orig)] != orig:
                continue

            if not dry_run:
                data[off:off + len(alt)] = alt
            applied += 1

    if not dry_run:
        with open(out_path, "wb") as f:
            f.write(data)
        import os
        os.chmod(out_path, 0o755)

    return {
        "candidates": candidates,
        "verified_equivalent": verified_equivalent,
        "applied": applied,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Instruction-level binary diversification.")
    ap.add_argument("input")
    ap.add_argument("-o", "--output")
    ap.add_argument("--seed", type=int, default=0,
                    help="per-device seed; 0 (default) rewrites every candidate")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change without writing")
    args = ap.parse_args()

    if not args.dry_run and not args.output:
        ap.error("-o/--output is required unless --dry-run")

    stats = rewrite(args.input, args.output or "/dev/null", args.seed, args.dry_run)
    print(f"reg-reg candidates          {stats['candidates']}")
    print(f"verified equivalent         {stats['verified_equivalent']}")
    print(f"{'would rewrite' if args.dry_run else 'rewritten'}"
          f"{'':15}".rstrip() + f"     {stats['applied']}")
    if not args.dry_run:
        print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
