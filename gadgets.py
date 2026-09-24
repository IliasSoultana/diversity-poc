#!/usr/bin/env python3
"""
gadgets.py — measure what link-order diversification actually costs an attacker.

compare.py answers "did the functions move".  That is the easy question, and
the flattering one.  This asks the harder one: a return-oriented exploit is
built from short instruction sequences ending in a return, so what happens to
*those* when the link order changes?

Two modes:

    gadgets.py BINARY_A BINARY_B      compare two variants
    gadgets.py --inventory BINARY     count gadgets in one binary

How gadgets are found depends on the instruction encoding:

  Fixed-width ISAs (AArch64, RISC-V).  Every instruction starts on a 4-byte
  boundary, so one linear sweep of the text section sees all of them.

  Variable-width ISAs (x86, x86-64).  An instruction may start at any byte, so
  a return opcode sitting inside the immediate or displacement of a longer
  instruction is still a real, executable return -- reachable by jumping into
  the middle of that instruction.  A linear sweep never reports those, and on
  x86 they are the majority of what a ROP chain is built from.  So we scan for
  return opcodes and try decoding backwards from each one, keeping the starts
  that decode cleanly and land exactly on the return.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass

try:
    import lief
except ImportError:
    sys.exit("lief is required:  pip install lief")

try:
    from nyxstone import Nyxstone
except ImportError:
    sys.exit("nyxstone is required:  pip install nyxstone  (needs LLVM 15-20)")


# How many instructions may precede the return. Real chains use short
# sequences; longer ones carry side effects the attacker cannot control.
MAX_GADGET_INSNS = 4

# How far back to try decoding from a return byte on a variable-width ISA.
# The longest valid x86-64 instruction is 15 bytes.
MAX_BACKWARD_BYTES = 20

# An unconditional transfer in the middle means control never reaches the
# return, so the sequence is not usable.
TERMINATORS = ("b ", "br ", "bl ", "blr ", "jmp", "call", "ret", "hlt", "ud2", "j")

# x86 return opcodes and their encoded lengths.
X86_RETURNS = {0xC3: 1, 0xC2: 3}

TRIPLES = {
    "aarch64": "aarch64-unknown-none",
    "x86_64": "x86_64-unknown-none",
    "riscv64": "riscv64-unknown-none",
    "arm": "armv7-unknown-none",
}
VARIABLE_WIDTH = {"x86_64"}


@dataclass(frozen=True)
class Gadget:
    address: int
    text: str
    raw: bytes
    symbol: str
    offset: int


def _arch(binary) -> str:
    header = binary.header
    raw = getattr(header, "machine_type", None) or getattr(header, "cpu_type", None)
    a = str(raw).lower()
    if "aarch64" in a or "arm64" in a:
        return "aarch64"
    if "x86_64" in a or "amd64" in a:
        return "x86_64"
    if "riscv" in a:
        return "riscv64"
    if "arm" in a:
        return "arm"
    raise SystemExit(f"unsupported architecture: {a}")


def _executable_sections(binary):
    for section in binary.sections:
        if (section.name or "") in (".text", "__text"):
            yield section.virtual_address, bytes(section.content)


def _function_map(binary) -> list[tuple[int, str]]:
    funcs = []
    for sym in binary.symbols:
        name = (sym.name or "").lstrip("_")
        value = getattr(sym, "value", 0)
        if name and value:
            funcs.append((value, name))
    return sorted(set(funcs))


def _owning_function(funcs: list[tuple[int, str]], address: int) -> tuple[str, int]:
    lo, hi, best = 0, len(funcs) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= address:
            best, lo = funcs[mid], mid + 1
        else:
            hi = mid - 1
    return (best[1], address - best[0]) if best else ("", 0)


def _unusable(assemblies) -> bool:
    return any(a.startswith(t) for a in assemblies for t in TERMINATORS)


def _linear_gadgets(nyx, blob: bytes, base: int, funcs) -> list[Gadget]:
    """Fixed-width ISAs: a single sweep sees every instruction."""
    try:
        insns = nyx.disassemble_to_instructions(list(blob), base)
    except Exception:
        return []

    out = []
    for i, insn in enumerate(insns):
        if not insn.assembly.startswith("ret"):
            continue
        window = []
        for j in range(i - 1, max(-1, i - 1 - MAX_GADGET_INSNS), -1):
            if _unusable([insns[j].assembly]):
                break
            window.insert(0, insns[j])
        for start in range(len(window) + 1):
            chain = window[start:] + [insn]
            addr = chain[0].address
            sym, off = _owning_function(funcs, addr)
            out.append(Gadget(
                address=addr,
                text=" ; ".join(c.assembly for c in chain),
                raw=b"".join(bytes(c.bytes) for c in chain),
                symbol=sym, offset=off,
            ))
    return out


def _backward_gadgets(nyx, blob: bytes, base: int, funcs) -> list[Gadget]:
    """Variable-width ISAs: decode backwards from every return byte."""
    out: list[Gadget] = []
    seen: set[tuple[int, int]] = set()

    for pos, byte in enumerate(blob):
        ret_len = X86_RETURNS.get(byte)
        if ret_len is None or pos + ret_len > len(blob):
            continue

        for back in range(1, MAX_BACKWARD_BYTES + 1):
            start = pos - back
            if start < 0:
                break
            window = blob[start:pos + ret_len]
            try:
                insns = nyx.disassemble_to_instructions(list(window), base + start)
            except Exception:
                continue  # not a valid instruction boundary
            if not insns:
                continue

            last = insns[-1]
            # The decode must land exactly on the return rather than swallow it.
            if last.address != base + pos or not last.assembly.startswith("ret"):
                continue
            middle = [i.assembly for i in insns[:-1]]
            if len(middle) > MAX_GADGET_INSNS or _unusable(middle):
                continue

            key = (base + start, len(window))
            if key in seen:
                continue
            seen.add(key)

            sym, off = _owning_function(funcs, base + start)
            out.append(Gadget(
                address=base + start,
                text=" ; ".join(i.assembly for i in insns),
                raw=bytes(window),
                symbol=sym, offset=off,
            ))
    return out


def extract(path: str) -> list[Gadget]:
    binary = lief.parse(path)
    if binary is None:
        raise SystemExit(f"could not parse {path}")

    arch = _arch(binary)
    nyx = Nyxstone(TRIPLES[arch])
    funcs = _function_map(binary)
    strategy = _backward_gadgets if arch in VARIABLE_WIDTH else _linear_gadgets

    gadgets: list[Gadget] = []
    for base, blob in _executable_sections(binary):
        gadgets.extend(strategy(nyx, blob, base, funcs))
    return gadgets


def compare(a: list[Gadget], b: list[Gadget]) -> dict:
    """Match gadgets between variants by (function, offset, bytes).

    Not by bytes alone: sequences such as `pop rbp ; ret` occur many times in
    one binary, so keying on bytes and comparing an arbitrary occurrence
    invents movement that did not happen.
    """
    def index(gs):
        out = {}
        for g in gs:
            out.setdefault((g.symbol, g.offset, g.raw), g)
        return out

    A, B = index(a), index(b)
    shared = set(A) & set(B)

    moved = same = 0
    anchored: dict[str, int] = {}
    for key in shared:
        ga, gb = A[key], B[key]
        if ga.address == gb.address:
            same += 1
            sym = ga.symbol or "<no symbol>"
            anchored[sym] = anchored.get(sym, 0) + 1
        else:
            moved += 1

    bytes_a = {g.raw for g in a}
    bytes_b = {g.raw for g in b}
    survived = len(bytes_a & bytes_b)

    return {
        "gadgets_a": len(a),
        "gadgets_b": len(b),
        "distinct_a": len(bytes_a),
        "distinct_b": len(bytes_b),
        "matched_gadgets": len(shared),
        "shared_sequences": survived,
        "survival_rate": round(100 * survived / max(1, len(bytes_a)), 1),
        "moved_absolute": moved,
        "same_absolute_address": same,
        "relocation_rate": round(100 * moved / max(1, len(shared)), 1),
        "unmoved_by_function": dict(sorted(anchored.items(), key=lambda kv: -kv[1])),
    }


def inventory(path: str) -> dict:
    gs = extract(path)
    return {
        "path": path,
        "gadgets": len(gs),
        "distinct_sequences": len({g.raw for g in gs}),
        "with_symbol": sum(1 for g in gs if g.symbol),
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Measure gadget survival across diversified variants.")
    ap.add_argument("binaries", nargs="+")
    ap.add_argument("--inventory", action="store_true",
                    help="count gadgets per binary instead of comparing two")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.inventory:
        results = [inventory(p) for p in args.binaries]
        print(json.dumps(results, indent=2) if args.json else "\n".join(
            f"{r['path']}: {r['gadgets']} gadgets "
            f"({r['distinct_sequences']} distinct)" for r in results))
        return

    if len(args.binaries) != 2:
        ap.error("comparison needs exactly two binaries (or use --inventory)")

    result = compare(extract(args.binaries[0]), extract(args.binaries[1]))

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"\nGadgets found      {result['gadgets_a']} / {result['gadgets_b']}"
          f"   ({result['distinct_a']} / {result['distinct_b']} distinct sequences)")
    print(f"Byte sequences present in both   {result['shared_sequences']} "
          f"({result['survival_rate']}% of variant A) -- none were destroyed")
    print(f"\nGadgets matched by function and offset   {result['matched_gadgets']}")
    print(f"  relocated            {result['moved_absolute']} "
          f"({result['relocation_rate']}%)")
    print(f"  same address         {result['same_absolute_address']}")
    if result["unmoved_by_function"]:
        print("    these sit in code divcc does not shuffle:")
        for sym, n in list(result["unmoved_by_function"].items())[:8]:
            print(f"      {sym:<28} {n}")
    print(
        "\nReading: matched gadgets sit at the same offset inside the same\n"
        "function in both variants -- shuffling relocates whole objects and\n"
        "never touches their contents. So one leaked function pointer lets an\n"
        "attacker compute every gadget in that object.\n"
    )


if __name__ == "__main__":
    main()
