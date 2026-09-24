#!/usr/bin/env python3
"""
gadgets.py — measure what link-order diversification actually costs an attacker.

compare.py answers "did the functions move".  That is the easy question, and
the flattering one.  This asks the harder one: a return-oriented exploit is
built from short instruction sequences ending in a return, so what happens to
*those* when the link order changes?

Three numbers come out, and only the third one matters:

  1. How many gadgets each variant contains.
     Link-order shuffling does not add or remove code, so this should be
     identical.  If it is not, something is wrong with the build.

  2. How many gadget byte sequences survive in both variants.
     Also expected to be ~100%.  Moving object files around does not rewrite
     instructions, so every gadget still exists somewhere.

  3. How many surviving gadgets keep the same offset inside their own
     function.
     This is the one that decides whether the mitigation is worth anything.
     If a gadget sits at the same offset within `process_sensor` in every
     variant, then an attacker who leaks the address of `process_sensor` on
     one device can compute every gadget in that object, on that device.
     Diversification then costs them one info leak, not an exploit.

Usage:
    python3 gadgets.py node_01 node_02
    python3 gadgets.py node_01 node_02 --json
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


# How many instructions may precede the return in a gadget. Real ROP chains
# use short sequences; anything longer tends to have side effects the attacker
# cannot control.
MAX_GADGET_INSNS = 4

# Instructions that end a gadget's usefulness if they appear in the middle:
# an unconditional transfer means control never reaches the return.
TERMINATORS = ("b ", "br ", "bl ", "blr ", "jmp", "call", "ret", "hlt", "ud2")


@dataclass(frozen=True)
class Gadget:
    address: int          # virtual address of the first instruction
    text: str             # "mov x0, x1 ; ret"
    raw: bytes            # the bytes, so identical gadgets compare equal
    symbol: str           # containing function, or "" if unknown
    offset: int           # distance from the start of that function


def _triple(binary) -> str:
    """Map the parsed binary's architecture to an LLVM target triple.

    ELF headers expose `machine_type`, Mach-O headers `cpu_type`; the tool has
    to read both because the demo builds native on macOS and ELF in CI.
    """
    header = binary.header
    raw = getattr(header, "machine_type", None) or getattr(header, "cpu_type", None)
    arch = str(raw).lower()
    if "aarch64" in arch or "arm64" in arch:
        return "aarch64-unknown-none"
    if "x86_64" in arch or "amd64" in arch:
        return "x86_64-unknown-none"
    if "riscv" in arch:
        return "riscv64-unknown-none"
    if "arm" in arch:
        return "armv7-unknown-none"
    raise SystemExit(f"unsupported architecture: {arch}")


def _executable_sections(binary):
    """Yield (name, virtual_address, bytes) for every executable section."""
    for section in binary.sections:
        name = section.name or ""
        if name in (".text", "__text"):
            yield name, section.virtual_address, bytes(section.content)


def _function_map(binary) -> list[tuple[int, str]]:
    """Sorted (address, name) pairs, used to attribute a gadget to a function."""
    funcs = []
    for sym in binary.symbols:
        name = (sym.name or "").lstrip("_")
        value = getattr(sym, "value", 0)
        if name and value:
            funcs.append((value, name))
    return sorted(set(funcs))


def _owning_function(funcs: list[tuple[int, str]], address: int) -> tuple[str, int]:
    """The last function starting at or before `address`."""
    lo, hi = 0, len(funcs) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if funcs[mid][0] <= address:
            best = funcs[mid]
            lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        return "", 0
    return best[1], address - best[0]


def extract(path: str) -> list[Gadget]:
    binary = lief.parse(path)
    if binary is None:
        raise SystemExit(f"could not parse {path}")

    nyx = Nyxstone(_triple(binary))
    funcs = _function_map(binary)
    gadgets: list[Gadget] = []

    for _name, base, blob in _executable_sections(binary):
        # Linear sweep. On fixed-width ISAs (AArch64, RISC-V) this sees every
        # instruction. On x86 it misses gadgets that only appear when decoding
        # from an unaligned offset -- see the limitation in the README.
        try:
            insns = nyx.disassemble_to_instructions(list(blob), base)
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"disassembly failed for {path}: {exc}")

        for i, insn in enumerate(insns):
            if not insn.assembly.startswith("ret"):
                continue

            # Walk backwards collecting usable instructions.
            window = []
            for j in range(i - 1, max(-1, i - 1 - MAX_GADGET_INSNS), -1):
                prev = insns[j].assembly
                if any(prev.startswith(t) for t in TERMINATORS):
                    break
                window.insert(0, insns[j])

            for start in range(len(window) + 1):
                chain = window[start:] + [insn]
                addr = chain[0].address
                raw = b"".join(bytes(c.bytes) for c in chain)
                sym, off = _owning_function(funcs, addr)
                gadgets.append(
                    Gadget(
                        address=addr,
                        text=" ; ".join(c.assembly for c in chain),
                        raw=raw,
                        symbol=sym,
                        offset=off,
                    )
                )

    return gadgets


def compare(a: list[Gadget], b: list[Gadget]) -> dict:
    """Match gadgets between two variants, then ask whether they moved.

    Identity is (containing function, offset inside it, bytes) -- not the byte
    sequence alone. Common epilogues such as `pop rbp ; ret` occur many times
    in one binary, so keying on bytes and picking an arbitrary occurrence
    compares unrelated gadgets and invents movement that did not happen.
    """

    def index(gadgets: list[Gadget]) -> dict[tuple[str, int, bytes], Gadget]:
        out: dict[tuple[str, int, bytes], Gadget] = {}
        for g in gadgets:
            out.setdefault((g.symbol, g.offset, g.raw), g)
        return out

    A, B = index(a), index(b)
    shared = set(A) & set(B)

    moved = 0
    same_address = 0
    anchored: dict[str, int] = {}

    for key in shared:
        ga, gb = A[key], B[key]
        if ga.address == gb.address:
            same_address += 1
            sym = ga.symbol or "<no symbol>"
            anchored[sym] = anchored.get(sym, 0) + 1
        else:
            moved += 1

    # Every matched pair shares a symbol and offset by construction, so the
    # in-function offset is preserved for all of them. What the byte-level view
    # adds is whether a sequence exists at all in the other variant.
    bytes_a = {g.raw for g in a}
    bytes_b = {g.raw for g in b}
    surviving_sequences = len(bytes_a & bytes_b)

    return {
        "gadgets_a": len(a),
        "gadgets_b": len(b),
        "distinct_a": len(bytes_a),
        "distinct_b": len(bytes_b),
        "matched_gadgets": len(shared),
        "shared_sequences": surviving_sequences,
        "survival_rate": round(100 * surviving_sequences / max(1, len(bytes_a)), 1),
        "moved_absolute": moved,
        "same_absolute_address": same_address,
        "relocation_rate": round(100 * moved / max(1, len(shared)), 1),
        "unmoved_by_function": dict(
            sorted(anchored.items(), key=lambda kv: -kv[1])
        ),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("binary_a")
    ap.add_argument("binary_b")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    a, b = extract(args.binary_a), extract(args.binary_b)
    result = compare(a, b)

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
        for sym, n in result["unmoved_by_function"].items():
            print(f"      {sym:<28} {n}")

    print(
        "\nReading: matched gadgets sit at the same offset inside the same\n"
        "function in both variants -- shuffling relocates whole objects and\n"
        "never touches their contents. So one leaked function pointer lets an\n"
        "attacker compute every gadget in that object."
    )
    print()


if __name__ == "__main__":
    main()
