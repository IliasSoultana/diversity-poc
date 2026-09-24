#!/usr/bin/env python3
"""
Cross-check gadgets.py against ROPgadget on binaries neither tool's author built.

A gadget finder that only ever runs on your own toy program proves very little.
This points both this tool and ROPgadget -- an established, widely used finder --
at the same system binaries and asks one question:

    is every gadget we report also reported by ROPgadget?

That is the direction that matters. A false positive means we are claiming an
instruction sequence that is not really there, which would make every number in
the README wrong. A false negative only means we are less thorough, which the
README already states: no jump- or call-terminated gadgets, at most four
instructions before the return.

Usage:
    python3 validate_against_ropgadget.py /usr/bin/ls /bin/bash
"""

from __future__ import annotations

import re
import subprocess
import sys

from gadgets import extract

# ROPgadget prints one gadget per line as "0xADDRESS : insn ; insn ; ret"
LINE = re.compile(r"^0x([0-9a-fA-F]+)\s*:")


def ropgadget_addresses(path: str, depth: int = 10) -> set[int]:
    """Every address ROPgadget reports, duplicates included.

    --all matters: by default ROPgadget collapses identical gadget strings to a
    single representative address, so most real occurrences never get printed
    and an address-level comparison looks far worse than it is.

    --depth is deliberately larger than this tool's own limit of four
    instructions before the return. ROPgadget bounds how far back it searches
    by instruction count, so an equal depth makes its set *narrower* than ours
    near the window edge and reports our valid gadgets as unconfirmed. A larger
    depth makes its result a superset, which is what a subset check needs.
    """
    proc = subprocess.run(
        ["ROPgadget", "--binary", path, "--depth", str(depth), "--all"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        sys.exit(f"ROPgadget failed on {path}:\n{proc.stderr[:400]}")

    found = set()
    for line in proc.stdout.splitlines():
        m = LINE.match(line.strip())
        if m:
            found.add(int(m.group(1), 16))
    return found


def self_consistent(path: str):
    """Every reported gadget must decode to exactly the bytes it claims.

    This is the real false-positive test and it needs no reference tool: if a
    gadget's bytes re-decode to a different instruction stream, or do not end
    in a return, the tool invented it.
    """
    from nyxstone import Nyxstone

    from gadgets import TRIPLES, _arch

    import lief
    nyx = Nyxstone(TRIPLES[_arch(lief.parse(path))])

    bad = []
    for g in extract(path):
        try:
            insns = nyx.disassemble_to_instructions(list(g.raw), g.address)
        except Exception:
            bad.append((g, "does not decode"))
            continue
        if not insns or not insns[-1].assembly.startswith("ret"):
            bad.append((g, "does not end in a return"))
        elif b"".join(bytes(i.bytes) for i in insns) != g.raw:
            bad.append((g, "re-decodes to different bytes"))
    return bad


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: validate_against_ropgadget.py BINARY [BINARY ...]")

    failures = 0
    for path in sys.argv[1:]:
        ours = {g.address for g in extract(path)}
        if not ours:
            print(f"{path}: no gadgets found, nothing to validate")
            continue

        print(f"\n{path}")

        # 1. False positives. This one is a hard failure.
        bad = self_consistent(path)
        print(f"  reported                {len(ours)}")
        print(f"  self-consistent         {len(ours) - len(bad)}")
        if bad:
            print(f"  INVALID                 {len(bad)}")
            for g, why in bad[:5]:
                print(f"    {g.address:#x} {why}: {g.text}")
            failures += 1
        else:
            print("  no false positives")

        # 2. Agreement with an outside tool. Reported, not enforced strictly:
        #    ROPgadget applies filters this tool does not, notably dropping
        #    `ret imm16` gadgets and odd sequences from unaligned decodes, so a
        #    residual difference is expected rather than a defect.
        theirs = ropgadget_addresses(path)
        confirmed = ours & theirs
        rate = 100 * len(confirmed) / len(ours)
        print(f"  also found by ROPgadget {len(confirmed)} of {len(ours)} ({rate:.1f}%)")

        if rate < 80:
            print(f"  FAIL: agreement dropped to {rate:.1f}%, "
                  "which suggests a real divergence rather than filtering")
            failures += 1

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
