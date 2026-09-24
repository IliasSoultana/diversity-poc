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


def ropgadget_addresses(path: str, depth: int = 5) -> set[int]:
    """Every address ROPgadget reports, duplicates included.

    --all matters: by default ROPgadget collapses identical gadget strings to a
    single representative address, so most real occurrences never get printed
    and an address-level comparison looks far worse than it is.

    --depth 5 matches this tool's limit of four instructions before the return.
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


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: validate_against_ropgadget.py BINARY [BINARY ...]")

    failures = 0
    for path in sys.argv[1:]:
        ours = {g.address for g in extract(path)}
        theirs = ropgadget_addresses(path)

        if not ours:
            print(f"{path}: no gadgets found, nothing to validate")
            continue

        confirmed = ours & theirs
        unconfirmed = ours - theirs
        rate = 100 * len(confirmed) / len(ours)

        print(f"\n{path}")
        print(f"  gadgets.py reported     {len(ours)}")
        print(f"  ROPgadget reported      {len(theirs)}")
        print(f"  confirmed by ROPgadget  {len(confirmed)} ({rate:.1f}%)")
        print(f"  not confirmed           {len(unconfirmed)}")

        if unconfirmed:
            print("  unconfirmed addresses (first 5):",
                  ", ".join(hex(a) for a in sorted(unconfirmed)[:5]))

        # ROPgadget applies its own filters, so a small unconfirmed remainder is
        # expected. A large one means we are inventing gadgets.
        if rate < 90:
            print(f"  FAIL: only {rate:.1f}% confirmed")
            failures += 1

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
