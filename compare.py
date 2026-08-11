#!/usr/bin/env python3
"""
compare.py — show function address differences between two diversified builds.

Usage:
    python compare.py <binary1> <binary2>

Prints a table of every shared function symbol with its address in each build
and flags whether the addresses differ.  A working diversity tool should show
"DIFFERENT" for most or all functions.
"""

import subprocess
import sys


def symbol_addresses(binary: str) -> dict[str, int]:
    result = subprocess.run(
        ["nm", "-n", binary],
        capture_output=True,
        text=True,
        check=True,
    )
    symbols: dict[str, int] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t"):
            name = parts[2].lstrip("_")   # strip macOS underscore prefix
            try:
                symbols[name] = int(parts[0], 16)
            except ValueError:
                pass
    return symbols


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} binary1 binary2")
        sys.exit(1)

    b1_path, b2_path = sys.argv[1], sys.argv[2]
    s1 = symbol_addresses(b1_path)
    s2 = symbol_addresses(b2_path)

    common = sorted(set(s1) & set(s2))

    print(f"\n{'Function':<28}  {'Build 1':>18}  {'Build 2':>18}  Result")
    print("-" * 78)
    different = 0
    for fn in common:
        a1, a2 = s1[fn], s2[fn]
        if a1 != a2:
            result = "DIFFERENT"
            different += 1
        else:
            result = "same"
        print(f"{fn:<28}  {a1:#020x}  {a2:#020x}  {result}")

    print("-" * 78)
    print(f"\n{different}/{len(common)} functions at different addresses.\n")


if __name__ == "__main__":
    main()
