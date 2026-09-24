# diversity-poc

[![CI](https://github.com/IliasSoultana/diversity-poc/actions/workflows/ci.yml/badge.svg)](https://github.com/IliasSoultana/diversity-poc/actions/workflows/ci.yml)

A proof-of-concept demonstrating compiler-level software diversity.

Each build is **functionally identical** — same source, same output — but
structurally unique at the binary level.  An exploit crafted for one node is
useless against every other node.

## The problem

When every device in a fleet runs the same binary, an attacker who captures
one device and reverse-engineers it gains an exploit that works on the entire
fleet.  AI-driven toolchains make this even faster.

## The approach

`divcc` is a thin compiler wrapper around clang.  It takes a `VARIANT_SEED`
and uses it to shuffle the link order of object files.  The linker places
object files sequentially in the text segment, so a different seed produces
a different function layout.

```
VARIANT_SEED=0xb2e1  →  [log_event, process_sensor, run_pipeline, ...]
VARIANT_SEED=0x61a7  →  [log_event, run_pipeline, validate_input, ...]
```

Same code, different addresses.  An exploit that jumps to `process_sensor`
at `0x3e28` on node_01 lands in the wrong function on node_02.

## Demo

```bash
# Build two "devices" with different seeds
VARIANT_SEED=0xb2e1 python3 divcc src/ -o node_01
VARIANT_SEED=0x61a7 python3 divcc src/ -o node_02

# Confirm identical behaviour
./node_01
./node_02

# Show layout differences
python3 compare.py node_01 node_02
```

Expected output (addresses will differ on your machine):

```
Function                       Build 1               Build 2   Result
----------------------------------------------------------------------
calibrate            0x0000000100003ee4  0x0000000100003ee8  DIFFERENT
handle_error         0x0000000100003ebc  0x0000000100003e70  DIFFERENT
process_sensor       0x0000000100003e28  0x0000000100003e98  DIFFERENT
...
8/9 functions at different addresses.
```

Or just run the full demo:

```bash
bash demo.sh
```

## Files

| File | Purpose |
|---|---|
| `divcc` | Compiler wrapper — reads `VARIANT_SEED`, shuffles link order |
| `compare.py` | Compares function addresses between two builds |
| `demo.sh` | Builds two nodes and runs the comparison |
| `src/` | Demo firmware split into one file per function |

## Measuring what it actually costs an attacker

`compare.py` answers the easy question -- did the functions move. `gadgets.py`
asks the one that decides whether the mitigation is worth anything.

A return-oriented exploit is built from short instruction sequences ending in a
return. So the question is not whether functions moved, but what happened to
those sequences. The tool disassembles both variants with
[Nyxstone](https://github.com/emproof-com/nyxstone), enumerates gadgets, and
compares them three ways:

```
$ python3 gadgets.py node_01 node_02

Gadgets found      16 / 16   (10 / 10 distinct sequences)
Survived the shuffle   10 sequences (100.0% of variant A)
  at a new address     10
  at the same address  0

Same offset inside the same function   10 (100.0%)
Different offset                       0
```

Read that carefully, because it is not a flattering result:

| Measurement | Result | What it means |
|---|---|---|
| Gadget count | identical | Shuffling link order neither adds nor removes code |
| Byte sequences surviving | **100%** | Every gadget still exists; none were destroyed |
| Moved to a new address | **100%** | An exploit with hardcoded addresses does break |
| Same offset within its function | **100%** | One leaked function pointer recovers every gadget in that object |

So link-order diversification defeats an attacker who hardcodes addresses, and
costs an attacker who has any info-leak primitive exactly one leak. That is a
real but narrow benefit, and it is the honest case for why production systems
do the work at instruction level rather than at link level.

### Running it

`gadgets.py` needs two libraries that the rest of the repo does not:

```
pip install -r requirements-gadgets.txt
```

Nyxstone builds against a system LLVM between versions 15 and 20:

```
# Debian/Ubuntu
sudo apt install llvm-18-dev
export NYXSTONE_LLVM_PREFIX=/usr/lib/llvm-18

# macOS
brew install llvm@19 zstd
export NYXSTONE_LLVM_PREFIX="$(brew --prefix llvm@19)"
export LDFLAGS="-L$(brew --prefix zstd)/lib" CXXFLAGS="-std=c++17"
```

### Limitations of the measurement

- **Linear sweep.** Instructions are decoded sequentially from the start of the
  text section. On AArch64 and RISC-V, where instructions are fixed width, that
  sees everything. On x86 it undercounts: many real gadgets only appear when
  decoding starts at an unaligned offset inside another instruction.
- **Returns only.** Gadgets ending in an indirect jump or call are not counted,
  so the true gadget population is larger than reported.
- **Gadgets are attributed to the nearest preceding symbol.** With a stripped
  binary, or across a section with no symbols, the offset comparison has
  nothing to anchor to and is skipped.

## What this does not protect against

Link-order shuffling is the coarsest form of software diversity, and it is
worth being precise about where it stops helping:

- **It moves objects, not instructions.** Function bodies are byte-identical
  across variants. Any gadget inside a function keeps its offset relative to
  that function's entry, so an attacker who learns one address learns every
  address within the same object.
- **One leak collapses it.** The whole benefit rests on the attacker not
  knowing the layout. A single info-leak primitive that discloses a function
  pointer re-anchors the rest, and diversity buys nothing further.
- **It does not touch control flow, constants or data layout.** Signatures
  used for reverse engineering — string tables, magic values, call graph
  shape — are unchanged, so identifying the firmware is no harder.
- **Nothing is hardened.** This changes where code sits, not whether it is
  exploitable. A buffer overflow remains a buffer overflow.
- **It needs the source.** This acts inside the toolchain, so it cannot be
  applied to a vendored blob or a binary you cannot rebuild — which is
  precisely the case in much of the embedded supply chain.

Production systems layer finer-grained techniques on top: instruction
scheduling variation, register allocation randomisation, dead-code insertion
and padding, randomised stack frame layout — and, where source is unavailable,
binary rewriting rather than a compiler wrapper.

The principle demonstrated here is the same: same source, unique binary,
per-device seed.

## Properties under test

CI builds three variants on every push and asserts all three properties that
make this worth doing at all:

| Property | Why it matters | How it is checked |
|---|---|---|
| **Functional equivalence** | A variant that behaves differently is a miscompile, not a mitigation | `node_01` and `node_02` must produce byte-identical output |
| **Layout divergence** | The security property itself | `compare.py` must report at least 5 of 9 functions relocated |
| **Seed determinism** | You must be able to rebuild the exact image a given unit is running | The same seed twice must relocate nothing |

The third is the one that is easy to forget. Per-device randomisation is
useless in the field if you cannot reproduce a specific device's binary when
it crashes.
