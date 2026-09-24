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
return. So the real question is what happened to *those*. The tool disassembles
both variants with [Nyxstone](https://github.com/emproof-com/nyxstone),
enumerates return-terminated gadgets, matches them between variants by
`(containing function, offset within it, bytes)`, and reports what changed.

```
$ python3 gadgets.py node_01 node_02          # x86-64, Linux

Gadgets found      17 / 17   (12 / 12 distinct sequences)
Byte sequences present in both   11 (91.7% of variant A) -- none were destroyed

Gadgets matched by function and offset   16
  relocated            7 (43.8%)
  same address         9
    these sit in code divcc does not shuffle:
      do_global_dtors_aux          5
      register_tm_clones           2
      deregister_tm_clones         2
```

Three things fall out, and none of them flatter the technique:

**No gadget is destroyed.** Shuffling link order does not rewrite instructions,
so every sequence that existed before still exists afterwards. The technique
relocates an attacker's building blocks; it does not remove them.

**Matched gadgets keep their offset inside their own function.** That is true by
construction -- objects move as units -- and it is the limitation that matters.
An attacker who leaks a single pointer into an object can compute every gadget
in it. Diversification costs them one info leak, not an exploit.

**On x86-64, more than half the gadgets never move at all.** Every unmoved one
sits in C runtime startup code that the compiler driver links in: `crt` object
files a source-level wrapper never sees. A tool that works on the finished
binary reaches them; one that wraps the compiler cannot. On AArch64 the same
measurement reports 100% relocation, because that startup code does not
contribute return-terminated gadgets to the text section there.

That last point is the honest argument against this whole approach, and it is
why production systems apply diversity at instruction level on the linked
image rather than by reordering objects.

### A bug this found

`divcc` originally pinned `main.c` last in every variant, with a comment
claiming the entry point needed it. It did not -- the linker resolves the entry
through the symbol table. The measurement showed `main` holding gadgets that
never moved, which is the opposite of the point. Every object now takes part in
the shuffle.

### Running it

`gadgets.py` needs two libraries the rest of the repo does not:

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
  text section. On AArch64 and RISC-V, with fixed-width instructions, that sees
  everything. On x86 it undercounts badly: many real gadgets appear only when
  decoding starts at an unaligned offset inside another instruction.
- **Returns only.** Sequences ending in an indirect jump or call are not
  counted, so the true gadget population is larger than reported.
- **Symbol-relative attribution.** Gadgets are assigned to the nearest preceding
  symbol. In a stripped binary there is nothing to anchor to and the comparison
  degrades to byte-level only.
- **A toy program.** Nine functions in one translation unit each. The
  proportions here should not be read as typical of real firmware.

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
