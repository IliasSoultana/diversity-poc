# diversity-poc

[![CI](https://github.com/IliasSoultana/diversity-poc/actions/workflows/ci.yml/badge.svg)](https://github.com/IliasSoultana/diversity-poc/actions/workflows/ci.yml)

A proof-of-concept demonstrating compiler-level software diversity.

Each build is **functionally identical** (same source, same output), but
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
| `divcc` | Compiler wrapper, reads `VARIANT_SEED`, shuffles link order |
| `compare.py` | Compares function addresses between two builds |
| `demo.sh` | Builds two nodes and runs the comparison |
| `src/` | Demo firmware split into one file per function |

## Measuring what it actually costs an attacker

`compare.py` answers the easy question: did the functions move. `gadgets.py`
asks the one that decides whether the mitigation is worth anything.

A return-oriented exploit is built from short instruction sequences ending in a
return. So the real question is what happens to *those*. The tool disassembles
both variants with [Nyxstone](https://github.com/emproof-com/nyxstone),
enumerates gadgets, matches them between variants by `(containing function,
offset within it, bytes)`, and reports what changed.

### Finding the gadgets

On **fixed-width** targets (AArch64, RISC-V) every instruction starts on a
4-byte boundary, so one linear sweep sees all of them.

On **x86** an instruction may start at any byte, so a return opcode inside the
immediate of a longer instruction is still executable by jumping into the
middle of it. These *unintended* gadgets are invisible to a linear sweep and
are most of what a real chain is built from:

```
movabs rbx, 0xc35fc35f      ->  48 bb 5f c3 5f c3 00 00 00 00
                                      ^^^^^
                                      pop rdi ; ret
```

One instruction to a linear decoder; a usable gadget two bytes in. So on x86
the tool scans for return opcodes and decodes backwards from each, keeping the
starts that decode cleanly and land exactly on the return.

### Result

```
$ python3 gadgets.py node_01 node_02          # x86-64, Linux

Gadgets found      32 / 34   (31 / 33 distinct sequences)
Byte sequences present in both   30 (96.8% of variant A)

Gadgets matched by function and offset   27
  relocated            7 (25.9%)
  same address         20
    these sit in code divcc does not shuffle:
      do_global_dtors_aux          10
      register_tm_clones           6
      deregister_tm_clones         4
```

Four things fall out, and none of them flatter the technique:

**Almost nothing is destroyed.** 96.8% of sequences exist in both variants.
Shuffling relocates an attacker's building blocks rather than removing them.
The missing few are unintended gadgets that appear or vanish at object
boundaries as alignment padding shifts. That is a side effect, not a defence.

**Matched gadgets keep their offset inside their own function.** True by
construction, since objects move as units, and it is the limitation that
matters: an attacker who leaks one pointer into an object can compute every
gadget in it. Diversification costs them one info leak, not an exploit.

**On x86-64 roughly three quarters never move at all.** Every unmoved one sits
in C runtime startup code the compiler driver links in, `crt` objects a
source-level wrapper never sees. A tool that rewrites the finished binary
reaches them; one that wraps the compiler cannot.

**Counting properly makes it worse.** Before unaligned decoding was
implemented, the same comparison reported 17 gadgets and 43.8% relocation. With
the unintended gadgets included it is 32 and 25.9%. The naive measurement
flattered the tool by roughly a factor of two.

That last point is the honest argument against this whole approach, and it is
why production systems apply diversity at instruction level on the linked image
rather than by reordering objects.

### A bug this found

`divcc` originally pinned `main.c` last in every variant, with a comment
claiming the entry point needed it. It does not; the linker resolves the entry
through the symbol table. The measurement showed `main` holding gadgets that
never moved, which is the opposite of the point. Every object now takes part in
the shuffle.

### Validation

Measuring only your own toy program proves very little, so `gadgets.py` also
runs against binaries this project did not build, checked two ways:

```
$ python3 validate_against_ropgadget.py /usr/bin/ls /usr/bin/ssh

/usr/bin/ls
  reported                1778
  self-consistent         1778
  no false positives
  also found by ROPgadget 1570 of 1778 (88.3%)
```

**Self-consistency** is the hard check and needs no reference tool: every
reported gadget must re-decode to exactly its own bytes and end in a return. A
tool cannot fake that. Zero failures across `ls`, `ssh` and `bash`.

**Agreement with [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)** is
measured but not treated as an oracle. ROPgadget filters `ret imm16` encodings
and some odd sequences from unaligned decodes; this tool does not. So the ~12%
residual is a policy difference, not a defect, and only a large drop would
signal a real divergence.

Getting that comparison right took three attempts, which is itself the lesson:
at first ROPgadget deduplicates identical gadget strings unless `--all` is
passed (18.8% agreement), and then it bounds its backward search by instruction
depth, so at equal depth its set is narrower than ours near the window edge
(49.8%). Only with `--all` and a larger depth is it a genuine superset (88.3%).

### Running it

```
pip install -r requirements-gadgets.txt
python3 -m pytest tests/ -q
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

- **Returns only.** Sequences ending in an indirect jump or call are not
  counted, so the real gadget population is larger than reported.
- **Four instructions, twenty bytes.** Longer gadgets exist and are excluded.
- **Symbol-relative attribution.** Gadgets are assigned to the nearest preceding
  symbol; in a stripped binary there is nothing to anchor to and the comparison
  degrades to byte level.
- **A toy program.** Nine functions of one line each. The proportions here
  should not be read as typical of real firmware, which is exactly why the
  validation runs against system binaries instead.

## Rewriting the finished binary

The measurement above is an argument against link-order shuffling: it relocates
whole objects, so gadget *bodies* survive byte-identical. `rewrite.py` does the
thing that argument points to instead: it edits the linked binary directly,
with no source and no recompilation.

x86-64 encodes every register-to-register ALU instruction two ways. `mov rax,
rbx` is either `48 89 d8` (opcode `0x89`, destination in r/m) or `48 8b c3`
(opcode `0x8b`, destination in reg). Same length, same effect, different bytes.
Swapping between them changes the contents of a function rather than just its
address. That is the property divcc could not reach.

```
$ python3 rewrite.py original -o rewritten --seed 1337
reg-reg candidates          26
verified equivalent         26
backed out (desync)         0
rewritten                   16
```

On a small test program CI compiles, rewrites and runs on every push: 26
candidate instructions inside known functions, 16 rewritten under the seed, 28
bytes changed, and the rewritten binary produces identical output. CI does not
take that on trust: it applies each of the 26 substitutions *individually*, runs
the binary, and fails unless the output is unchanged. Execution is the ground
truth an in-tool equivalence check can only approximate.

### What it deliberately does not do

- **Same-length substitutions only.** Changing an instruction's length would
  shift everything after it and require relocating every address that refers
  past the edit. That is the hard part of real binary rewriting, and it is out
  of scope here.
- **Register-to-register ALU ops only** (`mov`, `add`, `sub`, `and`, `or`,
  `xor`, `cmp`), the instructions with a clean dual encoding.
- **Nothing is trusted unverified.** Every candidate replacement is
  disassembled and checked to mean exactly what the original meant; a transform
  the tool cannot prove equivalent is skipped, not guessed.

### Two things this shook out

The rewriter restricts edits to bytes inside a function symbol's range. An
earlier version swept the whole `.text`, which risks rewriting data that happens
to decode as a valid instruction but is read rather than executed. Rewriting it changes a
value, not an instruction.

The per-substitution execution check earned its place immediately: the first
version of the CI harness ran the binary under `bash -e`, and the sample program
returned a non-zero status by design, so the script aborted on that exit code
and reported a "behavioural failure" that was entirely in the test, not the
tool. Verifying by execution is only as good as the harness that does the
executing.

This is a miniature of what a product like [emproof
Nyx](https://www.emproof.com/) does at scale: instruction-level rewriting on a
compiled image, reduced to the one substitution that can be made provably safe
in a weekend.

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
  used for reverse engineering, string tables, magic values, call graph
  shape, are unchanged, so identifying the firmware is no harder.
- **Nothing is hardened.** This changes where code sits, not whether it is
  exploitable. A buffer overflow remains a buffer overflow.
- **It needs the source.** This acts inside the toolchain, so it cannot be
  applied to a vendored blob or a binary you cannot rebuild, which is
  precisely the case in much of the embedded supply chain.

Production systems layer finer-grained techniques on top: instruction
scheduling variation, register allocation randomisation, dead-code insertion
and padding, randomised stack frame layout, and, where source is unavailable,
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
