# diversity-poc

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

## Limitations

This PoC uses **link-order shuffling**, the simplest form of software
diversity.  Production systems use additional techniques such as:

- Instruction-level scheduling variation
- Register allocation randomisation  
- Dead-code insertion and padding
- Randomised stack frame layout

The principle demonstrated here is the same: same source, unique binary,
per-device seed.
