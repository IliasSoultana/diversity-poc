#!/usr/bin/env bash
# demo.sh — build the firmware twice with different seeds, then compare layouts.
set -e

echo "=== diversity-poc demo ==="
echo ""
echo "Building node_01 with VARIANT_SEED=0xb2e1 ..."
VARIANT_SEED=0xb2e1 python3 divcc src/ -o node_01

echo ""
echo "Building node_02 with VARIANT_SEED=0x61a7 ..."
VARIANT_SEED=0x61a7 python3 divcc src/ -o node_02

echo ""
echo "Both binaries produce identical output:"
echo "--- node_01 ---"
./node_01
echo "--- node_02 ---"
./node_02

echo ""
echo "Function layout comparison:"
python3 compare.py node_01 node_02
