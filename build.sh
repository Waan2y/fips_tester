#!/usr/bin/env bash
set -euo pipefail

# Debug build only.
cargo build

# Convenience: place the binary at repo root.
cp -f "target/debug/fips_tester" "./fips_tester"
chmod +x "./fips_tester"

echo "Built ./fips_tester (debug)"
