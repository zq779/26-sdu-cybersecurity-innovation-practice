#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
CC_BIN=${CC:-cc}
mkdir -p results

{
  date -Is
  uname -a
  command -v lscpu >/dev/null && lscpu | grep -E 'Architecture|Model name|CPU\(s\)|Thread|Core|Socket|Flags' | head -n 12 || true
  "$CC_BIN" --version | head -n 1
  openssl version || true
} > results/environment.txt 2>&1

make clean
make -j"$(nproc)" all
./build/sm3_test | tee results/correctness.txt
./scripts/verify_openssl.py | tee results/openssl-differential.txt
./build/sm3_bench 4096 "${TOTAL_MIB:-256}" | tee results/benchmark.txt
make asm-check | tee results/disassembly-summary.txt

make sanitize 2>&1 | tee results/sanitizer.txt
make clean
make -j"$(nproc)" all

echo "Validation artifacts written to $ROOT/results"
