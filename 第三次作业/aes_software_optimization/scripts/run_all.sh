#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$ROOT/build" -j
ctest --test-dir "$ROOT/build" --output-on-failure
"$ROOT/build/aeslab_bench" --bytes $((16*1024*1024)) --iters 8
"$ROOT/build/aeslab_bench" --bytes $((16*1024*1024)) --iters 8 --csv > "$ROOT/report/benchmark.csv"
echo "CSV written to report/benchmark.csv"
