#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="${ROOT}/build"

cmake -S "${ROOT}" -B "${BUILD_DIR}" "${@}"
cmake --build "${BUILD_DIR}" -j
"${BUILD_DIR}/fhe_conv" --rounds 5 --random-tests 5
