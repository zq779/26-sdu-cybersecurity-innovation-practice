#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "build" / "sm3_cli"


def openssl_sm3(path: Path) -> str:
    p = subprocess.run(
        ["openssl", "dgst", "-sm3", "-r", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return p.stdout.split()[0].lower()


def main() -> int:
    if not CLI.exists():
        print(f"missing {CLI}; run make first", file=sys.stderr)
        return 2
    lengths = [0, 1, 2, 3, 31, 55, 56, 57, 63, 64, 65, 119, 120, 121,
               127, 128, 129, 255, 256, 1024, 4096, 8192]
    rng = random.Random(20260727)
    lengths += [rng.randrange(0, 10000) for _ in range(106)]

    with tempfile.TemporaryDirectory(prefix="sm3-diff-") as td:
        paths = []
        for idx, length in enumerate(lengths):
            data = bytes(rng.randrange(256) for _ in range(length))
            path = Path(td) / f"case-{idx:03d}-{length}.bin"
            path.write_bytes(data)
            paths.append(path)

        actual = {}
        for start in range(0, len(paths), 32):
            chunk = paths[start:start + 32]
            p = subprocess.run(
                [str(CLI), *map(str, chunk)],
                check=True,
                capture_output=True,
                text=True,
            )
            for line in p.stdout.splitlines():
                digest, filename = line.split(maxsplit=1)
                actual[Path(filename).name] = digest.lower()

        for path in paths:
            expected = openssl_sm3(path)
            got = actual.get(path.name)
            if got != expected:
                print(f"[FAIL] {path.name}: got={got} expected={expected}")
                return 1

    print(f"[PASS] {len(lengths)} files matched OpenSSL SM3; backend auto-dispatch exercised")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
