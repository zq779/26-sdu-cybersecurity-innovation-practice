#!/usr/bin/env python3
"""Build deterministic sample files used by the project tests.

The block sample is Bitcoin Testnet4's genesis block, reconstructed from the
parameters in Bitcoin Core's chainparams.cpp.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent
SAMPLES = ROOT / "samples"
SAMPLES.mkdir(exist_ok=True)


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


msg = b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
coinbase_script = bytes.fromhex("04ffff001d0104") + b"\x4c" + bytes([len(msg)]) + msg
output_script = b"\x21" + bytes(33) + b"\xac"
tx = (
    (1).to_bytes(4, "little")
    + compact_size(1)
    + bytes(32)
    + (0xFFFFFFFF).to_bytes(4, "little")
    + compact_size(len(coinbase_script))
    + coinbase_script
    + (0xFFFFFFFF).to_bytes(4, "little")
    + compact_size(1)
    + (5_000_000_000).to_bytes(8, "little")
    + compact_size(len(output_script))
    + output_script
    + (0).to_bytes(4, "little")
)
txid_internal = sha256d(tx)
assert txid_internal[::-1].hex() == "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
header = (
    (1).to_bytes(4, "little")
    + bytes(32)
    + txid_internal
    + (1714777860).to_bytes(4, "little")
    + (0x1D00FFFF).to_bytes(4, "little")
    + (393743547).to_bytes(4, "little")
)
assert sha256d(header)[::-1].hex() == "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
block = header + compact_size(1) + tx

# A structurally valid SegWit serialization sample (not intended for broadcast).
segwit_tx = (
    (2).to_bytes(4, "little")
    + b"\x00\x01"
    + compact_size(1)
    + bytes.fromhex("11" * 32)
    + (0).to_bytes(4, "little")
    + compact_size(0)
    + (0xFFFFFFFD).to_bytes(4, "little")
    + compact_size(1)
    + (1000).to_bytes(8, "little")
    + compact_size(22)
    + bytes.fromhex("0014" + "22" * 20)
    + compact_size(2)
    + compact_size(71)
    + bytes.fromhex("30" * 71)
    + compact_size(33)
    + bytes.fromhex("02" + "33" * 32)
    + (0).to_bytes(4, "little")
)

(SAMPLES / "testnet4_genesis_tx.hex").write_text(tx.hex() + "\n", encoding="utf-8")
(SAMPLES / "testnet4_genesis_block.hex").write_text(block.hex() + "\n", encoding="utf-8")
(SAMPLES / "synthetic_segwit_tx.hex").write_text(segwit_tx.hex() + "\n", encoding="utf-8")
print("sample files generated")
