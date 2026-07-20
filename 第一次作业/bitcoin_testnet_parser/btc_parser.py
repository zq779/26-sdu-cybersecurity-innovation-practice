#!/usr/bin/env python3
"""Bitcoin raw transaction/block byte-and-bit parser.

Standard-library only. Supports legacy and SegWit transaction serialization,
Bitcoin Script disassembly, TXID/WTXID, block header/PoW target, and merkle-root
verification. Designed for Bitcoin Core testnet4 coursework, but the binary
formats are shared by mainnet/testnet/signet/regtest.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


class ParseError(ValueError):
    pass


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def display_hash(serialized_32: bytes) -> str:
    """Convert Bitcoin's serialized little-endian uint256 to display hex."""
    return serialized_32[::-1].hex()


def decode_script_num(data: bytes) -> int:
    if not data:
        return 0
    value = int.from_bytes(data, "little")
    if data[-1] & 0x80:
        value &= ~(0x80 << (8 * (len(data) - 1)))
        return -value
    return value


def compact_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    negative = bool(bits & 0x00800000)
    if negative or mantissa == 0:
        return 0
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def calculate_merkle_root(txids_display: Iterable[str]) -> str:
    level = [bytes.fromhex(txid)[::-1] for txid in txids_display]
    if not level:
        return ""
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0][::-1].hex()


@dataclass
class FieldRecord:
    name: str
    offset: int
    size: int
    hex: str
    binary: str
    decoded: Any = None
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        out = {
            "name": self.name,
            "offset": self.offset,
            "bit_offset": self.offset * 8,
            "size": self.size,
            "hex": self.hex,
            "binary": self.binary,
        }
        if self.decoded is not None:
            out["decoded"] = self.decoded
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class ParseContext:
    fields: list[FieldRecord] = field(default_factory=list)

    def add(self, name: str, offset: int, raw: bytes, decoded: Any = None, note: str = "") -> None:
        self.fields.append(
            FieldRecord(
                name=name,
                offset=offset,
                size=len(raw),
                hex=raw.hex(),
                binary=" ".join(f"{b:08b}" for b in raw),
                decoded=decoded,
                note=note,
            )
        )


class Reader:
    def __init__(self, data: bytes, ctx: Optional[ParseContext] = None, base_offset: int = 0):
        self.data = data
        self.pos = 0
        self.ctx = ctx or ParseContext()
        self.base_offset = base_offset

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def peek(self, n: int = 1) -> bytes:
        if self.pos + n > len(self.data):
            raise ParseError(f"need {n} byte(s) at offset {self.base_offset + self.pos}, only {self.remaining()} remain")
        return self.data[self.pos : self.pos + n]

    def take(self, n: int, name: str, decoded: Any = None, note: str = "") -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ParseError(f"field {name}: need {n} byte(s) at offset {self.base_offset + self.pos}, only {self.remaining()} remain")
        start = self.pos
        raw = self.data[start : start + n]
        self.pos += n
        self.ctx.add(name, self.base_offset + start, raw, decoded=decoded, note=note)
        return raw

    def u32le(self, name: str, note: str = "") -> int:
        start = self.pos
        raw = self.peek(4)
        value = int.from_bytes(raw, "little")
        self.take(4, name, decoded=value, note=note)
        return value

    def u64le(self, name: str, note: str = "") -> int:
        raw = self.peek(8)
        value = int.from_bytes(raw, "little")
        self.take(8, name, decoded=value, note=note)
        return value

    def compact_size(self, name: str) -> tuple[int, bytes]:
        start = self.pos
        first = self.peek(1)[0]
        if first < 0xFD:
            raw = self.data[self.pos : self.pos + 1]
            value = first
            self.pos += 1
        elif first == 0xFD:
            raw = self.peek(3)
            value = int.from_bytes(raw[1:], "little")
            if value < 0xFD:
                raise ParseError(f"non-canonical CompactSize at offset {self.base_offset + start}")
            self.pos += 3
        elif first == 0xFE:
            raw = self.peek(5)
            value = int.from_bytes(raw[1:], "little")
            if value <= 0xFFFF:
                raise ParseError(f"non-canonical CompactSize at offset {self.base_offset + start}")
            self.pos += 5
        else:
            raw = self.peek(9)
            value = int.from_bytes(raw[1:], "little")
            if value <= 0xFFFFFFFF:
                raise ParseError(f"non-canonical CompactSize at offset {self.base_offset + start}")
            self.pos += 9
        self.ctx.add(name, self.base_offset + start, raw, decoded=value, note="Bitcoin CompactSize unsigned integer")
        return value, raw


OPCODES: dict[int, str] = {
    0x00: "OP_0",
    0x4C: "OP_PUSHDATA1",
    0x4D: "OP_PUSHDATA2",
    0x4E: "OP_PUSHDATA4",
    0x4F: "OP_1NEGATE",
    0x50: "OP_RESERVED",
    0x61: "OP_NOP",
    0x62: "OP_VER",
    0x63: "OP_IF",
    0x64: "OP_NOTIF",
    0x65: "OP_VERIF",
    0x66: "OP_VERNOTIF",
    0x67: "OP_ELSE",
    0x68: "OP_ENDIF",
    0x69: "OP_VERIFY",
    0x6A: "OP_RETURN",
    0x6B: "OP_TOALTSTACK",
    0x6C: "OP_FROMALTSTACK",
    0x6D: "OP_2DROP",
    0x6E: "OP_2DUP",
    0x6F: "OP_3DUP",
    0x70: "OP_2OVER",
    0x71: "OP_2ROT",
    0x72: "OP_2SWAP",
    0x73: "OP_IFDUP",
    0x74: "OP_DEPTH",
    0x75: "OP_DROP",
    0x76: "OP_DUP",
    0x77: "OP_NIP",
    0x78: "OP_OVER",
    0x79: "OP_PICK",
    0x7A: "OP_ROLL",
    0x7B: "OP_ROT",
    0x7C: "OP_SWAP",
    0x7D: "OP_TUCK",
    0x7E: "OP_CAT_DISABLED",
    0x7F: "OP_SUBSTR_DISABLED",
    0x80: "OP_LEFT_DISABLED",
    0x81: "OP_RIGHT_DISABLED",
    0x82: "OP_SIZE",
    0x83: "OP_INVERT_DISABLED",
    0x84: "OP_AND_DISABLED",
    0x85: "OP_OR_DISABLED",
    0x86: "OP_XOR_DISABLED",
    0x87: "OP_EQUAL",
    0x88: "OP_EQUALVERIFY",
    0x89: "OP_RESERVED1",
    0x8A: "OP_RESERVED2",
    0x8B: "OP_1ADD",
    0x8C: "OP_1SUB",
    0x8D: "OP_2MUL_DISABLED",
    0x8E: "OP_2DIV_DISABLED",
    0x8F: "OP_NEGATE",
    0x90: "OP_ABS",
    0x91: "OP_NOT",
    0x92: "OP_0NOTEQUAL",
    0x93: "OP_ADD",
    0x94: "OP_SUB",
    0x95: "OP_MUL_DISABLED",
    0x96: "OP_DIV_DISABLED",
    0x97: "OP_MOD_DISABLED",
    0x98: "OP_LSHIFT_DISABLED",
    0x99: "OP_RSHIFT_DISABLED",
    0x9A: "OP_BOOLAND",
    0x9B: "OP_BOOLOR",
    0x9C: "OP_NUMEQUAL",
    0x9D: "OP_NUMEQUALVERIFY",
    0x9E: "OP_NUMNOTEQUAL",
    0x9F: "OP_LESSTHAN",
    0xA0: "OP_GREATERTHAN",
    0xA1: "OP_LESSTHANOREQUAL",
    0xA2: "OP_GREATERTHANOREQUAL",
    0xA3: "OP_MIN",
    0xA4: "OP_MAX",
    0xA5: "OP_WITHIN",
    0xA6: "OP_RIPEMD160",
    0xA7: "OP_SHA1",
    0xA8: "OP_SHA256",
    0xA9: "OP_HASH160",
    0xAA: "OP_HASH256",
    0xAB: "OP_CODESEPARATOR",
    0xAC: "OP_CHECKSIG",
    0xAD: "OP_CHECKSIGVERIFY",
    0xAE: "OP_CHECKMULTISIG",
    0xAF: "OP_CHECKMULTISIGVERIFY",
    0xB0: "OP_NOP1",
    0xB1: "OP_CHECKLOCKTIMEVERIFY",
    0xB2: "OP_CHECKSEQUENCEVERIFY",
    0xB3: "OP_NOP4",
    0xB4: "OP_NOP5",
    0xB5: "OP_NOP6",
    0xB6: "OP_NOP7",
    0xB7: "OP_NOP8",
    0xB8: "OP_NOP9",
    0xB9: "OP_NOP10",
    0xBA: "OP_CHECKSIGADD",
}
for i in range(1, 17):
    OPCODES[0x50 + i] = f"OP_{i}"


def printable_ascii(data: bytes) -> Optional[str]:
    if not data:
        return ""
    if all(32 <= b < 127 for b in data):
        return data.decode("ascii")
    return None


def parse_script(script: bytes) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    p = 0
    while p < len(script):
        op_offset = p
        opcode = script[p]
        p += 1
        item: dict[str, Any] = {"offset": op_offset, "opcode": f"0x{opcode:02x}"}
        if 1 <= opcode <= 75:
            length = opcode
            item["name"] = f"PUSH_{length}"
        elif opcode == 0x4C:
            if p + 1 > len(script):
                item["error"] = "truncated OP_PUSHDATA1 length"
                items.append(item)
                break
            length = script[p]
            item["length_bytes"] = script[p : p + 1].hex()
            p += 1
            item["name"] = "OP_PUSHDATA1"
        elif opcode == 0x4D:
            if p + 2 > len(script):
                item["error"] = "truncated OP_PUSHDATA2 length"
                items.append(item)
                break
            length = int.from_bytes(script[p : p + 2], "little")
            item["length_bytes"] = script[p : p + 2].hex()
            p += 2
            item["name"] = "OP_PUSHDATA2"
        elif opcode == 0x4E:
            if p + 4 > len(script):
                item["error"] = "truncated OP_PUSHDATA4 length"
                items.append(item)
                break
            length = int.from_bytes(script[p : p + 4], "little")
            item["length_bytes"] = script[p : p + 4].hex()
            p += 4
            item["name"] = "OP_PUSHDATA4"
        else:
            item["name"] = OPCODES.get(opcode, f"OP_UNKNOWN_{opcode:02X}")
            items.append(item)
            continue

        if p + length > len(script):
            item["error"] = f"push requests {length} byte(s), only {len(script) - p} remain"
            item["data"] = script[p:].hex()
            items.append(item)
            break
        pushed = script[p : p + length]
        p += length
        item["data_length"] = length
        item["data"] = pushed.hex()
        text = printable_ascii(pushed)
        if text is not None:
            item["ascii"] = text
        item["script_num"] = decode_script_num(pushed)
        items.append(item)
    return items


def classify_script(script: bytes) -> str:
    if len(script) == 25 and script[:3] == bytes.fromhex("76a914") and script[-2:] == bytes.fromhex("88ac"):
        return "P2PKH"
    if len(script) == 23 and script[:2] == bytes.fromhex("a914") and script[-1:] == bytes.fromhex("87"):
        return "P2SH"
    if len(script) == 22 and script[:2] == bytes.fromhex("0014"):
        return "P2WPKH (SegWit v0)"
    if len(script) == 34 and script[:2] == bytes.fromhex("0020"):
        return "P2WSH (SegWit v0)"
    if len(script) == 34 and script[:2] == bytes.fromhex("5120"):
        return "P2TR (Taproot / SegWit v1)"
    if script[:1] == bytes.fromhex("6a"):
        return "OP_RETURN / nulldata"
    if len(script) in (35, 67) and script[-1:] == bytes.fromhex("ac"):
        return "P2PK"
    return "nonstandard or unclassified"


def parse_transaction(reader: Reader, prefix: str = "tx") -> dict[str, Any]:
    start = reader.pos
    version_start = reader.pos
    version = reader.u32le(f"{prefix}.version", note="transaction format version")
    version_raw = reader.data[version_start : reader.pos]

    segwit = False
    marker_flag = b""
    if reader.remaining() >= 2 and reader.peek(1) == b"\x00" and reader.peek(2)[1] != 0:
        segwit = True
        marker = reader.take(1, f"{prefix}.marker", decoded=0, note="SegWit marker")
        flag_value = reader.peek(1)[0]
        flag = reader.take(1, f"{prefix}.flag", decoded=flag_value, note="SegWit serialization flag")
        marker_flag = marker + flag

    vin_section_start = reader.pos
    vin_count, _ = reader.compact_size(f"{prefix}.vin_count")
    if vin_count > 1_000_000:
        raise ParseError(f"unreasonable input count: {vin_count}")

    inputs: list[dict[str, Any]] = []
    for i in range(vin_count):
        ip = f"{prefix}.vin[{i}]"
        prev_raw = reader.peek(32)
        prev_txid = display_hash(prev_raw)
        reader.take(32, f"{ip}.prev_txid", decoded=prev_txid, note="serialized little-endian transaction hash")
        prev_vout = reader.u32le(f"{ip}.prev_vout", note="index of spent output; 0xffffffff for coinbase")
        script_len, _ = reader.compact_size(f"{ip}.scriptSig_length")
        if script_len > reader.remaining():
            raise ParseError(f"{ip}: scriptSig length exceeds remaining bytes")
        script = reader.take(script_len, f"{ip}.scriptSig", decoded={"type": "unlocking script", "length": script_len})
        sequence = reader.u32le(f"{ip}.sequence")
        inputs.append(
            {
                "prev_txid": prev_txid,
                "prev_vout": prev_vout,
                "scriptSig_hex": script.hex(),
                "scriptSig_asm": parse_script(script),
                "sequence": sequence,
            }
        )

    vout_count, _ = reader.compact_size(f"{prefix}.vout_count")
    if vout_count > 1_000_000:
        raise ParseError(f"unreasonable output count: {vout_count}")
    outputs: list[dict[str, Any]] = []
    for i in range(vout_count):
        op = f"{prefix}.vout[{i}]"
        value = reader.u64le(f"{op}.value_satoshis", note="1 BTC = 100,000,000 satoshis")
        script_len, _ = reader.compact_size(f"{op}.scriptPubKey_length")
        if script_len > reader.remaining():
            raise ParseError(f"{op}: scriptPubKey length exceeds remaining bytes")
        script = reader.take(script_len, f"{op}.scriptPubKey", decoded={"type": "locking script", "length": script_len})
        outputs.append(
            {
                "value_satoshis": value,
                "value_btc": f"{value / 100_000_000:.8f}",
                "scriptPubKey_hex": script.hex(),
                "script_type": classify_script(script),
                "scriptPubKey_asm": parse_script(script),
            }
        )

    witness_start = reader.pos
    witnesses: list[list[dict[str, Any]]] = []
    if segwit:
        for i in range(vin_count):
            wp = f"{prefix}.vin[{i}].witness"
            item_count, _ = reader.compact_size(f"{wp}.item_count")
            stack: list[dict[str, Any]] = []
            for j in range(item_count):
                length, _ = reader.compact_size(f"{wp}[{j}].length")
                if length > reader.remaining():
                    raise ParseError(f"{wp}[{j}]: witness item length exceeds remaining bytes")
                item = reader.take(length, f"{wp}[{j}].data", decoded={"length": length})
                stack.append({"length": length, "hex": item.hex(), "ascii": printable_ascii(item)})
            witnesses.append(stack)

    locktime_start = reader.pos
    locktime = reader.u32le(
        f"{prefix}.locktime",
        note="0 means immediately final; otherwise block height or Unix time depending on value",
    )
    end = reader.pos
    raw = reader.data[start:end]

    if segwit:
        stripped = version_raw + reader.data[vin_section_start:witness_start] + reader.data[locktime_start:end]
    else:
        stripped = raw

    txid = sha256d(stripped)[::-1].hex()
    wtxid = sha256d(raw)[::-1].hex()
    is_coinbase = (
        len(inputs) == 1
        and inputs[0]["prev_txid"] == "00" * 32
        and inputs[0]["prev_vout"] == 0xFFFFFFFF
    )
    coinbase_height = None
    if is_coinbase and inputs[0]["scriptSig_asm"]:
        first = inputs[0]["scriptSig_asm"][0]
        if "data" in first:
            coinbase_height = decode_script_num(bytes.fromhex(first["data"]))

    result: dict[str, Any] = {
        "offset": reader.base_offset + start,
        "size": end - start,
        "version": version,
        "segwit_serialization": segwit,
        "marker_flag": marker_flag.hex() if segwit else None,
        "vin_count": vin_count,
        "inputs": inputs,
        "vout_count": vout_count,
        "outputs": outputs,
        "witnesses": witnesses,
        "locktime": locktime,
        "txid": txid,
        "wtxid": wtxid,
        "is_coinbase": is_coinbase,
        "raw_hex": raw.hex(),
        "stripped_hex": stripped.hex(),
    }
    if coinbase_height is not None:
        result["coinbase_height_from_first_push"] = coinbase_height
    return result


def parse_tx_bytes(data: bytes) -> tuple[dict[str, Any], ParseContext]:
    ctx = ParseContext()
    reader = Reader(data, ctx)
    tx = parse_transaction(reader, "tx")
    if reader.remaining() != 0:
        raise ParseError(f"{reader.remaining()} trailing byte(s) after transaction")
    return {"kind": "transaction", "transaction": tx}, ctx


def parse_block_bytes(data: bytes) -> tuple[dict[str, Any], ParseContext]:
    ctx = ParseContext()
    reader = Reader(data, ctx)
    if len(data) < 81:
        raise ParseError("a serialized block needs at least an 80-byte header and transaction count")

    header_start = reader.pos
    version = reader.u32le("block.header.version")
    prev_raw = reader.peek(32)
    prev_hash = display_hash(prev_raw)
    reader.take(32, "block.header.previous_block_hash", decoded=prev_hash, note="serialized little-endian uint256")
    merkle_raw = reader.peek(32)
    merkle_root = display_hash(merkle_raw)
    reader.take(32, "block.header.merkle_root", decoded=merkle_root, note="serialized little-endian uint256")
    timestamp = reader.u32le("block.header.timestamp", note="Unix epoch seconds")
    bits = reader.u32le("block.header.bits", note="compact proof-of-work target (nBits)")
    nonce = reader.u32le("block.header.nonce")
    header_end = reader.pos
    header = data[header_start:header_end]
    block_hash = sha256d(header)[::-1].hex()
    target = compact_target(bits)
    target_hex = f"{target:064x}" if target else "0" * 64
    hash_value = int(block_hash, 16)
    pow_valid = bool(target and hash_value <= target)
    difficulty1_target = compact_target(0x1D00FFFF)
    difficulty = (difficulty1_target / target) if target else None

    tx_count, _ = reader.compact_size("block.tx_count")
    if tx_count > 10_000_000:
        raise ParseError(f"unreasonable transaction count: {tx_count}")
    txs = []
    for i in range(tx_count):
        txs.append(parse_transaction(reader, f"block.tx[{i}]"))
    if reader.remaining() != 0:
        raise ParseError(f"{reader.remaining()} trailing byte(s) after block")

    calculated_merkle = calculate_merkle_root(tx["txid"] for tx in txs)
    result = {
        "kind": "block",
        "block": {
            "size": len(data),
            "header_size": 80,
            "hash": block_hash,
            "version": version,
            "previous_block_hash": prev_hash,
            "merkle_root_in_header": merkle_root,
            "merkle_root_calculated": calculated_merkle,
            "merkle_root_valid": calculated_merkle == merkle_root,
            "timestamp": timestamp,
            "timestamp_utc": datetime.fromtimestamp(timestamp, timezone.utc).isoformat(),
            "bits_numeric": bits,
            "bits_hex": f"{bits:08x}",
            "target_hex": target_hex,
            "difficulty_relative_to_0x1d00ffff": difficulty,
            "nonce": nonce,
            "proof_of_work_valid": pow_valid,
            "tx_count": tx_count,
            "transactions": txs,
            "raw_hex": data.hex(),
        },
    }
    return result, ctx


def read_hex_argument(hex_text: Optional[str], file_path: Optional[str]) -> bytes:
    if bool(hex_text) == bool(file_path):
        raise ParseError("provide exactly one of --hex or --file")
    if file_path:
        text = Path(file_path).read_text(encoding="utf-8")
    else:
        text = hex_text or ""
    cleaned = "".join(text.split())
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ParseError(f"invalid hexadecimal input: {exc}") from exc


def ensure_complete_coverage(data: bytes, fields: list[FieldRecord]) -> list[int]:
    coverage = [0] * len(data)
    for f in fields:
        for i in range(f.offset, f.offset + f.size):
            if 0 <= i < len(data):
                coverage[i] += 1
    return [i for i, count in enumerate(coverage) if count != 1]


def write_reports(result: dict[str, Any], ctx: ParseContext, raw: bytes, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    fields = sorted(ctx.fields, key=lambda f: f.offset)
    bad_coverage = ensure_complete_coverage(raw, fields)
    result["parser_meta"] = {
        "raw_size_bytes": len(raw),
        "field_count": len(fields),
        "every_byte_covered_exactly_once": not bad_coverage,
        "coverage_problem_offsets": bad_coverage[:100],
    }
    result["fields"] = [f.as_dict() for f in fields]

    (out_dir / "parsed.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    with (out_dir / "bytes_and_bits.tsv").open("w", encoding="utf-8", newline="") as fp:
        fp.write("byte_offset\tbit_range\tfield\thex\tbinary\tdecoded_on_field_start\tnote\n")
        for f in fields:
            for j, b in enumerate(bytes.fromhex(f.hex)):
                offset = f.offset + j
                decoded = json.dumps(f.decoded, ensure_ascii=False) if j == 0 and f.decoded is not None else ""
                note = f.note if j == 0 else ""
                fp.write(
                    f"{offset}\t{offset * 8}-{offset * 8 + 7}\t{f.name}\t{b:02x}\t{b:08b}\t{decoded}\t{note}\n"
                )

    summary = result["transaction"] if result["kind"] == "transaction" else result["block"]
    lines = [
        f"kind: {result['kind']}",
        f"raw_size_bytes: {len(raw)}",
        f"every_byte_covered_exactly_once: {not bad_coverage}",
    ]
    if result["kind"] == "transaction":
        lines += [
            f"txid: {summary['txid']}",
            f"wtxid: {summary['wtxid']}",
            f"segwit_serialization: {summary['segwit_serialization']}",
            f"vin_count: {summary['vin_count']}",
            f"vout_count: {summary['vout_count']}",
            f"locktime: {summary['locktime']}",
        ]
    else:
        lines += [
            f"block_hash: {summary['hash']}",
            f"tx_count: {summary['tx_count']}",
            f"merkle_root_valid: {summary['merkle_root_valid']}",
            f"proof_of_work_valid: {summary['proof_of_work_valid']}",
            f"bits: {summary['bits_hex']}",
            f"target: {summary['target_hex']}",
        ]
    (out_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def rpc_call(url: str, method: str, params: list[Any], user: Optional[str], password: Optional[str]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": "byte-parser", "method": method, "params": params}).encode()
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    if user is not None or password is not None:
        token = base64.b64encode(f"{user or ''}:{password or ''}".encode()).decode()
        request.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise ParseError(f"RPC HTTP error {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ParseError(f"RPC connection failed: {exc}") from exc
    if payload.get("error"):
        raise ParseError(f"RPC error: {payload['error']}")
    return payload["result"]


def add_input_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--hex", help="serialized data as hexadecimal text")
    parser.add_argument("--file", help="text file containing serialized hexadecimal data")
    parser.add_argument("--out-dir", required=True, help="directory for parsed.json, bytes_and_bits.tsv and summary.txt")


def add_rpc_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rpc-url", default=os.getenv("BITCOIN_RPC_URL", "http://127.0.0.1:48332"))
    parser.add_argument("--rpc-user", default=os.getenv("BITCOIN_RPC_USER"))
    parser.add_argument("--rpc-password", default=os.getenv("BITCOIN_RPC_PASSWORD"))
    parser.add_argument("--out-dir", required=True)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Parse every byte/bit of Bitcoin raw transactions and blocks")
    sub = parser.add_subparsers(dest="command", required=True)

    tx = sub.add_parser("tx", help="parse raw transaction hex")
    add_input_options(tx)
    block = sub.add_parser("block", help="parse raw block hex")
    add_input_options(block)

    rpc_tx = sub.add_parser("rpc-tx", help="fetch a transaction from Bitcoin Core RPC and parse it")
    add_rpc_options(rpc_tx)
    rpc_tx.add_argument("--txid", required=True)
    rpc_tx.add_argument("--blockhash", help="recommended for confirmed tx when txindex is disabled")

    rpc_block = sub.add_parser("rpc-block", help="fetch a full serialized block from Bitcoin Core RPC and parse it")
    add_rpc_options(rpc_block)
    rpc_block.add_argument("--blockhash", required=True)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.command == "tx":
            raw = read_hex_argument(args.hex, args.file)
            result, ctx = parse_tx_bytes(raw)
        elif args.command == "block":
            raw = read_hex_argument(args.hex, args.file)
            result, ctx = parse_block_bytes(raw)
        elif args.command == "rpc-tx":
            params: list[Any] = [args.txid, 0]
            if args.blockhash:
                params.append(args.blockhash)
            raw_hex = rpc_call(args.rpc_url, "getrawtransaction", params, args.rpc_user, args.rpc_password)
            raw = bytes.fromhex(raw_hex)
            result, ctx = parse_tx_bytes(raw)
            result["source"] = {"rpc_method": "getrawtransaction", "txid_requested": args.txid, "blockhash": args.blockhash}
        elif args.command == "rpc-block":
            raw_hex = rpc_call(args.rpc_url, "getblock", [args.blockhash, 0], args.rpc_user, args.rpc_password)
            raw = bytes.fromhex(raw_hex)
            result, ctx = parse_block_bytes(raw)
            result["source"] = {"rpc_method": "getblock", "blockhash_requested": args.blockhash}
        else:
            raise ParseError(f"unsupported command: {args.command}")
        out_dir = Path(args.out_dir)
        write_reports(result, ctx, raw, out_dir)
        print(f"OK: wrote reports to {out_dir.resolve()}")
        return 0
    except (ParseError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
