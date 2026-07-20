#!/usr/bin/env python3
import unittest
from pathlib import Path

from btc_parser import parse_block_bytes, parse_tx_bytes

ROOT = Path(__file__).resolve().parent


class ParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import make_samples  # noqa: F401

    def read_sample(self, name: str) -> bytes:
        return bytes.fromhex((ROOT / "samples" / name).read_text().strip())

    def test_testnet4_genesis_transaction(self):
        result, ctx = parse_tx_bytes(self.read_sample("testnet4_genesis_tx.hex"))
        tx = result["transaction"]
        self.assertEqual(tx["txid"], "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e")
        self.assertTrue(tx["is_coinbase"])
        self.assertFalse(tx["segwit_serialization"])
        self.assertEqual(sum(f.size for f in ctx.fields), tx["size"])

    def test_testnet4_genesis_block(self):
        result, ctx = parse_block_bytes(self.read_sample("testnet4_genesis_block.hex"))
        block = result["block"]
        self.assertEqual(block["hash"], "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043")
        self.assertTrue(block["proof_of_work_valid"])
        self.assertTrue(block["merkle_root_valid"])
        self.assertEqual(block["tx_count"], 1)
        self.assertEqual(sum(f.size for f in ctx.fields), block["size"])

    def test_segwit_serialization(self):
        result, _ = parse_tx_bytes(self.read_sample("synthetic_segwit_tx.hex"))
        tx = result["transaction"]
        self.assertTrue(tx["segwit_serialization"])
        self.assertNotEqual(tx["txid"], tx["wtxid"])
        self.assertEqual(len(tx["witnesses"][0]), 2)
        self.assertEqual(tx["outputs"][0]["script_type"], "P2WPKH (SegWit v0)")


if __name__ == "__main__":
    unittest.main(verbosity=2)
