"""
Unit tests for BCS encoding/decoding in Python v2.

Offline ops (encode/decode/sign) use aptos_sdk v1 BCS, same as go-v2 uses v1 BCS
for offline ops. Only network client ops require aptos_sdk_v2.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent  # implementations/python-v2/

CLI = [sys.executable, "-m", "aptx_py_v2"]

# Canonical BCS vector from conformance/cases/sign-single-ed25519.yaml (verified cross-SDK)
CANONICAL_BCS = "0x111111111111111111111111111111111111111111111111111111111111111100000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220222222222222222222222222222222222222222222222222222222222222222208e803000000000000400d0300000000006400000000000000ffe30b540200000004"


def run_cli(*args, cwd=None) -> dict:
    result = subprocess.run(
        [*CLI, *args, "--output-format", "json"],
        cwd=cwd or HERE,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"CLI failed:\n{result.stderr}"
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------
# BCS encode tests
# ---------------------------------------------------------------------------

class TestBCSEncode:
    def test_encode_single_transfer_matches_canonical(self):
        """BCS output must be bit-identical to the canonical cross-SDK vector."""
        payload = run_cli(
            "encode", "single",
            "--function", "0x1::aptos_account::transfer",
            "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
            "--arg", "address:0x2222222222222222222222222222222222222222222222222222222222222222",
            "--arg", "u64:1000",
            "--sequence-number", "0",
            "--chain-id", "4",
            "--max-gas-amount", "200000",
            "--gas-unit-price", "100",
            "--expiration-timestamp", "9999999999",
        )
        assert payload["action"] == "encode"
        assert payload["bcs"] == CANONICAL_BCS, (
            f"BCS mismatch\ngot:  {payload['bcs']}\nwant: {CANONICAL_BCS}"
        )

    def test_encode_fields_present(self):
        payload = run_cli(
            "encode", "single",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sequence-number", "5",
            "--chain-id", "4",
            "--max-gas-amount", "100000",
            "--gas-unit-price", "100",
            "--expiration-timestamp", "9999999999",
        )
        assert payload["action"] == "encode"
        assert payload["txn_type"] == "single"
        assert payload["sequence_number"] == 5
        assert payload["chain_id"] == 4
        assert payload["bcs"].startswith("0x")

    def test_encode_v2_matches_v1_bcs(self):
        """python-v2 BCS must be identical to python-v1 (both use same BCS library)."""
        v1_result = subprocess.run(
            [sys.executable, "-m", "aptx_py",
             "encode", "single",
             "--function", "0x1::aptos_account::transfer",
             "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
             "--arg", "address:0x2222222222222222222222222222222222222222222222222222222222222222",
             "--arg", "u64:1000",
             "--sequence-number", "0",
             "--chain-id", "4",
             "--max-gas-amount", "200000",
             "--gas-unit-price", "100",
             "--expiration-timestamp", "9999999999",
             "--output-format", "json"],
            cwd=HERE.parent / "python",
            capture_output=True, text=True,
        )
        if v1_result.returncode == 0:
            v1_payload = json.loads(v1_result.stdout)
            v2_payload = run_cli(
                "encode", "single",
                "--function", "0x1::aptos_account::transfer",
                "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
                "--arg", "address:0x2222222222222222222222222222222222222222222222222222222222222222",
                "--arg", "u64:1000",
                "--sequence-number", "0",
                "--chain-id", "4",
                "--max-gas-amount", "200000",
                "--gas-unit-price", "100",
                "--expiration-timestamp", "9999999999",
            )
            assert v2_payload["bcs"] == v1_payload["bcs"], "v2 BCS must match v1"

    def test_encode_deterministic(self):
        args = [
            "encode", "single",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sequence-number", "0",
            "--chain-id", "4",
            "--max-gas-amount", "200000",
            "--gas-unit-price", "100",
            "--expiration-timestamp", "9999999999",
        ]
        assert run_cli(*args)["bcs"] == run_cli(*args)["bcs"]


# ---------------------------------------------------------------------------
# BCS decode tests
# ---------------------------------------------------------------------------

class TestBCSDecode:
    def test_decode_canonical_vector(self):
        payload = run_cli("decode", "--input-bcs", CANONICAL_BCS)
        assert payload["action"] == "decode"
        assert payload["chain_id"] == 4
        assert payload["sequence_number"] == 0
        assert payload["max_gas_amount"] == 200000
        assert payload["gas_unit_price"] == 100
        assert payload["expiration_timestamp"] == 9999999999

    def test_decode_roundtrip(self):
        enc = run_cli(
            "encode", "single",
            "--function", "0x1::aptos_account::transfer",
            "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
            "--arg", "address:0x2222222222222222222222222222222222222222222222222222222222222222",
            "--arg", "u64:1000",
            "--sequence-number", "9",
            "--chain-id", "2",
            "--max-gas-amount", "150000",
            "--gas-unit-price", "200",
            "--expiration-timestamp", "7777777777",
        )
        dec = run_cli("decode", "--input-bcs", enc["bcs"])
        assert dec["sequence_number"] == 9
        assert dec["chain_id"] == 2
        assert dec["max_gas_amount"] == 150000
        assert dec["gas_unit_price"] == 200
        assert dec["expiration_timestamp"] == 7777777777


# ---------------------------------------------------------------------------
# Sign tests
# ---------------------------------------------------------------------------

class TestSign:
    PRIV_KEY = "0x0101010101010101010101010101010101010101010101010101010101010101"

    def test_sign_output_structure(self):
        payload = run_cli(
            "sign",
            "--input-bcs", CANONICAL_BCS,
            "--private-key", self.PRIV_KEY,
            "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        assert payload["action"] == "sign"
        assert payload["public_key"].startswith("0x")
        assert len(payload["public_key"]) == 66
        assert payload["signature"].startswith("0x")
        assert len(payload["signature"]) == 130
        assert payload["signed_bcs"].startswith("0x")

    def test_sign_deterministic(self):
        args = [
            "sign",
            "--input-bcs", CANONICAL_BCS,
            "--private-key", self.PRIV_KEY,
            "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
        ]
        r1 = run_cli(*args)
        r2 = run_cli(*args)
        assert r1["signature"] == r2["signature"]
        assert r1["public_key"] == r2["public_key"]
        assert r1["signed_bcs"] == r2["signed_bcs"]

    def test_sign_v2_matches_v1_signature(self):
        """Ed25519 is deterministic; v2 must produce the same signature as v1."""
        v1_result = subprocess.run(
            [sys.executable, "-m", "aptx_py",
             "sign",
             "--input-bcs", CANONICAL_BCS,
             "--private-key", self.PRIV_KEY,
             "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
             "--output-format", "json"],
            cwd=HERE.parent / "python",
            capture_output=True, text=True,
        )
        if v1_result.returncode == 0:
            v1_payload = json.loads(v1_result.stdout)
            v2_payload = run_cli(
                "sign",
                "--input-bcs", CANONICAL_BCS,
                "--private-key", self.PRIV_KEY,
                "--sender-address", "0x1111111111111111111111111111111111111111111111111111111111111111",
            )
            assert v2_payload["signature"] == v1_payload["signature"], "v2 signature must match v1"
            assert v2_payload["public_key"] == v1_payload["public_key"], "v2 public_key must match v1"


# ---------------------------------------------------------------------------
# Mock conformance tests
# ---------------------------------------------------------------------------

class TestMockConformance:
    def test_single_simulate_mock(self):
        payload = run_cli(
            "simulate", "single",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        )
        assert payload["implementation"] == "python-v2"
        assert payload["sdk_mode"] == "mock"
        assert payload["result"]["success"] is True

    def test_multi_agent_simulate_mock(self):
        payload = run_cli(
            "simulate", "multi-agent",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--secondary-signer-address", "0x2",
            "--arg", "address:0x3",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        )
        assert payload["txn_type"] == "multi-agent"
        assert payload["result"]["success"] is True

    def test_multi_sig_simulate_mock(self):
        payload = run_cli(
            "simulate", "multi-sig",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--multisig-action", "propose",
            "--multisig-address", "0xabc",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        )
        assert payload["txn_type"] == "multi-sig"
        assert payload["result"]["success"] is True

    def test_multi_key_simulate_mock(self):
        payload = run_cli(
            "simulate", "multi-key",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--multi-key-threshold", "2",
            "--multi-key-public-key", "0xaaa",
            "--multi-key-public-key", "0xbbb",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        )
        assert payload["txn_type"] == "multi-key"
        assert payload["result"]["success"] is True

    def test_mock_hash_deterministic(self):
        args = [
            "simulate", "single",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        ]
        assert run_cli(*args)["result"]["tx_hash"] == run_cli(*args)["result"]["tx_hash"]

    def test_implementation_label(self):
        payload = run_cli(
            "simulate", "single",
            "--network", "testnet",
            "--function", "0x1::coin::transfer",
            "--sender-address", "0x1",
            "--arg", "address:0x2",
            "--arg", "u64:100",
            "--sdk-mode", "mock",
        )
        assert payload["implementation"] == "python-v2"
        assert payload["sdk_backend"] == "aptos-sdk-v2"
