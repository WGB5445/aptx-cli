# Python Implementation

Target SDK: `aptos-sdk >= 0.11.0` (PyPI)

## Install

```bash
pip install -e implementations/python
# or just the SDK dependency:
pip install aptos-sdk>=0.11.0
```

## Current Status

| Feature | Mock mode | Real SDK |
|---|---|---|
| `single` simulate | ✅ | ✅ |
| `multi-agent` simulate | ✅ | ⚠️ primary signer only |
| `multi-key` simulate | ✅ | ❌ not implemented |
| `multi-sig` simulate | ✅ | ❌ not implemented |

For the limitations in real SDK mode, see [docs/sdk-feedback.md](../../docs/sdk-feedback.md).

## Entry Point

```bash
# Mock mode (no network, deterministic output):
python3 -m aptx_py simulate single \
  --input ../../fixtures/transactions/single-transfer.json \
  --sdk-mode mock \
  --output-format json

# Real mode (calls Aptos testnet):
python3 -m aptx_py simulate single \
  --input ../../fixtures/transactions/single-transfer.json \
  --output-format json
```

## Real SDK Path

When `--sdk-mode` is omitted (defaults to real), the CLI:

1. Imports `aptx_py.sdk` which wraps `aptos_sdk.async_client.RestClient`.
2. Fetches the account sequence number and chain ID from the configured network.
3. Builds a `RawTransaction` with the given sender address.
4. Calls `rest_client.simulate_transaction(raw_txn, dummy_account)` which
   zeroes the signature automatically — no private key is needed for simulation.
5. Returns real `success`, `vm_status`, `gas_used`, and `tx_hash` values.

The `asyncio.run()` bridge is used so the CLI entry point stays synchronous.

## Role In The Workspace

- participates in `python3 conformance/run.py`
- `--sdk-mode mock` gives deterministic output for baseline comparisons
- real mode validates actual SDK behaviour against the conformance spec
