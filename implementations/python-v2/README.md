# Python v2 Implementation

Python implementation of the aptx CLI targeting `aptos-sdk-v2`.

## Requirements

- Python 3.12+
- `aptos-sdk` (v1, used for offline `encode`/`decode`/`sign` BCS — installed automatically)
- `aptos-sdk-v2` (only for real `--sdk-mode sdk` network calls — optional, see below)

## Installation

```bash
cd implementations/python-v2
pip install -e .
```

`aptos-sdk-v2` isn't published to PyPI (it lives in the `v2` subdirectory of
`aptos-labs/aptos-python-sdk`), so it's an optional extra rather than a hard dependency — mock mode
and encode/decode/sign don't need it. To install it for real SDK network calls:

```bash
pip install -e ".[sdk]"
```

## Running

```bash
# Mock mode (no network)
python3 -m aptx_py_v2 simulate single \
  --function 0x1::coin::transfer \
  --sender-address 0x1 \
  --arg address:0x2 --arg u64:100 \
  --sdk-mode mock --output-format json

# Offline BCS encode (no network)
python3 -m aptx_py_v2 encode single \
  --function 0x1::coin::transfer \
  --sender-address 0x1 \
  --arg address:0x2 --arg u64:100 \
  --chain-id 4 --sequence-number 0 \
  --output-format json
```

## SDK Coverage

| Feature | Status |
|---|---|
| `encode` / `decode` / `sign` | ✅ full |
| `simulate single` | ✅ |
| `simulate multi-agent` | ⚠️ primary-only |
| `simulate multi-sig` | pending |
| `simulate multi-key` | pending |
| Localnet integration tests | pending |

## Key API differences from v1

| v1 (`aptos_sdk`) | v2 (`aptos_sdk_v2`) |
|---|---|
| `Serializer.bytes(data)` | `Serializer.to_bytes(data)` |
| `ed25519.PrivateKey(NaclSigningKey(...))` | `Ed25519PrivateKey.from_str(hex)` |
| `SignedTransaction(...).bcs_serialize()` | `SignedTransaction(...).to_bytes()` |
| `auth.ed25519_auth.signature.data` | `auth.authenticator.signature._signature` |
