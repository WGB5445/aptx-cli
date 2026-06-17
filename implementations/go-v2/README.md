# Go v2 Implementation

Go implementation of the aptx CLI targeting `github.com/aptos-labs/aptos-go-sdk/v2`.

## Architecture

| Concern | Package used |
|---|---|
| Network calls (simulate/submit/run/inspect) | `github.com/aptos-labs/aptos-go-sdk/v2` |
| Offline BCS encode/decode/sign | `github.com/aptos-labs/aptos-go-sdk` (v1, BCS format is identical) |

The v2 SDK's BCS package is `internal`, so v1 is used for offline operations. This is safe because BCS is a deterministic, version-stable format and v2 depends on v1 explicitly.

## Requirements

- Go 1.25+

## Running

```bash
# Mock mode (no network)
cd implementations/go-v2
go run ./cmd/aptx simulate single \
  --function 0x1::coin::transfer \
  --sender-address 0x1 \
  --arg address:0x2 --arg u64:100 \
  --sdk-mode mock --output-format json

# Offline BCS encode (no network)
go run ./cmd/aptx encode single \
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
| `simulate multi-agent` | ✅ |
| `simulate multi-sig` | pending |
| `simulate multi-key` | pending |
| Localnet integration tests | pending |
