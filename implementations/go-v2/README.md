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
| `confidential-asset` | ✅ (see below — not yet wired into CI) |
| Localnet integration tests | pending |

## `confidential-asset` (experimental, local-only for now)

Go v2 supports the same `confidential-asset` txn-type as TypeScript (see
[`spec/confidential-asset.md`](../../spec/confidential-asset.md)), backed by
`aptos-go-sdk`'s `v2/confidentialasset` package. **This currently depends on an unmerged
upstream branch and is not wired into CI** — see [Setup](#setup-required-before-first-use) below.

### Setup (required before first use)

1. Clone `github.com/aptos-labs/aptos-go-sdk` and check out branch `logan/v2-confidential-asset`
   locally (adds the `v2/confidentialasset` package, plus a small `BuildXxxPayload`/submit split
   refactor needed so this CLI can implement `simulate` as build-and-dry-run, matching every other
   txn-type — the package's functions otherwise build+simulate+sign+submit in one call with no way
   to get an unsigned transaction back out).
2. Point `go.mod` at your local checkout — it already has this `replace` directive; update the
   path if your checkout lives elsewhere:
   ```
   replace github.com/aptos-labs/aptos-go-sdk/v2 => /path/to/your/aptos-go-sdk/v2
   ```
3. `withdraw`, `transfer`, `normalize` (and balance verification) need real proof generation via
   the `confidential-asset-bindings` Rust FFI, which requires `CGO_ENABLED=1` and its prebuilt
   static library. Download it once per platform (no Rust toolchain needed):
   ```bash
   cd implementations/go-v2
   go run github.com/aptos-labs/confidential-asset-bindings/bindings/go/aptosconfidential/tools/download@v1.1.2
   ```
   This downloads into `native/<platform-triple>/`. `register`, `deposit`, and `rollover` don't
   need CGO at all and work with `CGO_ENABLED=0` — the binary degrades gracefully (a clear error,
   not a build failure) if you try `withdraw`/`transfer`/`normalize` without CGO.

### Running

```bash
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$(pwd)/native/aarch64-apple-darwin"  # match your downloaded platform triple

go run ./cmd/aptx run confidential-asset \
  --network local --fullnode http://127.0.0.1:8080/v1 \
  --sender-address 0x... --private-key ed25519-priv-0x... \
  --confidential-action register \
  --confidential-token-address 0xa \
  --confidential-decryption-key 0x<32-byte-hex>
```

Flags are identical to TypeScript's (`--confidential-action`, `--confidential-token-address`,
`--confidential-decryption-key`, `--confidential-amount`, `--confidential-recipient`,
`--confidential-with-pause-incoming`, `--confidential-memo`). Unlike TS, there is no
`TwistedEd25519PrivateKey` type in Go — the decryption key is always passed as a raw hex string.

### Known cross-SDK behavioral difference

Go's `Transfer`/`Withdraw` require the balance to already be in normalized (canonical chunked)
form and return an explicit error otherwise ("balance not normalized; call NormalizeBalance
first"). TS's `transfer`/`withdraw` do not enforce this precondition. In practice this means a Go
flow needs an explicit `normalize` step after `rollover` before `transfer`/`withdraw`, even in
cases where the equivalent TS flow does not. This was found by the cross-SDK interop test (see
below) and is a genuine SDK difference, not a bug in this CLI's wiring.

### Cross-SDK verification

`get-confidential-balance` (`implementations/go-v2/scripts/get-confidential-balance`) independently
decrypts a balance via Go's `native.GetBalance`, mirroring how
`implementations/typescript/scripts/live-confidential-asset.ts` uses
`ConfidentialAsset.getBalance` directly.

`tests/live_confidential_asset_interop.py` (repo root, **run manually — not yet wired into CI**
since it needs the local `go.mod` replace above) drives a real cross-SDK lifecycle: Go registers
and funds alice's confidential balance, deposits, rolls over, normalizes, and transfers to bob;
TS registers bob, rolls his balance over, normalizes, and withdraws — proving TS can read and
spend a ciphertext Go produced, and vice versa. Every balance checkpoint is decrypted
independently by both `native.GetBalance` (Go) and `ConfidentialAsset.getBalance` (TS) and
asserted to agree, despite the underlying ciphertexts never being byte-identical (Twisted ElGamal
encryption and the sigma/range proofs are randomized per call — see
[`spec/confidential-asset.md`](../../spec/confidential-asset.md#cross-sdk-verification-model)).

```bash
cd implementations/go-v2 && go run github.com/aptos-labs/confidential-asset-bindings/bindings/go/aptosconfidential/tools/download@v1.1.2
cd ../..
APTX_TEST_NETWORK=local APTX_TEST_FULLNODE=http://127.0.0.1:8080/v1 APTX_TEST_FAUCET=http://127.0.0.1:8081 \
  python3 tests/live_confidential_asset_interop.py
```
