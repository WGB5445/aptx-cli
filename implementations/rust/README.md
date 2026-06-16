# Rust Implementation

Target SDK: [`aptos-sdk = "0.5.0"`](https://crates.io/crates/aptos-sdk) — published by Aptos Labs on crates.io from the standalone [aptos-rust-sdk](https://github.com/aptos-labs/aptos-rust-sdk) repository (not the Aptos monorepo).

> **Rust version:** Requires Rust ≥ 1.95.0 (see `rust-toolchain.toml`).
>
> **First build note:** `aptos-sdk` transitively depends on `aws-lc-sys` (a C crypto
> library), so the first `cargo build` requires `cmake` and a C compiler and takes
> ~1-2 minutes. See [docs/sdk-feedback.md](../../docs/sdk-feedback.md) for details.

## Build

```bash
cd implementations/rust
cargo build
```

## Current Status

| Feature | Mock mode | Real SDK |
|---|---|---|
| `single` simulate | ✅ | ✅ |
| `multi-agent` simulate | ✅ | ✅ (`NoAccountAuthenticator` for all signers) |
| `multi-key` simulate | ✅ | ❌ not yet implemented |
| `multi-sig` simulate | ✅ | ❌ not yet implemented |

Multi-agent simulation works properly because the SDK uses BCS encoding internally
and `build_simulation_signed_multi_agent` inserts `NoAccountAuthenticator` for all
signers — no private keys required for any signer.

## Entry Point

```bash
# Mock mode (no network, deterministic output):
cargo run --quiet -- simulate single \
  --input ../../fixtures/transactions/single-transfer.json \
  --sdk-mode mock \
  --output-format json

# Real mode (calls Aptos testnet):
cargo run --quiet -- simulate single \
  --input ../../fixtures/transactions/single-transfer.json \
  --output-format json

# Multi-agent real simulation:
cargo run --quiet -- simulate multi-agent \
  --function 0x1::aptos_account::transfer \
  --sender-address 0xabc \
  --secondary-signer-address 0xdef \
  --arg address:0x123 --arg u64:1000000 \
  --output-format json
```

## Real SDK Path

When `--sdk-mode` is omitted (defaults to real), `src/sdk.rs`:

1. Creates an `Aptos` client via `AptosConfig::testnet()` (or the configured network).
2. Fetches the account sequence number via `aptos.get_sequence_number(sender)`.
3. Builds the payload via `InputEntryFunctionData::new(function).type_arg(...).arg(...).build()` —
   the builder handles BCS encoding of all argument types automatically.
4. For single: builds a `SignedTransaction` with `AccountAuthenticator::NoAccountAuthenticator`
   (no private key needed) and calls `aptos.simulate_signed(&signed)`.
5. For multi-agent: calls `build_simulation_signed_multi_agent(&multi_agent)` which inserts
   `NoAccountAuthenticator` for primary and all secondary signers, then `aptos.simulate_signed`.
6. Returns typed results from `SimulationResult` (`.success()`, `.vm_status()`, `.gas_used()`).

## Role In The Workspace

- participates in `python3 conformance/run.py`
- `--sdk-mode mock` gives deterministic output for baseline comparisons
- real mode validates actual SDK behaviour against the conformance spec
