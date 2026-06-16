# SDK Feedback: Gaps Found During Conformance Implementation

This document records gaps, rough edges, and improvement suggestions found while
implementing the conformance test harness against each SDK. Each section covers
one SDK with concrete examples from this workspace.

---

## TypeScript (`@aptos-labs/ts-sdk`)

### What works well

- `Aptos` client exposes `transaction.simulate()` with a clean builder API.
- `AccountAddress.fromString()` normalises short addresses automatically.
- Type tags and move arguments integrate directly with `TypeTagParser`.

### Gaps

#### 1. `simulate()` requires a full `SimpleTransaction` — no zero-sender shortcut

Simulating a transaction when you don't have a live account (e.g. you just want
gas estimation for an arbitrary address) still requires building a full
`SimpleTransaction`. The API does not accept a plain address string; you must
supply an `Account` instance or manually zero the `AccountAuthenticator`.

**Suggestion**: expose a `simulateWithAddress(address, payload, opts?)` helper
that constructs the zero-authenticator internally, matching the behaviour of
Go's `SimulateTransaction` and the Rust/Python REST-call approach.

#### 2. No built-in type for the simulation response projection

`transaction.simulate()` returns the raw JSON array from the REST API. There is
no typed wrapper for the simulation result fields (`success`, `vm_status`,
`gas_used`, `hash`). Callers must cast to `any` or write their own interface.

**Suggestion**: export `SimulationResult` (or re-export the REST API type) so
that callers get compile-time safety.

#### 3. Multi-agent simulation requires all secondary authenticators to be present

The SDK forces you to collect all secondary signers' signatures before calling
simulate, which is impractical for a "what would happen if" dry-run.

**Suggestion**: allow secondary signer slots to be stubbed with zero
authenticators, similar to how the primary signer is handled for `--no-sign`
flows.

---

## Python (`aptos-sdk >= 0.11.0`)

### What works well

- `RestClient.simulate_transaction(raw_txn, account)` automatically zeros the
  signature for simulation, so a dummy `Account.generate()` works safely.
- `RawTransaction` takes `sender` as an `AccountAddress`, making it clear that
  the signing account and the sender account are independent concepts.
- Async API (`async_client.RestClient`) is clean and works well with
  `asyncio.run()`.

### Gaps

#### 1. `simulate_transaction` only handles single-signer

The `simulate_transaction` method calls `sign_simulated_transaction()` on the
primary signer only. There is no equivalent for multi-agent transactions where
you need secondary-signer zero-authenticators.

**Suggestion**: add `simulate_multi_agent_transaction(raw_txn, primary, [])` (or
accept `None` for secondary signers) that builds a
`MultiAgentRawTransaction` with zero authenticators for all secondaries.

#### 2. `EntryFunction.natural` argument ordering is not obvious

The signature is `natural(module_id, function_name, type_tags, args)` where
`module_id` takes the form `"address::module"` (without the function name).
This is different from the common `address::module::function` triple used in
the CLI and REST API, and the difference is easy to miss.

**Suggestion**: add a `from_str("address::module::function", type_tags, args)`
factory that accepts the full triple and splits internally.

#### 3. `chain_id()` return type is undocumented

`await rest_client.chain_id()` returns an `int`, but this is not mentioned in
the docstring. The method name suggests it could return a richer type.

**Suggestion**: add a docstring clarifying the return type and value range.

#### 4. No `close()` in sync client; async client requires explicit close

`RestClient` is an async context manager, but there is no convenient sync
wrapper. When bridging with `asyncio.run()` you must remember to call
`await rest_client.close()` in a `finally` block, or sessions leak.

**Suggestion**: implement `__del__` or a sync context manager shim so the
client can be used safely from synchronous code without requiring `try/finally`.

---

## Go (`aptos-go-sdk` via `go.mod`)

### What works well

- `client.SimulateTransaction(rawTxn, account)` is the cleanest API surface of
  all four SDKs — one call, zero boilerplate, returns typed `[]SimulatedTransaction`.
- Address normalisation (`AccountAddress`) is automatic.
- The synchronous API fits naturally with Go's conventional blocking style.

### Gaps

#### 1. Multi-key (`K-of-N`) transaction signing not yet implemented

The Go SDK does not have a `MultiKeyAccount` type or helpers for K-of-N
multi-key wallets. This is the reason `multi-key` tests exclude `go` in
`conformance/cases/multi-key-simulate.yaml`.

**Suggestion**: add `MultiKeyAccount{PublicKeys, Threshold}` with a
`SimulateTransaction` override that zero-fills all key slots.

#### 2. Simulation response type is sparsely typed

`[]SimulatedTransaction` exposes `Success bool` and `VmStatus string`, but
`GasUsed` is a `string` (returned as a decimal string by the REST API) rather
than `uint64`. Callers must parse it manually.

**Suggestion**: add a `GasUsedU64() uint64` accessor or change the field type
with a custom JSON unmarshaller.

#### 3. No convenience accessor for `InputEntryFunctionData`

Building the payload requires constructing `InputEntryFunctionData` with `[]any`
args. There is no type-aware builder that validates argument types against the
on-chain ABI before sending.

**Suggestion**: add an `EntryFunctionBuilder` that accepts typed args
(`u64`, `address`, `bool`, …) and validates the count and types before
building the payload.

---

## Rust (`aptos-sdk = "0.5.0"`)

The Rust implementation uses `aptos-sdk = "0.5.0"` published on crates.io from
[github.com/aptos-labs/aptos-rust-sdk](https://github.com/aptos-labs/aptos-rust-sdk),
a standalone repository — not the Aptos monorepo. Requires Rust ≥ 1.95.0
(pinned in `implementations/rust/rust-toolchain.toml`).

### What works well

- `AccountAuthenticator::NoAccountAuthenticator` is a first-class public type,
  so simulation without a private key is explicit and correct (no zero-byte
  padding workarounds needed).
- `build_simulation_signed_multi_agent(multi_agent)` handles the multi-agent
  simulation case cleanly: it inserts `NoAccountAuthenticator` for both the
  primary sender and all secondary signers, using BCS encoding automatically.
  This is a significant improvement over the JSON REST API path, which cannot
  express multi-agent authenticators without BCS.
- `InputEntryFunctionData` builder handles BCS argument encoding automatically.
  Callers pass typed Rust values (`u64`, `bool`, `AccountAddress`, etc.) and
  the SDK encodes them correctly without manual `bcs::to_bytes` calls.
- `SimulationResult` returns typed accessors (`.success()`, `.vm_status()`,
  `.gas_used()`, `.hash()`) rather than raw JSON.

### Gaps

#### 1. `aws-lc-sys` is a mandatory dep — requires C toolchain to build

`aws-lc-sys` is in `[dependencies]` without `optional = true`, so it always
compiles C crypto code even when only the REST client is needed. First build
takes ~1-2 minutes and requires `cmake` and a C compiler.

**Suggestion**: gate `aws-lc-sys` behind an optional `aws-lc` feature (or
behind the `keyless` / crypto features that actually use it), so pure
REST-client use cases can build without a C toolchain.

#### 2. `Aptos::simulate` requires an `Account` object, not a bare address

The high-level `aptos.simulate(&account, payload)` builds the raw transaction
using `account.address()` as the sender. There is no variant that accepts a
plain `AccountAddress` for "simulate as this address I don't hold a key for."

Callers who want to simulate on behalf of an arbitrary address must manually
build the `RawTransaction`, attach `NoAccountAuthenticator`, and call
`simulate_signed` — which works but is not obvious from the API surface.

**Suggestion**: add `simulate_as(address: AccountAddress, payload, opts?)` that
constructs a `NoAccountAuthenticator`-signed transaction internally.

#### 3. `chain_id()` returns `0` for `devnet` and `custom` networks

`AptosConfig::devnet().chain_id()` returns `ChainId::new(0)` because devnet's
chain ID changes on each reset. For `custom` URLs it also returns `0`.
Transactions built with `chain_id = 0` will fail if the node rejects them.

**Suggestion**: add `Aptos::fetch_chain_id()` that queries the node at
construction time and caches the real value, similar to how Python's
`RestClient.chain_id()` works.

#### 4. Sequence number required — accounts that don't exist return 404

`aptos.get_sequence_number(address)` fails with a 404 error for addresses that
have never been on-chain. This makes it impossible to simulate a transaction
for a brand-new address.

**Suggestion**: expose a `get_sequence_number_or_zero(address)` helper that
returns `0` when the account is not found, which is the correct default for
simulation of new accounts.

---

## Cross-SDK summary table

| Feature | TypeScript | Python | Go | Rust |
|---|---|---|---|---|
| Single simulate | ✅ | ✅ | ✅ | ✅ |
| Multi-agent simulate | ⚠️ requires all signers | ⚠️ primary only | ✅ | ✅ NoAccountAuth |
| Multi-key simulate | ✅ | ❌ not implemented | ❌ not in SDK | ❌ not implemented |
| Multi-sig simulate | ✅ | ❌ not implemented | ✅ | ❌ not implemented |
| Typed simulation result | ⚠️ raw JSON | ⚠️ dict | ✅ struct | ✅ SimulationResult |
| Zero-key simulation | ⚠️ workaround needed | ✅ auto-zeros | ✅ auto-zeros | ✅ NoAccountAuthenticator |
| Standalone install | ✅ npm | ✅ pip | ✅ go get | ⚠️ needs C toolchain + Rust 1.95 (aws-lc-sys) |
| BCS encode (offline) | ✅ | ✅ | ✅ | ✅ |
| BCS decode (offline) | ✅ | ✅ | ✅ | ✅ |
| Ed25519 sign (offline) | ✅ | ✅ | ✅ | ✅ |
| Orderless transactions | ✅ (replayProtectionNonce) | ❌ not in SDK | ✅ (TransactionExtraConfigV1) | ✅ (RawTransactionOrderless) |

Legend: ✅ works, ⚠️ partial/workaround needed, ❌ not available

---

## Interoperability findings (cross-SDK BCS conformance)

These findings were produced by running `encode`, `decode`, and `sign` commands across all 4 SDKs
with identical inputs and comparing results (see `conformance/cases/encode-single.yaml`,
`decode-single.yaml`, `sign-single-ed25519.yaml`).

### ✅ BCS encoding is byte-identical across all 4 SDKs

Given the same sender address, function, arguments, and transaction parameters (sequence number,
chain ID, gas settings, expiration), all 4 SDKs produce exactly the same BCS bytes. This confirms
that cross-SDK transaction building is safe: a transaction constructed offline in Go can be signed
in Rust, submitted in TypeScript, and decoded in Python without any intermediate format conversion.

### ✅ Ed25519 signatures are deterministic and identical across all 4 SDKs

Same signing message + same Ed25519 private key → same 64-byte signature across TypeScript,
Python, Go, and Rust. This is guaranteed by RFC 8032. All 4 SDKs implement the Aptos signing
message format consistently: `sha3_256("APTOS::RawTransaction") ‖ bcs_bytes(rawTxn)`.

### ⚠️ Python's `PublicKey.to_bytes()` includes a BCS ULEB128 length prefix

When serializing a public key to compare with other SDKs, use `.key.encode()` on the underlying
`nacl.signing.VerifyKey` to get the raw 32 bytes. `PublicKey.to_bytes()` returns BCS-encoded form
(`0x20` prefix + 32 bytes) which looks like a valid but longer key and will mismatch other SDKs.

**Suggestion**: add a `PublicKey.raw_bytes()` method that returns the 32-byte key without BCS
encoding, to avoid this footgun.

### ⚠️ Orderless transactions are NOT supported by the Python SDK

The Python `aptos-sdk` has no concept of `replayProtectionNonce`. Developers building
multi-SDK flows with AIP-107 orderless transactions must use TypeScript, Go, or Rust for the
transaction-building step, then bridge to Python only for operations that don't require orderless
transaction construction.

**Suggestion**: add `RawTransactionOrderless` support to the Python SDK parity with the other
three SDKs.
