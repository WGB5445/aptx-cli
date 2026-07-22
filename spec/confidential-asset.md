# Confidential Asset Spec (TypeScript + Go v2 extension)

> **Not part of the cross-language contract.** Unlike [`canonical-cli.md`](canonical-cli.md), this
> document describes a txn-type implemented in the TypeScript backend
> (`implementations/typescript`, fully supported, CI-tested) and the Go v2 backend
> (`implementations/go-v2`, experimental — depends on an unmerged upstream `aptos-go-sdk` branch,
> not yet wired into CI, see [`implementations/go-v2/README.md`](../implementations/go-v2/README.md#confidential-asset-experimental-local-only-for-now)).
> It is not required from Python/Rust, and its fields are **not** part of the conformance
> projection in [`output-schema.json`](output-schema.json) — the `conformance/run.py` runner does
> not check this txn-type against baselines. See
> [Cross-SDK verification model](#cross-sdk-verification-model) below for how this actually works
> across TS and Go — it is a different model than `conformance/run.py`'s byte-identical baseline
> diffing.

## Background

[Aptos Confidential Assets](https://aptos.dev) let an account hold an encrypted ("confidential")
balance of a fungible asset, built on Twisted ElGamal encryption and Bulletproofs range proofs, on
top of the on-chain Move module `0x1::confidential_asset` (part of `aptos-framework`, address
`0x1` — not a separate deployment). Balances are only decryptable by the holder of the matching
`TwistedEd25519PrivateKey` ("decryption key"); everyone else sees ciphertexts.

The TypeScript implementation wraps
[`@aptos-labs/confidential-asset`](https://www.npmjs.com/package/@aptos-labs/confidential-asset)
(currently `^2.2.0`, from the `aptos-ts-sdk` monorepo, `confidential-asset/` subdirectory), whose
`ConfidentialAssetTransactionBuilder` builds sigma-proofs, range proofs, and ciphertexts
client-side and returns a plain `SimpleTransaction` — which is why this fits into `aptx`'s
existing simulate/sign/submit pipeline, unlike the library's higher-level `ConfidentialAsset`
class (which signs and submits internally and would not fit that split).

## Command shape

Same top-level actions as the canonical CLI:

```
aptx simulate confidential-asset   # build and simulate; no signing required
aptx submit  confidential-asset    # build, sign, and submit to network
aptx run     confidential-asset    # simulate + submit in one step
```

`aptx inspect` is unaffected (it doesn't take a txn-type).

## Flags

| Flag | Required for | Description |
|---|---|---|
| `--confidential-action ACTION` | always | One of `register`, `deposit`, `withdraw`, `transfer`, `rollover`, `normalize`, `rotate` |
| `--confidential-token-address ADDRESS` | always | The fungible-asset metadata object address (e.g. the APT FA object, resolvable via `0x1::coin::paired_metadata<0x1::aptos_coin::AptosCoin>`) |
| `--confidential-decryption-key HEX` | `register`, `withdraw`, `transfer`, `normalize`, `rotate` | The sender's (current) `TwistedEd25519PrivateKey`, hex-encoded (32-byte seed, with or without `0x` prefix) |
| `--confidential-new-decryption-key HEX` | `rotate` | The new `TwistedEd25519PrivateKey` to rotate to, same encoding as `--confidential-decryption-key` |
| `--confidential-amount U64` | `deposit`, `withdraw`, `transfer` | Amount to move, in the asset's base units |
| `--confidential-recipient ADDRESS` | `transfer` (required); `withdraw` (optional) | Recipient address. For `withdraw`, defaults to the sender if omitted. **Not accepted by `deposit`** — the underlying library only supports self-deposit at this layer |
| `--confidential-with-pause-incoming` | `rollover` (optional) | Also pause incoming transfers after rolling over — **required before `rotate`** (see [Behavioral notes](#behavioral-notes)) |
| `--confidential-memo HEX` | `transfer` (optional) | Optional memo bytes attached to the transfer |

Standard flags (`--network`, `--sender-address`, `--private-key*`, `--output*`, `--sdk-mode`, etc.)
work the same as for other txn-types. `--function`, `--script-hex`, `--arg`, and `--type-arg` are
rejected for `confidential-asset` — the transaction payload (including proofs) is built entirely
from the flags above.

## Supported actions

| Action | Effect |
|---|---|
| `register` | Registers a confidential balance for the sender for the given token, using the encryption key derived from `--confidential-decryption-key` |
| `deposit` | Moves `--confidential-amount` from the sender's normal (non-confidential) balance into their own confidential **pending** balance |
| `rollover` | Moves the sender's pending balance into their available balance (required before spending newly deposited/received funds) |
| `transfer` | Sends `--confidential-amount` from the sender's confidential available balance to `--confidential-recipient`'s confidential pending balance |
| `withdraw` | Moves `--confidential-amount` from the sender's confidential available balance back into a normal balance (the sender's own, or `--confidential-recipient` if given) |
| `normalize` | Normalizes the sender's available-balance ciphertext into canonical chunked form (needed after enough transfers/deposits accumulate without a rollover) |
| `rotate` | Rotates the sender's encryption key from `--confidential-decryption-key` to `--confidential-new-decryption-key`, re-encrypting the existing available balance under the new key. Requires incoming transfers to already be paused (see [Behavioral notes](#behavioral-notes)) |

## Out of scope

Not implemented in this CLI (available in the underlying library, but deliberately excluded here
as advanced/niche and unnecessary to validate the core integration):

- **Keyless DK backup/recovery** (`registerBalanceAndEncryptDk`, `upsertEd25519BackupKeyAndEncryptDk`,
  `recoverDecryptionKeyFromBackup`) — encrypting/backing up the decryption key under a keyless
  account's Ed25519 backup key
- **Auditor configuration** (reading is used internally by `transfer`/`withdraw`/`normalize` to
  build proofs correctly, but there's no CLI action to set an auditor)
- **Indexer activity queries** (`getActivities`) — requires a separate indexer connection

## Behavioral notes

- **`--sdk-mode mock`**: works mechanically (the mock backend is txn-type-agnostic and just echoes
  parsed input with a fake tx hash), but the result is **not meaningful** for `confidential-asset`
  — no proof is built or verified, so a mock "success" says nothing about correctness. Use
  `--sdk-mode sdk` (the default) against a real network for anything beyond exercising the CLI's
  argument plumbing.
- **Decryption-key redaction**: `--confidential-decryption-key` is never echoed back in JSON/YAML
  output, matching how `--private-key` is handled.
- **WASM crypto**: the library's discrete-log solver and Bulletproofs range-proof code run via a
  WASM module that auto-initializes on first use. In Node.js it loads from local `node_modules`
  (no network fetch), so it works offline in CI/localnet.
- **Localnet requirement**: needs a reasonably current Aptos CLI for `aptos node run-localnet` —
  its bundled `aptos-framework` must include `confidential_asset.move`. This repo does not pin an
  Aptos CLI version anywhere (CI installs "latest"); if a future framework build ever drops or
  gates the module, this would need revisiting.
- **Deposit has no recipient**: `--confidential-recipient` is accepted for `withdraw`/`transfer`
  but not `deposit`, because the underlying transaction builder's `deposit()` only supports
  depositing into the sender's own balance.
- **`rotate` requires incoming transfers to already be paused**: the on-chain module aborts with
  `E_INCOMING_TRANSFERS_NOT_PAUSED` otherwise. Pausing is a side effect of `rollover
  --confidential-with-pause-incoming`, which calls a distinct entry function
  (`rollover_pending_balance_and_pause` vs plain `rollover_pending_balance`) with two more
  preconditions of its own: (a) the library client-side-checks the available balance is
  **normalized** first and throws `Balance must be normalized before rollover` otherwise — and a
  plain `rollover` always leaves the available balance un-normalized (the same underlying fact as
  the Go cross-SDK finding below, just enforced client-side in TS instead of on-chain), so a
  `normalize` is needed first if the account has ever rolled over before; and (b) it requires a
  **nonzero pending balance** to roll over (`E_NOTHING_TO_ROLLOVER` otherwise), so a small `deposit`
  is also needed first purely to give it something to roll over. In practice, rotating an
  already-active balance is: `normalize` → `deposit` (any amount, even 1 unit) → `rollover
  --confidential-with-pause-incoming` → `rotate` (see
  `implementations/typescript/scripts/live-confidential-asset.ts` for this exact sequence exercised
  end to end). `rotate` also defaults to requiring the pending balance be empty at rotation time
  (`checkPendingBalanceEmpty`, not exposed as a CLI flag) and defaults to unpausing incoming
  transfers again once rotation completes (`unpause`, also not exposed) — both use the underlying
  library's default (`true`), matching the common case.

## Cross-SDK verification model

Unlike `single`/`multi-agent`/`multi-sig`/`multi-key`, this txn-type cannot use the byte-identical
BCS/signature comparison `conformance/run.py` uses for e.g. `encode-single.yaml` /
`sign-single-ed25519.yaml`. Twisted ElGamal ciphertexts, sigma-proofs, and Bulletproofs range
proofs all draw fresh randomness (blinding factors / proof nonces) per call, so two SDKs given the
*same logical input* (same amount, same keys) produce different ciphertext/proof bytes and
different transaction hashes by design — that is not a bug, and a baseline-diff check would never
be stable across runs even for a single SDK.

Cross-SDK verification instead follows a **semantic/interop** model, implemented for TS ↔ Go v2 in
`tests/live_confidential_asset_interop.py` (repo root):

1. Both implementations expose the same `--confidential-*` flags/actions described above, so the
   test driver calls either language's CLI interchangeably (the same pattern
   `tests/live_multi_agent.py` uses to drive multiple CLIs from one Python script).
2. Verification decrypts on-chain state rather than comparing transaction bytes: build/submit with
   CLI A, then independently decrypt the resulting balance with CLI B's (or SDK B's) own
   decryption path, and assert the plaintext amount matches — not the ciphertext.
3. The test crosses the pairing rather than each SDK only checking its own output: Go registers,
   deposits, rolls over, normalizes, and transfers alice's balance to bob; TS registers bob, rolls
   his balance over, normalizes it, and withdraws — proving ciphertexts/proofs produced by Go are
   correctly read and spent by TS (and vice versa for the writes TS makes that Go reads), not just
   "each SDK can read its own writes". Every checkpoint is decrypted independently by both Go's
   `native.GetBalance` and TS's `ConfidentialAsset.getBalance` and asserted to agree.
4. Because this doesn't fit `conformance/run.py`'s baseline-diff model, it lives as its own interop
   test target rather than a `conformance/cases/*.yaml` case.

**Go v2's implementation** is `aptos-go-sdk`'s `v2/confidentialasset` package (branch
`logan/v2-confidential-asset`, **not yet merged upstream** — see
[`implementations/go-v2/README.md`](../implementations/go-v2/README.md#confidential-asset-experimental-local-only-for-now)
for the exact setup required, including a small additive refactor on that branch splitting
payload-building from signing/submitting so `simulate` can be a real dry run there too, matching
every other txn-type). It mirrors `@aptos-labs/confidential-asset`'s API (see its
`doc/TS_GO_MAP.md`) and uses the `confidential-asset-bindings` Rust core via CGO/FFI for the
proof-heavy operations (`Withdraw`/`Transfer`/`NormalizeBalance`/`GetBalance`, under its
`confidentialasset/native` subpackage) — the same Rust core a Rust CLI implementation would use
directly without the FFI hop, if one is added later.

Because `implementations/go-v2/go.mod` currently points at a local filesystem checkout of that
unmerged branch (not a real pseudo-version fetchable from a plain `git clone` + CI), the interop
test is **not yet wired into CI** — it's run manually today. Once the `aptos-go-sdk` branch merges
upstream and `go.mod` can reference a real version, wiring `tests/live_confidential_asset_interop.py`
into the `localnet-live` CI job is the natural next step.

**Cross-SDK finding from building this:** Go's `Transfer`/`Withdraw`/`Rotate` require the balance to
already be normalized and error otherwise; TS's do not enforce this (TS's `rotate` in particular
succeeds immediately after a paused `rollover`, while Go's `rotate` needs one more explicit
`normalize` after that same paused `rollover` — the on-chain state is identical either way, Go's
client just checks more defensively). A Go-driven flow needs explicit `normalize` calls in more
places than the equivalent TS flow does — a genuine behavioral difference between the two SDKs that
this cross-SDK test surfaced, documented in
[`implementations/go-v2/README.md`](../implementations/go-v2/README.md#known-cross-sdk-behavioral-difference).

## Test coverage

`implementations/typescript/scripts/live-confidential-asset.ts` (run via `pnpm
test:confidential-asset`, wired into the CI `localnet-live` job) drives the full lifecycle against
a real localnet: `register` (two accounts) → `deposit` → `rollover` → `normalize` → `deposit` →
`rollover --confidential-with-pause-incoming` → `rotate` → `transfer` → `rollover` → `withdraw`.
After each mutating step, it independently decrypts on-chain balances via
`@aptos-labs/confidential-asset`'s `ConfidentialAsset.getBalance` (not just trusting the CLI's own
reported success) to assert the expected available/pending amounts — including, after `rotate`,
that the balance decrypts correctly (and to the same amount) under the **new** decryption key.
`register` is also simulated through both the `node` and `deno` runtimes as a lightweight parity
check, matching the pattern in `live-multikey.ts`/`live-multisig.ts`.

`tests/live_confidential_asset_interop.py` (repo root, manual — see
[Cross-SDK verification model](#cross-sdk-verification-model)) covers the Go v2 side and the
TS ↔ Go interop: `register` → `deposit` → `rollover` → `normalize` → `transfer` (all Go) → `rollover`
→ `normalize` → `withdraw` (all TS), with every balance checkpoint decrypted and cross-checked by
both `native.GetBalance` (Go) and `ConfidentialAsset.getBalance` (TS).
