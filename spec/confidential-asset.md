# Confidential Asset Spec (TypeScript-only extension)

> **Not part of the cross-language contract.** Unlike [`canonical-cli.md`](canonical-cli.md), this
> document describes a txn-type implemented only in the TypeScript backend
> (`implementations/typescript`). It is not required from Python/Go/Rust, and its fields are
> **not** part of the conformance projection in [`output-schema.json`](output-schema.json) — the
> `conformance/run.py` runner does not check this txn-type against baselines.

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
| `--confidential-action ACTION` | always | One of `register`, `deposit`, `withdraw`, `transfer`, `rollover`, `normalize` |
| `--confidential-token-address ADDRESS` | always | The fungible-asset metadata object address (e.g. the APT FA object, resolvable via `0x1::coin::paired_metadata<0x1::aptos_coin::AptosCoin>`) |
| `--confidential-decryption-key HEX` | `register`, `withdraw`, `transfer`, `normalize` | The sender's `TwistedEd25519PrivateKey`, hex-encoded (32-byte seed, with or without `0x` prefix) |
| `--confidential-amount U64` | `deposit`, `withdraw`, `transfer` | Amount to move, in the asset's base units |
| `--confidential-recipient ADDRESS` | `transfer` (required); `withdraw` (optional) | Recipient address. For `withdraw`, defaults to the sender if omitted. **Not accepted by `deposit`** — the underlying library only supports self-deposit at this layer |
| `--confidential-with-pause-incoming` | `rollover` (optional) | Also pause incoming transfers after rolling over (used before a key rotation, which this CLI does not implement — see below) |
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

## Out of scope

Not implemented in this CLI (available in the underlying library, but deliberately excluded here
as advanced/niche and unnecessary to validate the core integration):

- **Key rotation** (`rotateEncryptionKey` / `rotate_encryption_key_raw`)
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

## Test coverage

`implementations/typescript/scripts/live-confidential-asset.ts` (run via `pnpm
test:confidential-asset`, wired into the CI `localnet-live` job) drives the full lifecycle against
a real localnet: `register` (two accounts) → `deposit` → `rollover` → `transfer` → `rollover` →
`withdraw`. After each mutating step, it independently decrypts on-chain balances via
`@aptos-labs/confidential-asset`'s `ConfidentialAsset.getBalance` (not just trusting the CLI's own
reported success) to assert the expected available/pending amounts. `register` is also simulated
through both the `node` and `deno` runtimes as a lightweight parity check, matching the pattern in
`live-multikey.ts`/`live-multisig.ts`. `normalize` is implemented but not exercised by this test,
since reaching a genuinely "unnormalized" balance requires an artificial setup outside this
happy-path flow.
