# SDK Upgrade Guide

This guide explains how to check whether a new SDK version (or a branch build) is compatible with the existing conformance baseline, and what to do when it isn't.

## Overview

The workflow is:

1. **Save a baseline** with the current SDK versions
2. **Switch to the new version or branch**
3. **Run conformance** and compare against the baseline
4. **Review diffs** — any changed fields are potential breaking changes
5. **Update implementations** if changes are required

## Step 1 — Check current versions

```bash
./scripts/show-sdk-versions.sh
```

Example output:
```
Currently pinned SDK versions:

  typescript  @aptos-labs/ts-sdk  ^6.1.0
  go          aptos-go-sdk        v1.12.0
  python      aptos-python-sdk    (mock only)
  rust        aptos-rust-sdk      (mock only)
```

## Step 2 — Save a baseline

Save the current conformance results before making any changes:

```bash
python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.1.json
```

Name the baseline file after the SDK and version being replaced (not the new one). This makes it easy to identify what the baseline represents later.

## Step 3 — Switch to the new version or branch

**Pin to a specific released version:**

```bash
./scripts/set-sdk-version.sh typescript 6.2.0
./scripts/set-sdk-version.sh go v1.13.0
```

**Pin to a git branch:**

```bash
# TypeScript — use the npm git syntax
cd implementations/typescript
pnpm add "https://github.com/aptos-labs/aptos-ts-sdk#main"

# Go — use branch name directly (Go resolves to pseudo-version)
cd implementations/go
GOCACHE=../../.cache/go-build go get github.com/aptos-labs/aptos-go-sdk@main
GOCACHE=../../.cache/go-build go mod tidy
```

**Pin to a local checkout:**

```bash
# TypeScript
cd implementations/typescript
pnpm add "file:../../../path/to/local/aptos-ts-sdk"

# Go — use replace directive in go.mod
# Add to implementations/go/go.mod:
# replace github.com/aptos-labs/aptos-go-sdk => ../../../path/to/local/aptos-go-sdk
```

## Step 4 — Compare against the baseline

```bash
python3 conformance/run.py --compare-baseline conformance/baselines/ts-sdk-6.1.json
```

### If compatible

```
All cases match baseline — SDK upgrade appears compatible.
```

The output JSON will show `"compatible": true` and an empty `diffs` array. Proceed with the upgrade.

### If there are differences

Example output when something changed:

```json
{
  "compatible": false,
  "baseline_sdk_versions": { "typescript": "^6.1.0" },
  "current_sdk_versions":  { "typescript": "^6.2.0" },
  "diffs": [
    {
      "case": "single-simulate",
      "change": "modified",
      "fields": {
        "vm_status": {
          "baseline": "Executed successfully",
          "current": "success"
        }
      }
    }
  ]
}
```

Each entry in `diffs` tells you:
- `case` — which test scenario was affected
- `change` — `added`, `removed`, or `modified`
- `fields` — for `modified`, the exact before/after values for each changed field

## Step 5 — Decide what to do with diffs

Not every diff is a breaking change. Use the field definitions in `spec/output-schema.json` and the canonical contract in `spec/canonical-cli.md` to decide:

| Field | Breaking if changed? | Likely cause |
|---|---|---|
| `action` | Yes — CLI contract | Implementation bug |
| `txn_type` | Yes — CLI contract | Implementation bug |
| `function` | Yes — CLI contract | Input handling change |
| `args` / `type_args` | Yes — CLI contract | Argument parsing change |
| `sender_address` | Yes — normalization must match | Address serialization change |
| `abi_enabled` | Yes — behavior flag | Default changed in SDK |
| `sign_mode` | Yes — signing behavior | Signer inference change |
| `result_mode` | Yes — behavior | Mock mode output change |
| `success` | Yes — mock always true | Mock behavior change |
| `vm_status` | Possibly — cosmetic | String format changed |
| `gas_used` | Possibly — cosmetic | Mock default changed |

**For breaking changes:** update the affected implementations to match the new SDK behavior, then update `spec/canonical-cli.md` if the CLI contract itself changed.

**For cosmetic changes** (like `vm_status` string format): update the projection in `conformance/run.py` or accept the new value and re-save the baseline.

## Step 6 — Re-run after fixes

After updating implementations:

```bash
# Verify implementations still build and typecheck
cd implementations/typescript && pnpm exec tsc --noEmit
cd implementations/go && go build ./...

# Verify conformance passes (cross-implementation consistency)
python3 conformance/run.py

# Optionally save a new baseline for the updated SDK version
python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.2.json
```

## Running conformance for a single implementation

To check only one language at a time:

```bash
# Only TypeScript
python3 conformance/run.py --impl typescript

# Only Go, and only the single-transfer case
python3 conformance/run.py --impl go --filter single
```

## Running conformance for a single test case

```bash
python3 conformance/run.py --filter multi-sig
```

## Note on mock vs. real conformance

The conformance runner uses `--sdk-mode mock`, which means results are deterministic and do not require a running network or private keys. This is intentional:

- it lets all languages participate even when not all have real SDK coverage
- it validates command shape and output structure, not on-chain execution

Real SDK behavior (actual transaction execution) is validated in CI via the `localnet-live` job. For a new SDK version, also run the localnet tests manually if possible:

```bash
aptos node run-localnet --test-dir /tmp/aptx-local --force-restart --assume-yes &
sleep 10

APTX_TEST_NETWORK=local \
APTX_TEST_FULLNODE=http://127.0.0.1:8080/v1 \
APTX_TEST_FAUCET=http://127.0.0.1:8081 \
python3 tests/live_multi_agent.py

cd implementations/typescript && pnpm test:multikey && pnpm test:multisig
cd implementations/go && go test ./integration -run 'Test(OnChainMultisig|CLIOnChainMultisig)' -v
```
