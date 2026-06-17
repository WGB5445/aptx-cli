# Aptos Transaction CLI Workspace

This repository hosts one canonical Aptos transaction CLI contract and multiple SDK-backed implementations of it.

The immediate goal is a usable transaction CLI. The broader goal is **SDK compatibility validation across languages** — verify that different SDKs produce identical behavior, and detect breaking changes when upgrading to a new SDK version.

## What This Repo Is

- a canonical CLI contract in [`spec/canonical-cli.md`](spec/canonical-cli.md)
- shared test cases and conformance checks in [`conformance/`](conformance/)
- shared fixtures in [`fixtures/`](fixtures/)
- multiple language implementations under [`implementations/`](implementations/)
- real localnet-backed integration coverage driven by Aptos CLI

## Architecture

Start here:

- workspace guide: [`AGENTS.md`](AGENTS.md)
- SDK upgrade guide: [`UPGRADING.md`](UPGRADING.md)
- architecture overview: [`docs/architecture.md`](docs/architecture.md)
- canonical CLI contract: [`spec/canonical-cli.md`](spec/canonical-cli.md)
- output schema (formal): [`spec/output-schema.json`](spec/output-schema.json)

Current implementations:

- matrix overview: [`implementations/README.md`](implementations/README.md)
- TypeScript: [`implementations/typescript/README.md`](implementations/typescript/README.md)
- Go (v1): [`implementations/go/README.md`](implementations/go/README.md)
- Go (v2): [`implementations/go-v2/README.md`](implementations/go-v2/README.md)
- Python (v1): [`implementations/python/README.md`](implementations/python/README.md)
- Python (v2): [`implementations/python-v2/README.md`](implementations/python-v2/README.md)
- Rust: [`implementations/rust/README.md`](implementations/rust/README.md)

## Quick Start

Run shared mock conformance across all implementations:

```bash
python3 conformance/run.py
```

### Offline transaction building (no network needed)

All 4 SDKs support `encode`, `decode`, and `sign` without any network connection:

```bash
# Build a raw transaction → BCS hex (identical output across all 4 SDKs)
node --experimental-strip-types implementations/typescript/src/cli.ts encode single \
  --function 0x1::aptos_account::transfer \
  --sender-address 0x1111111111111111111111111111111111111111111111111111111111111111 \
  --arg address:0x2222222222222222222222222222222222222222222222222222222222222222 \
  --arg u64:1000 \
  --sequence-number 0 --chain-id 1 --output-format json

# Sign the BCS hex with an Ed25519 private key (deterministic across all 4 SDKs)
node --experimental-strip-types implementations/typescript/src/cli.ts sign \
  --input-bcs 0x... --private-key 0x... --output-format json

# Decode BCS hex back to human-readable fields
node --experimental-strip-types implementations/typescript/src/cli.ts decode \
  --input-bcs 0x... --output-format json
```

### Simulate (requires network / mock mode)

```bash
# TypeScript (Node)
cd implementations/typescript && pnpm start -- simulate single --input ../../fixtures/transactions/single-transfer.json --output-format json

# TypeScript (Bun)
cd implementations/typescript && bun src/cli.ts simulate single --input ../../fixtures/transactions/single-transfer.json --output-format json

# TypeScript (Deno)
cd implementations/typescript && pnpm start:deno -- simulate single --input ../../fixtures/transactions/single-transfer.json --output-format json

# Go
cd implementations/go && env GOCACHE=../../.cache/go-build go run ./cmd/aptx simulate single --input ../../fixtures/transactions/single-transfer.json --output-format json

# Python
python3 -m aptx_py simulate single --input fixtures/transactions/single-transfer.json --output-format json

# Rust
cd implementations/rust && cargo run --quiet -- simulate single --input ../../fixtures/transactions/single-transfer.json --output-format json
```

## SDK Version Compatibility Checking

A primary use case for this workspace is verifying that a new SDK version does not break existing behavior.

**1. Save a baseline for the current SDK versions:**

```bash
python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.1.json
```

**2. Upgrade the SDK:**

```bash
./scripts/set-sdk-version.sh typescript 6.2.0
./scripts/set-sdk-version.sh go v1.13.0
```

**3. Run conformance and compare against the baseline:**

```bash
python3 conformance/run.py --compare-baseline conformance/baselines/ts-sdk-6.1.json
```

If compatible, you will see:
```
All cases match baseline — SDK upgrade appears compatible.
```

If there are breaking changes, the output shows exactly which fields changed, so developers know what to update.

See [`conformance/README.md`](conformance/README.md) for the full conformance workflow.

## Adding New Test Cases

Test cases are plain YAML files in `conformance/cases/`. To add a new case:

1. Create `conformance/cases/<name>.yaml`
2. Define `name`, `description`, `implementations`, and `argv`
3. Run `python3 conformance/run.py --filter <name>` to verify it works

No Python code changes required. See [`conformance/README.md`](conformance/README.md) for the YAML format.

## Current Status

| Implementation | SDK | Offline (encode/decode/sign) | Simulate coverage |
|---|---|---|---|
| TypeScript | `@aptos-labs/ts-sdk` ^7.1.0 | ✅ | single, multi-agent, multi-key, multi-sig |
| Go (v1) | `aptos-go-sdk` v1.13.0 | ✅ | single, multi-agent, multi-sig (multi-key pending) |
| Go (v2) | `aptos-go-sdk/v2` v2.0.0-dev | ✅ | single, multi-agent (localnet tests pending) |
| Python (v1) | `aptos-sdk` >=0.11.0 | ✅ | mock only (no orderless support) |
| Python (v2) | `aptos-sdk-v2` | ✅ | mock only (localnet tests pending) |
| Rust | `aptos-sdk` 0.5.0 | ✅ | mock only |

- **BCS encoding is bit-identical across all 4 SDKs** — same inputs → same bytes, proven by `conformance/cases/encode-single.yaml`
- **Ed25519 signatures are deterministic and identical** across all 4 SDKs — proven by `conformance/cases/sign-single-ed25519.yaml`
- Canonical BCS test vector: [`fixtures/bcs/single-transfer-raw.hex`](fixtures/bcs/single-transfer-raw.hex)
- CI runs two jobs: **conformance** (mock, all languages) and **localnet-live** (real TypeScript + Go tests)
- the TypeScript `pnpm start:deno` entrypoint falls back to `$HOME/.deno/bin/deno` when `deno` is not on `PATH`
- `multi-agent` supports both entry-function (`--function`) and script payload (`--script-hex`)
- `multi-sig` uses `--multisig-action`: `create-account`, `propose`, `approve`, `execute`
- `multi-key` uses `--multi-key-public-key`, `--multi-key-threshold`, `--multi-key-signer <index>:<key>`

## Validation

- shared mock conformance: [`conformance/README.md`](conformance/README.md)
- conformance test cases: [`conformance/cases/`](conformance/cases/)
- saved baselines: [`conformance/baselines/`](conformance/baselines/)
- shared real multi-agent helper: [`tests/live_multi_agent.py`](tests/live_multi_agent.py)
- TypeScript localnet multikey flow: [`implementations/typescript/scripts/live-multikey.ts`](implementations/typescript/scripts/live-multikey.ts)
- TypeScript localnet multisig flow: [`implementations/typescript/scripts/live-multisig.ts`](implementations/typescript/scripts/live-multisig.ts)
- Go CLI localnet multisig flow: [`implementations/go/integration/cli_multisig_test.go`](implementations/go/integration/cli_multisig_test.go)
- Go SDK localnet multisig flow: [`implementations/go/integration/multisig_test.go`](implementations/go/integration/multisig_test.go)
