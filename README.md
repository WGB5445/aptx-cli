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
- Go: [`implementations/go/README.md`](implementations/go/README.md)
- Python: [`implementations/python/README.md`](implementations/python/README.md)
- Rust: [`implementations/rust/README.md`](implementations/rust/README.md)

## Quick Start

Run shared mock conformance across all implementations:

```bash
python3 conformance/run.py
```

Run a specific implementation:

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

| Implementation | SDK | Real coverage |
|---|---|---|
| TypeScript | `@aptos-labs/ts-sdk` ^6.1.0 | single, multi-agent, multi-key, multi-sig |
| Go | `aptos-go-sdk` v1.12.0 | single, multi-agent, multi-sig (multi-key pending) |
| Python | `aptos-python-sdk` | mock only |
| Rust | `aptos-rust-sdk` | mock only |

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
