# Architecture

## Purpose

This workspace exists to keep multiple Aptos SDK-backed CLIs aligned around one canonical contract. The immediate product is a transaction-oriented CLI. The broader goal is **SDK compatibility validation**: detect breaking changes when upgrading to a new SDK version, and surface what developers need to change.

## Layers

### 1. Canonical Contract

`spec/canonical-cli.md` defines the shared command shape:

- actions: `simulate`, `submit`, `run`, `inspect`
- transaction types: `single`, `multi-agent`, `multi-key`, `multi-sig`
- flags, argument format, and behavioral rules

`spec/output-schema.json` defines the normalized JSON projection that every implementation must produce. This is what the conformance runner compares.

### 2. Shared Test Cases

`conformance/cases/*.yaml` contains the test cases. Each YAML file specifies:

- which implementations to include
- the CLI argv to pass
- a human-readable description

Adding a new test case requires no Python changes — just add a YAML file.

### 3. Conformance Runner

`conformance/run.py` loads test cases from `conformance/cases/`, runs each implementation with `--sdk-mode mock`, extracts the normalized projection from the output, and checks that all implementations agree.

Key features:

- `--filter PATTERN` — run only matching cases
- `--impl LIST` — run only specific implementations
- `--save-baseline FILE` — save results as a versioned baseline JSON
- `--compare-baseline FILE` — compare current results against a saved baseline

The runner also reads and reports the current SDK versions from each implementation's package config.

### 4. Real SDK Implementations

Each implementation lives under `implementations/<language>`:

- `typescript`: primary real backend, supports Node/Bun/Deno
- `go`: real backend for core transaction paths
- `python`: mock-oriented (conformance only)
- `rust`: mock-oriented (conformance only)

### 5. Real Integration Coverage

Real behavior is validated against Aptos localnet. Current coverage:

- shared real multi-agent flow via `tests/live_multi_agent.py`
- TypeScript localnet multikey and multisig flows
- Go localnet multisig flow and CLI-driven multisig flow

## Validation Model

The repository uses two validation tracks.

### Mock Track

Purpose:
- fast, shared, deterministic
- validates CLI contract, output structure, and cross-implementation consistency

Entry:

```bash
python3 conformance/run.py
```

### Localnet Track

Purpose:
- validates real SDK behavior
- validates transaction build/sign/simulate/submit/wait paths

Entry:
- GitHub Actions workflow in `.github/workflows/ci.yml` (`localnet-live` job)
- local runs using `aptos node run-localnet`

## SDK Version Compatibility Workflow

When evaluating a new SDK version:

1. Save a baseline with the current versions:
   ```bash
   python3 conformance/run.py --save-baseline conformance/baselines/go-sdk-1.12.json
   ```

2. Upgrade the SDK:
   ```bash
   ./scripts/set-sdk-version.sh go v1.13.0
   ```

3. Compare against the baseline:
   ```bash
   python3 conformance/run.py --compare-baseline conformance/baselines/go-sdk-1.12.json
   ```

   If compatible: `All cases match baseline — SDK upgrade appears compatible.`

   If not: the diff output shows exactly which fields changed, allowing developers to see what needs to be updated.

## Why the Mock/Localnet Split Exists

Not every language SDK is equally mature. Requiring all implementations to have identical real coverage would stall progress. The split allows:

- strict structure checks across all languages
- deeper real checks where the SDKs are ready
- gradual expansion of real coverage

## Current Gaps

- Go `multi-key` support is not yet implemented
- Python and Rust are not yet connected to real localnet flows
- conformance compares mock-shaped projections; real execution parity is validated separately in CI

## Practical Rule

When adding or changing a real feature:

1. Update `spec/canonical-cli.md` if the command shape changes
2. Update or add a `conformance/cases/*.yaml` test case for the new behavior
3. Update the implementation(s)
4. Add or update a real localnet test for that path
5. Keep shared conformance stable unless the contract intentionally changed
