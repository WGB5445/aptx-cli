# Project Guide

This repository is an Aptos transaction CLI workspace. It contains:

- a canonical CLI contract in `spec/`
- shared test cases and conformance checks in `conformance/`
- shared fixtures in `fixtures/`
- multiple language implementations in `implementations/`
- localnet-backed integration coverage in `tests/` and language-specific integration tests
- SDK version management scripts in `scripts/`

## Intent

The project is not a single CLI implementation. It is a workspace for keeping several SDK-backed CLIs aligned so new SDK versions can be checked for:

- command-shape compatibility
- transaction behavior compatibility
- localnet usability

When an SDK releases a new version or a branch is ready for review, the workspace provides a structured way to:
1. compare the new version's behavior against a saved baseline
2. see exactly which fields changed
3. understand what developers need to update

## Primary Layout

| Path | Purpose |
|---|---|
| `README.md` | Workspace entrypoint and quick start |
| `UPGRADING.md` | Step-by-step guide for SDK upgrade checking |
| `docs/architecture.md` | Architecture and validation model |
| `spec/canonical-cli.md` | Canonical command and flag contract |
| `spec/output-schema.json` | JSON Schema for the conformance output projection |
| `conformance/run.py` | Conformance runner (loads from `conformance/cases/`) |
| `conformance/cases/` | YAML test case definitions (one file per case) |
| `conformance/baselines/` | Saved conformance baselines for version comparison |
| `scripts/set-sdk-version.sh` | Pin an implementation's SDK to a version or git ref |
| `scripts/show-sdk-versions.sh` | Print currently pinned SDK versions |
| `tests/live_multi_agent.py` | Shared real multi-agent integration helper |
| `implementations/README.md` | Implementation status matrix |
| `implementations/typescript` | TS SDK implementation (Node/Bun/Deno) |
| `implementations/go` | Go SDK implementation and integration tests |
| `implementations/python` | Python mock-oriented implementation |
| `implementations/rust` | Rust mock-oriented implementation |

## SDK Upgrade Checking

See `UPGRADING.md` for the full workflow. Quick reference:

```bash
# 1. Save baseline at current SDK versions
python3 conformance/run.py --save-baseline conformance/baselines/go-sdk-1.12.json

# 2. Switch to a new version or branch
./scripts/set-sdk-version.sh go v1.13.0

# 3. Compare against baseline — shows field-level diffs if anything changed
python3 conformance/run.py --compare-baseline conformance/baselines/go-sdk-1.12.json
```

## Adding Test Cases

Test cases are YAML files in `conformance/cases/`. No Python code changes needed:

1. Create `conformance/cases/<name>.yaml`
2. Define `name`, `description`, `implementations`, and `argv`
3. Run `python3 conformance/run.py --filter <name>` to verify

See `conformance/README.md` for the YAML format.

## Working Rules

- Preserve the canonical CLI shape unless `spec/canonical-cli.md` and all active implementations are updated together.
- Prefer localnet-backed tests for real SDK changes.
- Keep mock conformance working even when only part of the workspace has real SDK support.
- Do not commit local build artifacts or generated binaries.

## Validation

Before considering a real backend change complete:

```bash
# Mock conformance (all languages)
python3 conformance/run.py

# TypeScript type check
cd implementations/typescript && pnpm exec tsc --noEmit

# Go build
cd implementations/go && go build ./...

# Localnet-backed tests for any changed real transaction path
# (see .github/workflows/ci.yml for the full test commands)
```

## Current Reality

| Implementation | SDK | Real Coverage | Localnet |
|---|---|---|---|
| TypeScript | `@aptos-labs/ts-sdk` ^6.1.0 | single, multi-agent, multi-key, multi-sig | yes |
| Go | `aptos-go-sdk` v1.12.0 | single, multi-agent, multi-sig (multi-key pending) | yes |
| Python | `aptos-python-sdk` | mock only | no |
| Rust | `aptos-rust-sdk` | mock only | no |
