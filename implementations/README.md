# Implementations

This directory contains language-specific implementations of the same canonical Aptos transaction CLI.

## Status Matrix

| Language | Target SDK | Real SDK Coverage | Localnet Integration |
| --- | --- | --- | --- |
| TypeScript | `@aptos-labs/ts-sdk` | `single`, `multi-agent`, `multi-key`, `multi-sig`, `inspect`, `confidential-asset` (TS-only, see [spec/confidential-asset.md](../spec/confidential-asset.md)) | yes |
| Go (v1) | `github.com/aptos-labs/aptos-go-sdk` v1.x | `single`, `multi-agent`, `multi-sig`, `inspect` | yes |
| Go (v2) | `github.com/aptos-labs/aptos-go-sdk/v2` | `single` ✅, `multi-agent` ✅, `multi-key`/`multi-sig` ❌ | no (pending) |
| Python (v1) | `aptos-sdk >= 0.11.0` (PyPI) | `single` ✅, `multi-agent` ⚠️ (primary-only), `multi-key`/`multi-sig` ❌ | no |
| Python (v2) | `aptos-sdk-v2` | `single` ✅, `multi-agent` ⚠️ (primary-only), `multi-key`/`multi-sig` ❌ | no (pending) |
| Rust | `aptos-sdk = "0.5.0"` (crates.io) | `single` ✅, `multi-agent` ✅ (NoAccountAuth), `multi-key`/`multi-sig` ❌ | no |

Legend: ✅ full support, ⚠️ partial (see [sdk-feedback.md](../docs/sdk-feedback.md)), ❌ not yet implemented

## Why The Matrix Is Uneven

The workspace is intentionally staged.

- TypeScript is the primary real backend and the fastest place to add new CLI behavior.
- Go is the second real backend and is used to cross-check real SDK behavior.
- Python and Rust now have **real SDK paths** for single and multi-agent simulation.
  Rust uses `aptos-sdk = "0.5.0"` (from [aptos-rust-sdk](https://github.com/aptos-labs/aptos-rust-sdk))
  which provides `NoAccountAuthenticator` for keyless simulation and `build_simulation_signed_multi_agent`
  for multi-agent. Python falls back to primary-only for multi-agent (SDK limitation).
- Multi-key and multi-sig remain mock-only for Python and Rust pending upstream SDK support.
  See [docs/sdk-feedback.md](../docs/sdk-feedback.md) for the full analysis.

## Current Rule

When a feature is called "implemented" at the workspace level, the expectation is:

1. the canonical CLI contract reflects it
2. at least one real backend supports it end-to-end
3. a localnet-backed test exists for that real path

Cross-language parity is still a goal, but it is not yet complete for every transaction type in every language.
