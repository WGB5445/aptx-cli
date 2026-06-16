# Conformance

The conformance suite verifies that all SDK implementations produce identical normalized output for the same inputs. It runs in mock mode — no network or private keys required.

## Quick start

```bash
python3 conformance/run.py
```

## Test cases

Cases live in `conformance/cases/*.yaml`. Each file defines:

| Field | Description |
|---|---|
| `name` | Unique identifier shown in output |
| `description` | Human-readable summary of what the case tests |
| `implementations` | Which language impls to include (omit to include all) |
| `argv` | CLI arguments passed to every implementation |

Use `{{fixtures}}` in `argv` values to reference the shared fixtures directory.

Example:

```yaml
name: single-simulate
description: Simulate a single transfer transaction loaded from a JSON fixture
implementations: [typescript, python, go, rust]
argv:
  - simulate
  - single
  - --input
  - "{{fixtures}}/transactions/single-transfer.json"
```

To add a new test case, create a new YAML file in `conformance/cases/`. No code changes required.

## CLI options

```
python3 conformance/run.py [options]

  --filter PATTERN       Only run cases whose name contains PATTERN
  --impl IMPL[,IMPL]     Only run specific implementations (e.g. typescript,go)
  --save-baseline FILE   Save results as a versioned baseline JSON file
  --compare-baseline FILE  Compare results against a saved baseline
```

## SDK version compatibility checking

This is the primary workflow for checking whether a new SDK version is compatible with the previous one.

**Step 1 — Save a baseline from the current stable SDK versions:**

```bash
python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.1.json
```

**Step 2 — Upgrade the SDK:**

```bash
# TypeScript
./scripts/set-sdk-version.sh typescript 6.2.0

# Go
./scripts/set-sdk-version.sh go v1.13.0
```

**Step 3 — Compare against the baseline:**

```bash
python3 conformance/run.py --compare-baseline conformance/baselines/ts-sdk-6.1.json
```

If all cases match, you will see:

```
All cases match baseline — SDK upgrade appears compatible.
```

If there are behavioral differences, the output lists exactly which fields changed:

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
        "vm_status": { "baseline": "success", "current": "Executed successfully" }
      }
    }
  ]
}
```

## What this suite validates

- Command shape (flags accepted, output written)
- Stable JSON output structure across all implementations
- Cross-implementation consistency (all impls agree on every field)

## What this suite does NOT validate

- Real SDK behavior (network calls, signature verification, on-chain results)
- Transaction execution — mock mode returns deterministic placeholder results

Real-network validation lives in `.github/workflows/ci.yml` (localnet-live job) and in `tests/`.
