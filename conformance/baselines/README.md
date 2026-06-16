# Conformance Baselines

This directory stores saved conformance results, used to detect behavioral changes when upgrading SDK versions.

## Workflow

**1. Save a baseline for the current SDK versions:**

```bash
python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.1.json
```

**2. Upgrade an SDK version:**

```bash
# TypeScript
./scripts/set-sdk-version.sh typescript 6.2.0

# Go
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

If there are breaking changes, you will see a diff showing exactly which fields changed and how.

## File naming convention

Use descriptive names that identify the SDK and version:

- `ts-sdk-6.1.json` — TypeScript SDK v6.1
- `go-sdk-1.12.json` — Go SDK v1.12
- `all-sdks-stable.json` — snapshot of all implementations at a known-good state

Commit baseline files when you want to track a specific stable state. Do not commit baselines for every CI run.
