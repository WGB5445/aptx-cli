#!/usr/bin/env python3
"""
Conformance runner for aptx-cli.

Loads test cases from conformance/cases/*.yaml, runs each against the
relevant implementations, and checks that they all produce identical
normalized output.

Usage:
  # Run all cases, compare implementations against each other
  python3 conformance/run.py

  # Run only cases matching a substring pattern
  python3 conformance/run.py --filter single

  # Run only specific implementations
  python3 conformance/run.py --impl typescript,go

  # Save results as a versioned baseline (for later comparison)
  python3 conformance/run.py --save-baseline conformance/baselines/ts-sdk-6.1.json

  # Compare current results against a saved baseline (SDK upgrade check)
  python3 conformance/run.py --compare-baseline conformance/baselines/ts-sdk-6.1.json
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    import yaml as _yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = Path(__file__).resolve().parent / "cases"

IMPLEMENTATIONS = {
    "typescript": [
        "node",
        "--experimental-strip-types",
        str(ROOT / "implementations" / "typescript" / "src" / "cli.ts"),
    ],
    "python": [
        "python3",
        "-m",
        "aptx_py",
    ],
    "go": [
        "go",
        "run",
        "./cmd/aptx",
    ],
    "rust": [
        "cargo",
        "run",
        "--quiet",
        "--",
    ],
}


# ---------------------------------------------------------------------------
# Case loading
# ---------------------------------------------------------------------------

def _parse_yaml_simple(path: Path) -> dict:
    """Minimal YAML parser for simple flat/list-only case files (no pyyaml required)."""
    result: dict = {}
    current_list: str | None = None

    with path.open() as f:
        for raw in f:
            line = raw.rstrip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("  - "):
                val = line[4:]
                if (val.startswith('"') and val.endswith('"')) or \
                   (val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                if current_list is not None:
                    result[current_list].append(val)
                continue

            if ":" in line:
                key, _, rest = line.partition(":")
                key = key.strip()
                rest = rest.strip()
                if rest == "":
                    result[key] = []
                    current_list = key
                elif rest.startswith("["):
                    items = rest.strip("[]").split(",")
                    result[key] = [i.strip().strip("\"'") for i in items if i.strip()]
                    current_list = None
                else:
                    if (rest.startswith('"') and rest.endswith('"')) or \
                       (rest.startswith("'") and rest.endswith("'")):
                        rest = rest[1:-1]
                    result[key] = rest
                    current_list = None

    return result


def load_cases() -> list[dict]:
    """Load all test cases from conformance/cases/*.yaml, sorted by filename."""
    if not CASES_DIR.exists():
        return []

    cases = []
    for path in sorted(CASES_DIR.glob("*.yaml")):
        if _HAS_YAML:
            with path.open() as f:
                case = _yaml.safe_load(f)
        else:
            case = _parse_yaml_simple(path)

        # Expand {{fixtures}} placeholder
        fixtures_root = str(ROOT / "fixtures")
        case["argv"] = [
            a.replace("{{fixtures}}", fixtures_root) for a in case["argv"]
        ]
        cases.append(case)

    return cases


# ---------------------------------------------------------------------------
# SDK version reading
# ---------------------------------------------------------------------------

def read_sdk_versions() -> dict:
    """Read pinned SDK versions from each implementation's package config."""
    versions: dict = {}

    # TypeScript: @aptos-labs/ts-sdk from package.json
    ts_pkg = ROOT / "implementations" / "typescript" / "package.json"
    if ts_pkg.exists():
        pkg = json.loads(ts_pkg.read_text())
        versions["typescript"] = pkg.get("dependencies", {}).get("@aptos-labs/ts-sdk")
    else:
        versions["typescript"] = None

    # Go: aptos-go-sdk from go.mod (handles both single-line and block require forms)
    go_mod = ROOT / "implementations" / "go" / "go.mod"
    versions["go"] = None
    if go_mod.exists():
        for line in go_mod.read_text().splitlines():
            parts = line.strip().split()
            # single-line: "require github.com/aptos-labs/aptos-go-sdk v1.13.0"
            if len(parts) >= 3 and parts[0] == "require" and parts[1] == "github.com/aptos-labs/aptos-go-sdk":
                versions["go"] = parts[2]
                break
            # block form: "    github.com/aptos-labs/aptos-go-sdk v1.13.0 // indirect"
            if len(parts) >= 2 and parts[0] == "github.com/aptos-labs/aptos-go-sdk":
                versions["go"] = parts[1]
                break

    # Python: aptos-sdk from pyproject.toml
    py_toml = ROOT / "implementations" / "python" / "pyproject.toml"
    versions["python"] = None
    if py_toml.exists():
        for line in py_toml.read_text().splitlines():
            stripped = line.strip().strip('",')
            if stripped.startswith("aptos-sdk"):
                versions["python"] = stripped
                break

    # Rust: aptos-sdk from Cargo.toml
    cargo_toml = ROOT / "implementations" / "rust" / "Cargo.toml"
    versions["rust"] = None
    if cargo_toml.exists():
        for line in cargo_toml.read_text().splitlines():
            if line.startswith("aptos-sdk"):
                import re
                m = re.search(r'version\s*=\s*"([^"]+)"', line)
                if m:
                    versions["rust"] = m.group(1)
                    break

    return versions


# ---------------------------------------------------------------------------
# Running an implementation
# ---------------------------------------------------------------------------

def _action_from_case(case: dict) -> str:
    """Extract the action name from the case argv."""
    argv = case.get("argv", [])
    return argv[0] if argv else ""


def run_impl(name: str, case: dict) -> dict:
    action = _action_from_case(case)
    extra_flags: list[str] = []
    # encode/decode/sign don't need --sdk-mode (they work offline)
    # but we still pass it so the CLI doesn't complain about unknown flags
    if action not in ("encode", "decode", "sign"):
        extra_flags = ["--sdk-mode", "mock"]
    cmd = [
        *IMPLEMENTATIONS[name],
        *case["argv"],
        *extra_flags,
        "--output-format", "json",
    ]
    cwd = ROOT
    env = os.environ.copy()

    if name == "python":
        cwd = ROOT / "implementations" / "python"
    elif name == "go":
        cwd = ROOT / "implementations" / "go"
        cache_dir = ROOT / ".cache" / "go-build"
        cache_dir.mkdir(parents=True, exist_ok=True)
        env["GOCACHE"] = str(cache_dir)
    elif name == "rust":
        cwd = ROOT / "implementations" / "rust"
        target_dir = ROOT / ".cache" / "cargo-target"
        target_dir.mkdir(parents=True, exist_ok=True)
        env["CARGO_TARGET_DIR"] = str(target_dir)

    proc = subprocess.run(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{name} exited {proc.returncode}\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


# ---------------------------------------------------------------------------
# Output normalization (projection)
# ---------------------------------------------------------------------------

def _normalize_address(addr: str) -> str:
    """Pad short 0x-prefixed addresses to 64 hex chars."""
    if isinstance(addr, str) and addr.startswith("0x"):
        return f"0x{addr[2:].rjust(64, '0')}"
    return addr


def projection(payload: dict) -> dict:
    """Extract the stable, implementation-independent fields from a result."""
    action = payload.get("action", "")

    if action == "encode":
        return {
            "action": "encode",
            "txn_type": payload.get("txn_type"),
            "bcs": payload.get("bcs"),
            "function": payload.get("function"),
            "chain_id": payload.get("chain_id"),
            "sequence_number": payload.get("sequence_number"),
            "max_gas_amount": payload.get("max_gas_amount"),
            "gas_unit_price": payload.get("gas_unit_price"),
            "expiration_timestamp": payload.get("expiration_timestamp"),
        }

    if action == "decode":
        def _seq(v):
            if v == "max_u64":
                return "max_u64"
            try:
                return int(v)
            except (ValueError, TypeError):
                return v
        return {
            "action": "decode",
            "txn_type": payload.get("txn_type"),
            "sender": _normalize_address(str(payload.get("sender", ""))),
            "function": payload.get("function"),
            "chain_id": int(payload["chain_id"]) if "chain_id" in payload else None,
            "sequence_number": _seq(payload.get("sequence_number")),
            "max_gas_amount": int(payload["max_gas_amount"]) if "max_gas_amount" in payload else None,
            "gas_unit_price": int(payload["gas_unit_price"]) if "gas_unit_price" in payload else None,
            "expiration_timestamp": int(payload["expiration_timestamp"]) if "expiration_timestamp" in payload else None,
        }

    if action == "sign":
        return {
            "action": "sign",
            "public_key": payload.get("public_key"),
            "signature": payload.get("signature"),
        }

    # Existing simulate/submit/run/inspect projection
    sender = payload["input"]["sender_address"]
    if isinstance(sender, str) and sender.startswith("0x"):
        sender = f"0x{sender[2:].rjust(64, '0')}"
    return {
        "action": payload["action"],
        "txn_type": payload["txn_type"],
        "function": payload["input"]["function"],
        "args": payload["input"].get("args") or [],
        "type_args": payload["input"].get("type_args") or [],
        "sender_address": sender,
        "abi_enabled": payload["abi_enabled"],
        "sign_mode": payload["signing"]["mode"],
        "result_mode": payload["result"]["mode"],
        "success": payload["result"]["success"],
        "vm_status": payload["result"]["vm_status"],
        "gas_used": payload["result"]["gas_used"],
    }


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def diff_results(baseline: dict, current: dict) -> list[dict]:
    """Return field-level differences between two conformance result sets."""
    diffs = []
    b_cases = baseline.get("cases", {})
    c_cases = current.get("cases", {})
    all_cases = sorted(set(b_cases) | set(c_cases))

    for name in all_cases:
        b = b_cases.get(name)
        c = c_cases.get(name)
        if b is None:
            diffs.append({"case": name, "change": "added"})
        elif c is None:
            diffs.append({"case": name, "change": "removed"})
        elif b != c:
            fields = {
                k: {"baseline": b.get(k), "current": c.get(k)}
                for k in set(b) | set(c)
                if b.get(k) != c.get(k)
            }
            diffs.append({"case": name, "change": "modified", "fields": fields})

    return diffs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run aptx-cli conformance checks across implementations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--filter", metavar="PATTERN",
        help="Only run cases whose name contains PATTERN",
    )
    parser.add_argument(
        "--impl", metavar="IMPL",
        help="Comma-separated implementations to run (e.g. typescript,go)",
    )
    parser.add_argument(
        "--save-baseline", metavar="FILE",
        help="Save conformance results as a baseline JSON file",
    )
    parser.add_argument(
        "--compare-baseline", metavar="FILE",
        help="Compare results against a saved baseline (SDK upgrade check)",
    )
    args = parser.parse_args()

    impl_filter = set(args.impl.split(",")) if args.impl else None

    cases = load_cases()
    if not cases:
        print("No test cases found in conformance/cases/. Did you forget to create them?", file=sys.stderr)
        return 1

    if args.filter:
        cases = [c for c in cases if args.filter in c["name"]]
        if not cases:
            print(f"No cases match filter '{args.filter}'", file=sys.stderr)
            return 1

    sdk_versions = read_sdk_versions()
    case_results: dict = {}
    failed = False

    for case in cases:
        case_impls = case.get("implementations", list(IMPLEMENTATIONS.keys()))
        if impl_filter:
            case_impls = [i for i in case_impls if i in impl_filter]

        projections: dict = {}
        for name in case_impls:
            try:
                payload = run_impl(name, case)
                projections[name] = projection(payload)
            except Exception as exc:
                print(f"ERROR [{case['name']}] {name}: {exc}", file=sys.stderr)
                failed = True
                continue

        if not projections:
            continue

        # Cross-implementation consistency check
        reference_impl, reference_proj = next(iter(projections.items()))
        for name, proj in projections.items():
            if proj != reference_proj:
                print(
                    json.dumps({"case": case["name"], "mismatch": {reference_impl: reference_proj, name: proj}}, indent=2),
                )
                print(
                    f"MISMATCH [{case['name']}]: {name} differs from {reference_impl}",
                    file=sys.stderr,
                )
                failed = True

        # Record canonical result for this case (all matching impls agree)
        case_results[case["name"]] = reference_proj

    current_output = {
        "status": "failed" if failed else "ok",
        "sdk_versions": sdk_versions,
        "cases": case_results,
        "implementations": list(IMPLEMENTATIONS.keys()),
    }

    # --save-baseline
    if args.save_baseline:
        save_path = Path(args.save_baseline)
        if not save_path.is_absolute():
            save_path = ROOT / save_path
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(current_output, indent=2) + "\n")
        print(f"Baseline saved: {save_path}", file=sys.stderr)

    # --compare-baseline
    if args.compare_baseline:
        cmp_path = Path(args.compare_baseline)
        if not cmp_path.is_absolute():
            cmp_path = ROOT / cmp_path
        if not cmp_path.exists():
            print(f"Baseline not found: {cmp_path}", file=sys.stderr)
            return 1

        saved = json.loads(cmp_path.read_text())
        diffs = diff_results(saved, current_output)

        compare_out = {
            "compatible": not diffs and not failed,
            "baseline_sdk_versions": saved.get("sdk_versions", {}),
            "current_sdk_versions": current_output["sdk_versions"],
            "diffs": diffs,
        }
        print(json.dumps(compare_out, indent=2))

        if diffs:
            print(f"\n{len(diffs)} conformance change(s) vs baseline:\n", file=sys.stderr)
            for d in diffs:
                change = d["change"]
                case_name = d["case"]
                if change in ("added", "removed"):
                    print(f"  [{change.upper()}] {case_name}", file=sys.stderr)
                else:
                    print(f"  [MODIFIED] {case_name}", file=sys.stderr)
                    for field, vals in d.get("fields", {}).items():
                        b_val = json.dumps(vals["baseline"])
                        c_val = json.dumps(vals["current"])
                        print(f"    {field}: {b_val} → {c_val}", file=sys.stderr)
            print(
                "\nReview the diff above and update implementations as needed.",
                file=sys.stderr,
            )
            print("See UPGRADING.md for guidance on which changes are breaking.", file=sys.stderr)
            return 1
        if failed:
            return 1
        print("All cases match baseline — SDK upgrade appears compatible.", file=sys.stderr)
        return 0

    print(json.dumps(current_output, indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
