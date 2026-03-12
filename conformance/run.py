#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "fixtures" / "transactions" / "single-transfer.json"

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

CASES = [
    {
        "name": "single-simulate",
        "implementations": ["typescript", "python", "go", "rust"],
        "argv": [
            "simulate",
            "single",
            "--input",
            str(FIXTURE),
        ],
    },
    {
        "name": "multi-agent-simulate",
        "implementations": ["typescript", "python", "go", "rust"],
        "argv": [
            "simulate",
            "multi-agent",
            "--network",
            "testnet",
            "--function",
            "0x1::aptos_account::transfer",
            "--sender-address",
            "0x111",
            "--secondary-signer-address",
            "0x222",
            "--arg",
            "address:0x333",
            "--arg",
            "u64:1000",
        ],
    },
    {
        "name": "multi-key-simulate",
        "implementations": ["typescript", "python", "rust"],
        "argv": [
            "simulate",
            "multi-key",
            "--network",
            "testnet",
            "--function",
            "0x1::aptos_account::transfer",
            "--sender-address",
            "0x111",
            "--multi-key-threshold",
            "2",
            "--multi-key-public-key",
            "0xaaa",
            "--multi-key-public-key",
            "0xbbb",
            "--arg",
            "address:0x333",
            "--arg",
            "u64:1000",
        ],
    },
    {
        "name": "multi-sig-propose-simulate",
        "implementations": ["typescript", "python", "go", "rust"],
        "argv": [
            "simulate",
            "multi-sig",
            "--network",
            "testnet",
            "--multisig-action",
            "propose",
            "--multisig-address",
            "0xabc",
            "--function",
            "0x1::aptos_account::transfer",
            "--sender-address",
            "0x111",
            "--arg",
            "address:0x333",
            "--arg",
            "u64:1000",
        ],
    },
]


def run_impl(name: str, case: dict):
    cmd = [
        *IMPLEMENTATIONS[name],
        *case["argv"],
        "--sdk-mode",
        "mock",
        "--output-format",
        "json",
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
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{name} failed with code {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return json.loads(proc.stdout)


def projection(payload: dict) -> dict:
    sender_address = payload["input"]["sender_address"]
    if isinstance(sender_address, str) and sender_address.startswith("0x"):
        sender_address = f"0x{sender_address[2:].rjust(64, '0')}"
    args = payload["input"].get("args") or []
    type_args = payload["input"].get("type_args") or []
    return {
        "action": payload["action"],
        "txn_type": payload["txn_type"],
        "function": payload["input"]["function"],
        "args": args,
        "type_args": type_args,
        "sender_address": sender_address,
        "abi_enabled": payload["abi_enabled"],
        "sign_mode": payload["signing"]["mode"],
        "result_mode": payload["result"]["mode"],
        "success": payload["result"]["success"],
        "vm_status": payload["result"]["vm_status"],
        "gas_used": payload["result"]["gas_used"],
    }


def main() -> int:
    case_results = {}
    for case in CASES:
        results = {}
        case_impls = case.get("implementations", list(IMPLEMENTATIONS.keys()))
        for name in case_impls:
            payload = run_impl(name, case)
            results[name] = projection(payload)

        baseline = None
        for name, proj in results.items():
            if baseline is None:
                baseline = proj
                continue
            if proj != baseline:
                print(json.dumps({"case": case["name"], "results": results}, indent=2))
                print(f"conformance mismatch detected in {name} for case {case['name']}", file=sys.stderr)
                return 1
        case_results[case["name"]] = baseline

    print(
        json.dumps(
            {
                "status": "ok",
                "cases": case_results,
                "implementations": list(IMPLEMENTATIONS.keys()),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
