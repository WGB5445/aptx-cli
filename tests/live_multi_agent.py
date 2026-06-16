#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
TS_DIR = ROOT / "implementations" / "typescript"
GO_DIR = ROOT / "implementations" / "go"
TEST_NETWORK = os.environ.get("APTX_TEST_NETWORK", "devnet").lower()
TEST_FULLNODE = os.environ.get("APTX_TEST_FULLNODE", "")
TEST_FAUCET = os.environ.get("APTX_TEST_FAUCET", "")

DEFAULT_FULLNODES = {
    "devnet": "https://api.devnet.aptoslabs.com/v1",
    "local": "http://127.0.0.1:8080/v1",
    "localnet": "http://127.0.0.1:8080/v1",
}
DEFAULT_FAUCETS = {
    "devnet": "https://faucet.devnet.aptoslabs.com",
    "local": "http://127.0.0.1:8081",
    "localnet": "http://127.0.0.1:8081",
}

MULTI_AGENT_SCRIPT_HEX = (
    "0xa11ceb0b0700000a0601000403040d04110405151b07302f085f2000000001010203040001000306020100010105010704060c"
    "060c03030205050001060c010501090003060c05030109010d6170746f735f6163636f756e74067369676e65720a61646472657373"
    "5f6f660e7472616e736665725f636f696e730000000000000000000000000000000000000000000000000000000000000001020000"
    "00010f0a0011000c040a0111000c050b000b050b0238000b010b040b03380102"
)
TYPE_ARGS = ["0x1::aptos_coin::AptosCoin", "0x1::aptos_coin::AptosCoin"]
SCRIPT_ARGS = ["u64:1000", "u64:1200"]


def run_cmd(cmd: List[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
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
            f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def load_json_output(stdout: str) -> dict:
    text = stdout.strip()
    if not text:
        raise ValueError("command produced empty stdout")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"stdout does not contain a JSON object:\n{text}")
    return json.loads(text[start : end + 1])


def fullnode_url() -> str:
    return TEST_FULLNODE or DEFAULT_FULLNODES.get(TEST_NETWORK, DEFAULT_FULLNODES["devnet"])


def faucet_url() -> str:
    return TEST_FAUCET or DEFAULT_FAUCETS.get(TEST_NETWORK, DEFAULT_FAUCETS["devnet"])


def http_json(url: str, *, method: str = "GET", body: Optional[dict] = None) -> dict:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"
    request = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def wait_for_transaction(tx_hash: str, timeout_secs: int = 60) -> None:
    deadline = time.time() + timeout_secs
    last_error = ""
    while time.time() < deadline:
        try:
            response = http_json(f"{fullnode_url()}/transactions/by_hash/{tx_hash}")
            if response.get("type") == "pending_transaction":
                time.sleep(1)
                continue
            if response.get("success") is False:
                raise RuntimeError(f"funding transaction failed: {response.get('vm_status')}")
            return
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                time.sleep(1)
                continue
            last_error = str(exc)
            time.sleep(1)
        except Exception as exc:
            last_error = str(exc)
            time.sleep(1)
    raise RuntimeError(f"timed out waiting for transaction {tx_hash}: {last_error}")


def fund_account(address: str, amount: int = 100_000_000, repeat: int = 3) -> None:
    """Fund an account, repeating `repeat` times to accumulate enough balance.

    The localnet faucet caps individual mint amounts.  Repeating ensures the
    account has enough balance for SDK-estimated max_gas_amount * gas_unit_price.
    Each call waits for ALL returned txn_hashes before proceeding.
    """
    for _ in range(repeat):
        response = http_json(f"{faucet_url()}/fund", method="POST", body={"address": address, "amount": amount})
        txn_hashes = response.get("txn_hashes") or []
        if not txn_hashes:
            raise RuntimeError(f"faucet response missing txn_hashes: {response}")
        for tx_hash in txn_hashes:
            wait_for_transaction(tx_hash)


def provision_accounts() -> dict:
    script = """
import { Account } from "@aptos-labs/ts-sdk";

const sender = Account.generate();
const secondary = Account.generate();

console.log(JSON.stringify({
  sender: {
    address: String(sender.accountAddress),
    publicKey: sender.publicKey.toString(),
    privateKey: sender.privateKey.toString(),
  },
  secondary: {
    address: String(secondary.accountAddress),
    publicKey: secondary.publicKey.toString(),
    privateKey: secondary.privateKey.toString(),
  },
}));
""".strip()
    proc = run_cmd(["node", "--input-type=module", "-e", script], cwd=TS_DIR, env=os.environ.copy())
    accounts = json.loads(proc.stdout)
    fund_account(accounts["sender"]["address"])
    fund_account(accounts["secondary"]["address"])
    return accounts


def base_multi_agent_args(accounts: dict) -> list[str]:
    args = [
        "--network",
        TEST_NETWORK,
        "--script-hex",
        MULTI_AGENT_SCRIPT_HEX,
        "--type-arg",
        TYPE_ARGS[0],
        "--type-arg",
        TYPE_ARGS[1],
        "--sender-address",
        accounts["sender"]["address"],
        "--secondary-signer-address",
        accounts["secondary"]["address"],
        "--arg",
        SCRIPT_ARGS[0],
        "--arg",
        SCRIPT_ARGS[1],
    ]
    if TEST_FULLNODE:
        args.extend(["--fullnode", TEST_FULLNODE])
    return args


def assert_success(payload: dict, implementation: str, action: str) -> None:
    if payload["implementation"] != implementation:
        raise AssertionError(f"unexpected implementation: {payload['implementation']}")
    if payload["txn_type"] != "multi-agent":
        raise AssertionError(f"unexpected txn_type: {payload['txn_type']}")
    if payload["sdk_mode"] != "sdk":
        raise AssertionError(f"unexpected sdk_mode: {payload['sdk_mode']}")
    if payload["result"]["vm_status"] != "Executed successfully":
        raise AssertionError(f"{implementation} {action} vm_status mismatch: {payload['result']['vm_status']}")
    if payload["result"]["success"] is not True:
        raise AssertionError(f"{implementation} {action} success mismatch: {payload['result']['success']}")


def run_typescript(accounts: dict) -> None:
    simulate_cmd = [
        "pnpm",
        "--silent",
        "start",
        "--",
        "simulate",
        "multi-agent",
        *base_multi_agent_args(accounts),
        "--public-key",
        accounts["sender"]["publicKey"],
        "--secondary-public-key",
        accounts["secondary"]["publicKey"],
        "--output-format",
        "json",
    ]
    simulate_payload = load_json_output(run_cmd(simulate_cmd, cwd=TS_DIR).stdout)
    assert_success(simulate_payload, "typescript", "simulate")

    deno_cmd = [
        "pnpm",
        "--silent",
        "start:deno",
        "--",
        "simulate",
        "multi-agent",
        *base_multi_agent_args(accounts),
        "--public-key",
        accounts["sender"]["publicKey"],
        "--secondary-public-key",
        accounts["secondary"]["publicKey"],
        "--output-format",
        "json",
    ]
    deno_payload = load_json_output(run_cmd(deno_cmd, cwd=TS_DIR).stdout)
    assert_success(deno_payload, "typescript", "simulate-deno")

    run_cmd_args = [
        "pnpm",
        "--silent",
        "start",
        "--",
        "run",
        "multi-agent",
        *base_multi_agent_args(accounts),
        "--private-key",
        accounts["sender"]["privateKey"],
        "--secondary-private-key",
        accounts["secondary"]["privateKey"],
        "--output-format",
        "json",
    ]
    run_payload = load_json_output(run_cmd(run_cmd_args, cwd=TS_DIR).stdout)
    assert_success(run_payload, "typescript", "run")


def run_go(accounts: dict) -> None:
    env = os.environ.copy()
    env["GOCACHE"] = str(ROOT / ".cache" / "go-build")
    env["GOMODCACHE"] = str(ROOT / ".cache" / "go-mod")

    simulate_cmd = [
        "go",
        "run",
        "./cmd/aptx",
        "simulate",
        "multi-agent",
        *base_multi_agent_args(accounts),
        "--public-key",
        accounts["sender"]["publicKey"],
        "--output-format",
        "json",
    ]
    simulate_payload = json.loads(run_cmd(simulate_cmd, cwd=GO_DIR, env=env).stdout)
    assert_success(simulate_payload, "go", "simulate")

    run_cmd_args = [
        "go",
        "run",
        "./cmd/aptx",
        "run",
        "multi-agent",
        *base_multi_agent_args(accounts),
        "--private-key",
        accounts["sender"]["privateKey"],
        "--secondary-private-key",
        accounts["secondary"]["privateKey"],
        "--output-format",
        "json",
    ]
    run_payload = json.loads(run_cmd(run_cmd_args, cwd=GO_DIR, env=env).stdout)
    assert_success(run_payload, "go", "run")


def main() -> int:
    if os.environ.get("APTX_SKIP_LIVE") == "1":
        print(json.dumps({"status": "skipped", "reason": "APTX_SKIP_LIVE=1"}, indent=2))
        return 0

    accounts = provision_accounts()
    run_typescript(accounts)
    run_go(accounts)
    print(json.dumps({"status": "ok", "tested": ["typescript", "typescript-deno", "go"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
