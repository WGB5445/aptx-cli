#!/usr/bin/env python3
"""Cross-SDK confidential-asset interop test: TypeScript <-> Go v2.

Unlike single/multi-agent/multi-sig (BCS-encoded, deterministic), confidential-asset
transactions use randomized Twisted ElGamal ciphertexts and sigma/range proofs, so two SDKs
given the same logical input never produce byte-identical output -- there is no
"conformance/run.py baseline diff" equivalent for this txn-type (see
spec/confidential-asset.md's "Cross-SDK verification model" section).

Instead this test proves genuine interop: alice's lifecycle is driven by the Go CLI, bob's by
the TypeScript CLI, and bob's confidential balance is fed by a transfer that GO built, signed,
and submitted -- then rolled over, normalized, and withdrawn by TS. If TS could not correctly
read/spend a ciphertext Go produced, this would fail. Every balance is independently decrypted
via BOTH implementations (Go's native.GetBalance and TS's ConfidentialAsset.getBalance) to
confirm they agree on the plaintext amount despite the ciphertext bytes never matching.

Run:  python3 tests/live_confidential_asset_interop.py
"""
import glob
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
TS_DIR = ROOT / "implementations" / "typescript"
GO_V2_DIR = ROOT / "implementations" / "go-v2"

TEST_NETWORK = os.environ.get("APTX_TEST_NETWORK", "local").lower()
TEST_FULLNODE = os.environ.get("APTX_TEST_FULLNODE", "http://127.0.0.1:8080/v1")
TEST_FAUCET = os.environ.get("APTX_TEST_FAUCET", "http://127.0.0.1:8081")

DEPOSIT_AMOUNT = 2_000_000
TRANSFER_AMOUNT = 500_000
WITHDRAW_AMOUNT = TRANSFER_AMOUNT


def run_cmd(cmd: List[str], cwd: Path, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
    return proc


def load_json_output(stdout: str) -> dict:
    text = stdout.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise ValueError(f"stdout does not contain a JSON object:\n{text}")
    return json.loads(text[start : end + 1])


def http_json(url: str, *, method: str = "GET", body: Optional[dict] = None) -> dict:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"content-type": "application/json"} if body is not None else {}
    request = urllib.request.Request(url, method=method, data=data, headers=headers)
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def wait_for_transaction(tx_hash: str, timeout_secs: int = 60) -> None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        try:
            response = http_json(f"{TEST_FULLNODE}/transactions/by_hash/{tx_hash}")
            if response.get("type") == "pending_transaction":
                time.sleep(1)
                continue
            if response.get("success") is False:
                raise RuntimeError(f"transaction {tx_hash} failed: {response.get('vm_status')}")
            return
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                time.sleep(1)
                continue
            raise
    raise RuntimeError(f"timed out waiting for transaction {tx_hash}")


def fund_account(address: str, amount: int = 100_000_000) -> None:
    response = http_json(f"{TEST_FAUCET}/fund", method="POST", body={"address": address, "amount": amount})
    txn_hashes = response.get("txn_hashes") or []
    if not txn_hashes:
        raise RuntimeError(f"faucet response missing txn_hashes: {response}")
    for tx_hash in txn_hashes:
        wait_for_transaction(tx_hash)


def resolve_apt_fa_metadata_address() -> str:
    result = http_json(
        f"{TEST_FULLNODE}/view",
        method="POST",
        body={
            "function": "0x1::coin::paired_metadata",
            "type_arguments": ["0x1::aptos_coin::AptosCoin"],
            "arguments": [],
        },
    )
    vec = result[0]["vec"]
    if not vec:
        raise RuntimeError("0x1::coin::paired_metadata returned none for AptosCoin")
    return vec[0]["inner"]


def provision_account() -> dict:
    script = """
import { Account } from "@aptos-labs/ts-sdk";
const a = Account.generate();
console.log(JSON.stringify({
  address: String(a.accountAddress),
  publicKey: a.publicKey.toString(),
  privateKey: a.privateKey.toString(),
}));
""".strip()
    proc = run_cmd(["node", "--input-type=module", "-e", script], cwd=TS_DIR, env=os.environ.copy())
    account = json.loads(proc.stdout)
    fund_account(account["address"])
    return account


def gen_decryption_key() -> str:
    return "0x" + secrets.token_hex(32)


# ---------------------------------------------------------------------------
# Go v2 CLI + balance check (needs CGO + the confidential-asset-bindings FFI static lib)
# ---------------------------------------------------------------------------


def go_env() -> Dict[str, str]:
    env = os.environ.copy()
    env["GOCACHE"] = str(ROOT / ".cache" / "go-build")
    env["GOMODCACHE"] = str(ROOT / ".cache" / "go-mod")
    env["CGO_ENABLED"] = "1"
    native_dirs = glob.glob(str(GO_V2_DIR / "native" / "*"))
    native_dirs = [d for d in native_dirs if os.path.isfile(os.path.join(d, "libaptos_confidential_asset_ffi.a"))]
    if not native_dirs:
        raise RuntimeError(
            "confidential-asset-bindings FFI static lib not found under "
            f"{GO_V2_DIR / 'native'} -- run `go run "
            "github.com/aptos-labs/confidential-asset-bindings/bindings/go/aptosconfidential/tools/download@v1.1.2` "
            "from implementations/go-v2 first"
        )
    env["CGO_LDFLAGS"] = f"-L{native_dirs[0]}"
    return env


def go_confidential_flags(
    action: str,
    token_address: str,
    *,
    decryption_key: Optional[str] = None,
    amount: Optional[int] = None,
    recipient: Optional[str] = None,
) -> List[str]:
    flags = ["--confidential-action", action, "--confidential-token-address", token_address]
    if decryption_key:
        flags += ["--confidential-decryption-key", decryption_key]
    if amount is not None:
        flags += ["--confidential-amount", str(amount)]
    if recipient:
        flags += ["--confidential-recipient", recipient]
    return flags


def run_go_confidential(account: dict, action: str, token_address: str, **kwargs) -> dict:
    cmd = [
        "go", "run", "./cmd/aptx",
        "run", "confidential-asset",
        "--network", TEST_NETWORK,
        "--fullnode", TEST_FULLNODE,
        "--output-format", "json",
        "--sender-address", account["address"],
        "--private-key", account["privateKey"],
        *go_confidential_flags(action, token_address, **kwargs),
    ]
    payload = load_json_output(run_cmd(cmd, cwd=GO_V2_DIR, env=go_env()).stdout)
    if payload["result"]["success"] is not True:
        raise AssertionError(f"go {action} failed: {payload['result']}")
    return payload


def get_go_balance(account: dict, decryption_key: str, token_address: str) -> dict:
    cmd = ["go", "run", "./scripts/get-confidential-balance", account["address"], decryption_key, token_address, TEST_FULLNODE]
    proc = run_cmd(cmd, cwd=GO_V2_DIR, env=go_env())
    return json.loads(proc.stdout.strip().splitlines()[-1])


# ---------------------------------------------------------------------------
# TypeScript CLI + balance check
# ---------------------------------------------------------------------------


def ts_confidential_flags(
    action: str,
    token_address: str,
    *,
    decryption_key: Optional[str] = None,
    amount: Optional[int] = None,
    recipient: Optional[str] = None,
) -> List[str]:
    flags = ["--confidential-action", action, "--confidential-token-address", token_address]
    if decryption_key:
        flags += ["--confidential-decryption-key", decryption_key]
    if amount is not None:
        flags += ["--confidential-amount", str(amount)]
    if recipient:
        flags += ["--confidential-recipient", recipient]
    return flags


def run_ts_confidential(account: dict, action: str, token_address: str, **kwargs) -> dict:
    cmd = [
        "node", "--experimental-strip-types", "src/cli.ts",
        "run", "confidential-asset",
        "--network", TEST_NETWORK,
        "--fullnode", TEST_FULLNODE,
        "--output-format", "json",
        "--sender-address", account["address"],
        "--private-key", account["privateKey"],
        *ts_confidential_flags(action, token_address, **kwargs),
    ]
    payload = load_json_output(run_cmd(cmd, cwd=TS_DIR, env=os.environ.copy()).stdout)
    if payload["result"]["success"] is not True:
        raise AssertionError(f"ts {action} failed: {payload['result']}")
    return payload


def get_ts_balance(account: dict, decryption_key: str, token_address: str) -> dict:
    script = """
import { Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import { ConfidentialAsset, TwistedEd25519PrivateKey } from "@aptos-labs/confidential-asset";
const [address, dk, tokenAddress, fullnode] = process.argv.slice(1);
const aptos = new Aptos(new AptosConfig({ network: Network.LOCAL, fullnode, clientConfig: { http2: false } }));
const ca = new ConfidentialAsset({ config: aptos.config });
const bal = await ca.getBalance({ accountAddress: address, tokenAddress, decryptionKey: new TwistedEd25519PrivateKey(dk) });
console.log(JSON.stringify({ available: Number(bal.availableBalance()), pending: Number(bal.pendingBalance()) }));
""".strip()
    proc = run_cmd(
        ["node", "--experimental-strip-types", "--input-type=module", "-e", script,
         "--", account["address"], decryption_key, token_address, TEST_FULLNODE],
        cwd=TS_DIR,
        env=os.environ.copy(),
    )
    return json.loads(proc.stdout.strip().splitlines()[-1])


def assert_balance(label: str, actual: dict, expected_available: int, expected_pending: int) -> None:
    if actual["available"] != expected_available or actual["pending"] != expected_pending:
        raise AssertionError(
            f"{label}: got available={actual['available']} pending={actual['pending']}, "
            f"want available={expected_available} pending={expected_pending}"
        )


def cross_check_balance(label: str, account: dict, dk: str, token_address: str, expected_available: int, expected_pending: int) -> None:
    """Decrypt the same on-chain ciphertext with both SDKs independently and confirm they agree."""
    go_balance = get_go_balance(account, dk, token_address)
    ts_balance = get_ts_balance(account, dk, token_address)
    assert_balance(f"{label} (go)", go_balance, expected_available, expected_pending)
    assert_balance(f"{label} (ts)", ts_balance, expected_available, expected_pending)


def main() -> int:
    if os.environ.get("APTX_SKIP_LIVE") == "1":
        print(json.dumps({"status": "skipped", "reason": "APTX_SKIP_LIVE=1"}, indent=2))
        return 0

    alice = provision_account()
    bob = provision_account()
    alice_dk = gen_decryption_key()
    bob_dk = gen_decryption_key()
    token_address = resolve_apt_fa_metadata_address()

    # register: alice via Go, bob via TS.
    run_go_confidential(alice, "register", token_address, decryption_key=alice_dk)
    run_ts_confidential(bob, "register", token_address, decryption_key=bob_dk)

    # deposit/rollover/normalize: alice, via Go.
    run_go_confidential(alice, "deposit", token_address, amount=DEPOSIT_AMOUNT)
    run_go_confidential(alice, "rollover", token_address)
    # Go's Transfer/Withdraw require a normalized balance (a stricter precondition than TS's,
    # which doesn't enforce this) -- see spec/confidential-asset.md for this cross-SDK finding.
    run_go_confidential(alice, "normalize", token_address, decryption_key=alice_dk)
    cross_check_balance("alice after deposit+rollover+normalize", alice, alice_dk, token_address, DEPOSIT_AMOUNT, 0)

    # transfer alice -> bob, via Go. bob's balance is now entirely fed by a Go-built transaction.
    run_go_confidential(
        alice, "transfer", token_address,
        decryption_key=alice_dk, amount=TRANSFER_AMOUNT, recipient=bob["address"],
    )
    cross_check_balance("alice after transfer", alice, alice_dk, token_address, DEPOSIT_AMOUNT - TRANSFER_AMOUNT, 0)
    cross_check_balance("bob after transfer", bob, bob_dk, token_address, 0, TRANSFER_AMOUNT)

    # rollover/normalize/withdraw: bob, via TS -- proving TS can read and spend a ciphertext Go produced.
    run_ts_confidential(bob, "rollover", token_address)
    run_ts_confidential(bob, "normalize", token_address, decryption_key=bob_dk)
    cross_check_balance("bob after rollover+normalize", bob, bob_dk, token_address, TRANSFER_AMOUNT, 0)

    run_ts_confidential(bob, "withdraw", token_address, decryption_key=bob_dk, amount=WITHDRAW_AMOUNT)
    cross_check_balance("bob after withdraw", bob, bob_dk, token_address, TRANSFER_AMOUNT - WITHDRAW_AMOUNT, 0)

    print(json.dumps({
        "status": "ok",
        "tested": ["go-v2-writes-ts-reads", "ts-writes-go-reads", "go-native-getbalance", "ts-getbalance"],
        "tokenAddress": token_address,
        "aliceAddress": alice["address"],
        "bobAddress": bob["address"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
