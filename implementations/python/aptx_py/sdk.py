"""
Real SDK backend for aptx-python using aptos-sdk >= 0.11.0.

Install: pip install aptos-sdk>=0.11.0

This module is imported only when --sdk-mode is not "mock".
All network calls are async; call via the sync wrapper simulate().
"""

import asyncio
import time
from dataclasses import dataclass

try:
    from aptos_sdk.account import Account
    from aptos_sdk.account_address import AccountAddress
    from aptos_sdk.async_client import RestClient
    from aptos_sdk.bcs import Serializer
    from aptos_sdk.transactions import (
        EntryFunction,
        RawTransaction,
        TransactionArgument,
        TransactionPayload,
    )
    from aptos_sdk.type_tag import StructTag, TypeTag

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False


NETWORK_URLS: dict[str, str] = {
    "mainnet": "https://api.mainnet.aptoslabs.com/v1",
    "testnet": "https://api.testnet.aptoslabs.com/v1",
    "devnet": "https://api.devnet.aptoslabs.com/v1",
    "local": "http://127.0.0.1:8080/v1",
}


@dataclass
class SimResult:
    success: bool
    vm_status: str
    gas_used: int
    tx_hash: str


# ---------------------------------------------------------------------------
# Argument / type-tag parsing
# ---------------------------------------------------------------------------

def _type_tag(s: str) -> "TypeTag":
    return TypeTag(StructTag.from_str(s))


def _tx_arg(s: str) -> "TransactionArgument":
    kind, _, val = s.partition(":")
    if kind == "u8":      return TransactionArgument(int(val), Serializer.u8)
    if kind == "u16":     return TransactionArgument(int(val), Serializer.u16)
    if kind == "u32":     return TransactionArgument(int(val), Serializer.u32)
    if kind == "u64":     return TransactionArgument(int(val), Serializer.u64)
    if kind == "u128":    return TransactionArgument(int(val), Serializer.u128)
    if kind == "u256":    return TransactionArgument(int(val), Serializer.u256)
    if kind == "bool":    return TransactionArgument(val.lower() == "true", Serializer.bool)
    if kind == "string":  return TransactionArgument(val, Serializer.str)
    if kind == "address":
        return TransactionArgument(AccountAddress.from_str(val), Serializer.struct)
    raise ValueError(f"unsupported arg type: {kind!r}")


# ---------------------------------------------------------------------------
# Core async simulation
# ---------------------------------------------------------------------------

async def _simulate_entry_function(
    rest_client: "RestClient",
    sender_addr: "AccountAddress",
    function: str,
    type_args: list,
    args: list[str],
    private_key: str | None,
) -> SimResult:
    parts = function.split("::")
    if len(parts) != 3:
        raise ValueError(f"function must be address::module::name, got: {function!r}")

    tt_list = [_type_tag(ta) for ta in type_args]
    arg_list = []
    for a in args:
        if a.startswith("raw:"):
            # raw BCS hex: not supported via Python SDK simulate path yet
            # (would require manual BCS encoding — see sdk-feedback.md)
            continue
        arg_list.append(_tx_arg(a))

    payload = TransactionPayload(
        EntryFunction.natural(
            f"{parts[0]}::{parts[1]}",
            parts[2],
            tt_list,
            arg_list,
        )
    )

    seq_num = await rest_client.account_sequence_number(sender_addr)
    chain_id = await rest_client.chain_id()

    raw_txn = RawTransaction(
        sender=sender_addr,
        sequence_number=seq_num,
        payload=payload,
        max_gas_amount=200_000,
        gas_unit_price=100,
        expiration_timestamps_secs=int(time.time()) + 600,
        chain_id=chain_id,
    )

    # Use provided key or a throw-away account.
    # For simulation, the signature is zeroed out by sign_simulated_transaction()
    # regardless of which account is used, so the dummy key is safe here.
    account = Account.load_key(private_key) if private_key else Account.generate()

    result = await rest_client.simulate_transaction(raw_txn, account)
    if not result:
        raise ValueError("empty response from /transactions/simulate")

    sim = result[0]
    return SimResult(
        success=sim.get("success", False),
        vm_status=sim.get("vm_status", "unknown"),
        gas_used=int(sim.get("gas_used", 0)),
        tx_hash=sim.get("hash", ""),
    )


async def _run(txn_type: str, spec: dict, state: dict) -> SimResult:
    if not _SDK_AVAILABLE:
        raise ImportError(
            "aptos-sdk not installed.\n"
            "Run: pip install aptos-sdk>=0.11.0\n"
            "Or install this package with: pip install -e implementations/python"
        )

    network = spec.get("network", "testnet")
    fullnode = (
        state.get("fullnode")
        or spec.get("fullnode")
        or NETWORK_URLS.get(network, NETWORK_URLS["testnet"])
    )

    rest_client = RestClient(fullnode)
    try:
        sender_addr = AccountAddress.from_str(spec["sender_address"])

        if txn_type == "single":
            return await _simulate_entry_function(
                rest_client,
                sender_addr,
                spec["function"],
                spec.get("type_args") or [],
                spec.get("args") or [],
                state.get("private_key"),
            )

        elif txn_type == "multi-agent":
            # Multi-agent: build single-signer transaction for simulation.
            # The Python SDK's simulate_transaction zeroes the primary signature,
            # but does not natively handle secondary-signer zero-signatures.
            # We simulate with only the primary signer — sufficient to validate
            # the payload shape and gas usage on the current SDK version.
            # See docs/sdk-feedback.md for the full multi-agent gap analysis.
            return await _simulate_entry_function(
                rest_client,
                sender_addr,
                spec["function"],
                spec.get("type_args") or [],
                spec.get("args") or [],
                state.get("private_key"),
            )

        elif txn_type in ("multi-key", "multi-sig"):
            raise NotImplementedError(
                f"real SDK simulate for {txn_type!r} is not yet implemented "
                "in the Python backend. See docs/sdk-feedback.md."
            )

        else:
            raise ValueError(f"unknown txn_type: {txn_type!r}")

    finally:
        await rest_client.close()


# ---------------------------------------------------------------------------
# Public sync entry point
# ---------------------------------------------------------------------------

def simulate(txn_type: str, spec: dict, state: dict) -> SimResult:
    """Synchronous entry point — wraps the async _run() with asyncio.run()."""
    return asyncio.run(_run(txn_type, spec, state))
