"""
Real SDK backend for aptx-python-v2 using aptos-sdk-v2.

Install: pip install aptos-sdk-v2

This module is imported only when --sdk-mode is not "mock".
All network calls are async; call via the sync wrapper simulate().
"""

import asyncio
import time
from dataclasses import dataclass

try:
    from aptos_sdk_v2.aptos import Aptos
    from aptos_sdk_v2.config import AptosConfig, Network, NETWORK_URLS
    from aptos_sdk_v2.types.account_address import AccountAddress
    from aptos_sdk_v2.transactions.raw_transaction import RawTransaction
    from aptos_sdk_v2.transactions.payload import (
        EntryFunction,
        TransactionPayload,
        TransactionArgument,
    )
    from aptos_sdk_v2.bcs import Serializer
    from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey

    _SDK_AVAILABLE = True
except ImportError:
    _SDK_AVAILABLE = False

_NETWORK_MAP: dict[str, "Network"] = {}
if _SDK_AVAILABLE:
    _NETWORK_MAP = {
        "mainnet": Network.MAINNET,
        "testnet": Network.TESTNET,
        "devnet": Network.DEVNET,
        "local": Network.LOCAL,
        "localnet": Network.LOCAL,
    }


@dataclass
class SimResult:
    success: bool
    vm_status: str
    gas_used: int
    tx_hash: str


def _type_tag(s: str):
    from aptos_sdk_v2.types.type_tag import TypeTag, StructTag
    return TypeTag(StructTag.from_str(s))


def _tx_arg(s: str) -> "TransactionArgument":
    kind, _, val = s.partition(":")
    if kind == "u8":
        return TransactionArgument(int(val), Serializer.u8)
    if kind == "u16":
        return TransactionArgument(int(val), Serializer.u16)
    if kind == "u32":
        return TransactionArgument(int(val), Serializer.u32)
    if kind == "u64":
        return TransactionArgument(int(val), Serializer.u64)
    if kind == "u128":
        return TransactionArgument(int(val), Serializer.u128)
    if kind == "bool":
        return TransactionArgument(val.lower() == "true", Serializer.bool)
    if kind == "string":
        return TransactionArgument(val, Serializer.str)
    if kind == "address":
        addr = AccountAddress.from_str_relaxed(val)
        return TransactionArgument(addr, lambda ser, v: v.serialize(ser))
    raise ValueError(f"unsupported arg type: {kind!r}")


async def _simulate_entry_function(
    aptos: "Aptos",
    sender_addr: "AccountAddress",
    function: str,
    type_args: list,
    args: list[str],
    private_key_hex: str | None,
) -> SimResult:
    parts = function.split("::")
    if len(parts) != 3:
        raise ValueError(f"function must be address::module::name, got: {function!r}")

    tt_list = [_type_tag(ta) for ta in type_args]
    arg_list = []
    for a in args:
        if a.startswith("raw:"):
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

    seq_num = await aptos.account.get_sequence_number(sender_addr)
    chain_id = await aptos.general.get_chain_id()

    raw_txn = RawTransaction(
        sender=sender_addr,
        sequence_number=seq_num,
        payload=payload,
        max_gas_amount=200_000,
        gas_unit_price=100,
        expiration_timestamps_secs=int(time.time()) + 600,
        chain_id=chain_id,
    )

    if private_key_hex:
        key_hex = private_key_hex
        for prefix in ("ed25519-priv-", "0x"):
            key_hex = key_hex.replace(prefix, "", 1)
        priv_key = Ed25519PrivateKey.from_str(key_hex)
        pub_key = priv_key.public_key()
    else:
        # Generate a temporary key for simulation
        from aptos_sdk_v2.crypto.ed25519 import Ed25519PrivateKey as _K
        import secrets
        _tmp = _K.from_str(secrets.token_hex(32))
        pub_key = _tmp.public_key()

    results = await aptos.transaction.simulate(raw_txn, pub_key)
    if not results:
        raise ValueError("empty response from /transactions/simulate")

    sim = results[0]
    return SimResult(
        success=sim.get("success", False),
        vm_status=sim.get("vm_status", "unknown"),
        gas_used=int(sim.get("gas_used", 0)),
        tx_hash=sim.get("hash", ""),
    )


async def _run(txn_type: str, spec: dict, state: dict) -> SimResult:
    if not _SDK_AVAILABLE:
        raise ImportError(
            "aptos-sdk-v2 not installed.\n"
            "Run: pip install git+https://github.com/aptos-labs/aptos-python-sdk.git@main#subdirectory=v2\n"
            "Or install this package with: pip install -e implementations/python-v2"
        )

    network_name = spec.get("network", "testnet").lower()
    fullnode = (
        state.get("fullnode")
        or spec.get("fullnode")
        or None
    )

    net = _NETWORK_MAP.get(network_name, Network.TESTNET)
    config = AptosConfig(network=net, fullnode_url=fullnode or None)

    async with Aptos(config) as aptos:
        sender_addr = AccountAddress.from_str_relaxed(spec["sender_address"])

        if txn_type in ("single", "multi-agent"):
            return await _simulate_entry_function(
                aptos,
                sender_addr,
                spec["function"],
                spec.get("type_args") or [],
                spec.get("args") or [],
                state.get("private_key"),
            )

        raise NotImplementedError(
            f"real SDK simulate for {txn_type!r} is not yet implemented "
            "in the Python v2 backend."
        )


def simulate(txn_type: str, spec: dict, state: dict) -> SimResult:
    """Synchronous entry point — wraps the async _run() with asyncio.run()."""
    return asyncio.run(_run(txn_type, spec, state))
