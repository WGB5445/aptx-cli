//! Real SDK backend for aptx-rust using aptos-sdk = "0.5.0".
//!
//! Published by Aptos Labs on crates.io from:
//!   https://github.com/aptos-labs/aptos-rust-sdk
//!
//! This is a standalone repo (not the Aptos monorepo) and compiles in any
//! standard Rust project (requires Rust >= 1.95.0). The only heavy transitive
//! dep is `aws-lc-sys`, which compiles C crypto code on first build (~1-2 min).
//!
//! See docs/sdk-feedback.md for gaps discovered during implementation.

use anyhow::{anyhow, bail, Result};
use aptos_sdk::{
    Aptos, AptosConfig, ChainId,
    aptos_bcs,
    const_hex,
    crypto::Ed25519PrivateKey,
    transaction::{
        TransactionAuthenticator, TransactionBuilder,
        authenticator::AccountAuthenticator,
        input::{InputEntryFunctionData, MoveU256, move_string},
        payload::TransactionPayload,
        types::RawTransaction,
        SignedTransaction,
    },
    types::AccountAddress,
};

/// Result of a simulation call.
pub struct SimResult {
    pub success: bool,
    pub vm_status: String,
    pub gas_used: u64,
    pub tx_hash: String,
}

/// Build an `Aptos` client for the given network / override URL.
fn make_client(network: &str, fullnode_override: Option<&str>) -> Result<Aptos> {
    let config = if let Some(url) = fullnode_override.filter(|s| !s.is_empty()) {
        AptosConfig::custom(url).map_err(|e| anyhow!("invalid fullnode URL: {e}"))?
    } else {
        match network {
            "mainnet" => AptosConfig::mainnet(),
            "devnet"  => AptosConfig::devnet(),
            "local"   => AptosConfig::local(),
            _         => AptosConfig::testnet(),
        }
    };
    Aptos::new(config).map_err(|e| anyhow!("failed to create Aptos client: {e}"))
}

/// Parse an address string to `AccountAddress`.
fn parse_address(addr: &str) -> Result<AccountAddress> {
    AccountAddress::from_hex(addr.trim_start_matches("0x"))
        .map_err(|e| anyhow!("invalid address {addr:?}: {e}"))
}

/// Build a payload from function + type_args + args strings.
///
/// arg format:     `type:value`   e.g. `u64:100`, `address:0x1`, `bool:true`, `string:hello`
/// type_arg format: full struct tag  e.g. `0x1::aptos_coin::AptosCoin`
fn build_payload(
    function: &str,
    type_args: &[String],
    args: &[String],
) -> Result<aptos_sdk::transaction::TransactionPayload> {
    let mut builder = InputEntryFunctionData::new(function);

    for ta in type_args {
        builder = builder.type_arg(ta.as_str());
    }

    for arg in args {
        if arg.starts_with("raw:") {
            bail!("raw:<hex> args are not yet supported in the Rust real SDK path");
        }

        let (kind, val) = arg
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid arg format (expected type:value): {arg:?}"))?;

        builder = match kind {
            "u8"   => builder.arg(val.parse::<u8>()
                .map_err(|_| anyhow!("bad u8 value: {val}"))?),
            "u16"  => builder.arg(val.parse::<u16>()
                .map_err(|_| anyhow!("bad u16 value: {val}"))?),
            "u32"  => builder.arg(val.parse::<u32>()
                .map_err(|_| anyhow!("bad u32 value: {val}"))?),
            "u64"  => builder.arg(val.parse::<u64>()
                .map_err(|_| anyhow!("bad u64 value: {val}"))?),
            "u128" => builder.arg(val.parse::<u128>()
                .map_err(|_| anyhow!("bad u128 value: {val}"))?),
            "u256" => builder.arg(
                MoveU256::parse(val).map_err(|e| anyhow!("bad u256 value {val}: {e}"))?,
            ),
            "bool" => builder.arg(val == "true"),
            "address" => builder.arg(parse_address(val)?),
            "string" => builder.arg(move_string(val)),
            _ => bail!("unsupported arg type: {kind:?}"),
        };
    }

    builder.build().map_err(|e| anyhow!("failed to build payload: {e}"))
}

/// Build a `RawTransaction` using the actual sender address.
async fn build_raw_transaction(
    aptos: &Aptos,
    sender_address: &str,
    function: &str,
    type_args: &[String],
    args: &[String],
) -> Result<RawTransaction> {
    let sender = parse_address(sender_address)?;
    let seq_num = aptos
        .get_sequence_number(sender)
        .await
        .map_err(|e| anyhow!("get_sequence_number failed: {e}"))?;

    let payload = build_payload(function, type_args, args)?;

    TransactionBuilder::new()
        .sender(sender)
        .sequence_number(seq_num)
        .payload(payload)
        .chain_id(aptos.chain_id())
        .max_gas_amount(200_000)
        .gas_unit_price(100)
        .expiration_from_now(600)
        .build()
        .map_err(|e| anyhow!("failed to build raw transaction: {e}"))
}

/// Extract a `SimResult` from the SDK's `SimulationResult`.
fn extract_result(r: aptos_sdk::transaction::SimulationResult) -> SimResult {
    SimResult {
        success: r.success(),
        vm_status: r.vm_status().to_string(),
        gas_used: r.gas_used(),
        tx_hash: r.hash().to_string(),
    }
}

/// Simulate a single entry-function transaction.
///
/// Uses `AccountAuthenticator::NoAccountAuthenticator` — no private key needed.
/// The sender address is the real on-chain address; the SDK zeroes all
/// authenticators before sending to the simulate endpoint.
pub async fn simulate_single(
    network: &str,
    fullnode_override: Option<&str>,
    sender_address: &str,
    function: &str,
    args: &[String],
    type_args: &[String],
) -> Result<SimResult> {
    let aptos = make_client(network, fullnode_override)?;
    let raw_txn =
        build_raw_transaction(&aptos, sender_address, function, type_args, args).await?;

    let auth = TransactionAuthenticator::single_sender(
        AccountAuthenticator::no_account_authenticator(),
    );
    let signed = SignedTransaction::new(raw_txn, auth);

    let result = aptos
        .simulate_signed(&signed)
        .await
        .map_err(|e| anyhow!("simulation failed: {e}"))?;

    Ok(extract_result(result))
}

/// Encode a raw transaction to BCS hex.
///
/// All gas and expiration parameters must be supplied explicitly; this
/// function is deterministic and does not contact a node.
pub fn encode_transaction(
    sender_address: &str,
    function: &str,
    type_args: &[String],
    args: &[String],
    sequence_number: u64,
    chain_id: u8,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp: u64,
) -> Result<String> {
    let sender = parse_address(sender_address)?;
    let payload = build_payload(function, type_args, args)?;
    let raw_txn = RawTransaction::new(
        sender,
        sequence_number,
        payload,
        max_gas_amount,
        gas_unit_price,
        expiration_timestamp,
        ChainId::new(chain_id),
    );
    let bytes = raw_txn.to_bcs().map_err(|e| anyhow!("BCS encode failed: {e}"))?;
    Ok(format!("0x{}", const_hex::encode(&bytes)))
}

/// Decode a BCS-encoded raw transaction back to a JSON summary.
pub fn decode_transaction(bcs_hex: &str) -> Result<serde_json::Value> {
    let hex_str = bcs_hex.trim_start_matches("0x");
    let bytes = const_hex::decode(hex_str).map_err(|e| anyhow!("invalid hex: {e}"))?;
    let raw_txn: RawTransaction =
        aptos_bcs::from_bytes(&bytes).map_err(|e| anyhow!("BCS decode failed: {e}"))?;

    let is_orderless = raw_txn.sequence_number == u64::MAX;
    let seq_str = if is_orderless {
        "max_u64".to_string()
    } else {
        raw_txn.sequence_number.to_string()
    };

    let fn_str = match &raw_txn.payload {
        TransactionPayload::EntryFunction(ef) => {
            format!("{}::{}", ef.module, ef.function)
        }
        TransactionPayload::Multisig(ms) => {
            format!("multisig:{}", ms.multisig_address.to_hex())  // to_hex includes 0x prefix
        }
        TransactionPayload::Script(_) => "script".to_string(),
        _ => "unknown".to_string(),
    };

    Ok(serde_json::json!({
        "action": "decode",
        "txn_type": if is_orderless { "orderless" } else { "single" },
        "sender": raw_txn.sender.to_hex(),
        "function": fn_str,
        "chain_id": raw_txn.chain_id.id(),
        "sequence_number": seq_str,
        "max_gas_amount": raw_txn.max_gas_amount,
        "gas_unit_price": raw_txn.gas_unit_price,
        "expiration_timestamp": raw_txn.expiration_timestamp_secs,
        "is_orderless": is_orderless,
    }))
}

/// Sign a BCS-encoded raw transaction with an Ed25519 private key.
///
/// The private key may be supplied as:
///   - raw hex (32 bytes, with or without "0x" prefix)
///   - AIP-80 format: `ed25519-priv-0x{hex}`
pub fn sign_transaction(bcs_hex: &str, private_key_hex: &str) -> Result<serde_json::Value> {
    let hex_str = bcs_hex.trim_start_matches("0x");
    let bytes = const_hex::decode(hex_str).map_err(|e| anyhow!("invalid bcs hex: {e}"))?;
    let raw_txn: RawTransaction =
        aptos_bcs::from_bytes(&bytes).map_err(|e| anyhow!("BCS decode failed: {e}"))?;

    let private_key = if private_key_hex.starts_with("ed25519-priv-") {
        Ed25519PrivateKey::from_aip80(private_key_hex)
            .map_err(|e| anyhow!("invalid AIP-80 private key: {e}"))?
    } else {
        let key_hex = private_key_hex.trim_start_matches("0x");
        let key_bytes =
            const_hex::decode(key_hex).map_err(|e| anyhow!("invalid private key hex: {e}"))?;
        Ed25519PrivateKey::from_bytes(&key_bytes)
            .map_err(|e| anyhow!("invalid private key bytes: {e}"))?
    };

    let signing_message = raw_txn
        .signing_message()
        .map_err(|e| anyhow!("signing_message failed: {e}"))?;
    let signature = private_key.sign(&signing_message);
    let public_key = private_key.public_key();

    let is_orderless = raw_txn.sequence_number == u64::MAX;

    Ok(serde_json::json!({
        "action": "sign",
        "txn_type": if is_orderless { "orderless" } else { "single" },
        "public_key": public_key.to_hex(),
        "signature": signature.to_hex(),
    }))
}

/// Simulate a multi-agent entry-function transaction.
///
/// Builds a `TransactionAuthenticator::MultiAgent` with
/// `NoAccountAuthenticator` for the primary sender and all secondary signers,
/// then calls `simulate_signed`. No private keys are required.
pub async fn simulate_multi_agent(
    network: &str,
    fullnode_override: Option<&str>,
    sender_address: &str,
    function: &str,
    args: &[String],
    type_args: &[String],
    secondary_addresses: &[String],
) -> Result<SimResult> {
    let aptos = make_client(network, fullnode_override)?;
    let raw_txn =
        build_raw_transaction(&aptos, sender_address, function, type_args, args).await?;

    let secondary_accounts = secondary_addresses
        .iter()
        .map(|a| parse_address(a))
        .collect::<Result<Vec<_>>>()?;

    let secondary_no_auths: Vec<AccountAuthenticator> = secondary_accounts
        .iter()
        .map(|_| AccountAuthenticator::no_account_authenticator())
        .collect();

    let auth = TransactionAuthenticator::multi_agent(
        AccountAuthenticator::no_account_authenticator(),
        secondary_accounts,
        secondary_no_auths,
    );
    let signed = SignedTransaction::new(raw_txn, auth);

    let result = aptos
        .simulate_signed(&signed)
        .await
        .map_err(|e| anyhow!("multi-agent simulation failed: {e}"))?;

    Ok(extract_result(result))
}
