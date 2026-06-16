# Canonical CLI Spec

This is the authoritative contract that all language implementations must conform to. Changes here must be reflected in every active implementation and in the conformance test cases.

## Command shape

```
aptx simulate <txn-type>   # build and simulate; no signing required
aptx submit  <txn-type>    # build, sign, and submit to network
aptx run     <txn-type>    # simulate + submit in one step
aptx inspect               # decode and display an existing transaction
```

## Transaction types

| Type | Description |
|---|---|
| `single` | Standard single-signer transaction |
| `multi-agent` | Transaction with multiple authorized signers |
| `multi-key` | M-of-N multisignature using MultiKey account |
| `multi-sig` | On-chain multisig account transaction |

## Flags

All implementations must accept these flags:

**Input / output**

| Flag | Description |
|---|---|
| `--input FILE` | Load transaction parameters from JSON or YAML file |
| `--input-format json\|yaml` | Override input format detection |
| `--output FILE` | Write result to file (default: stdout) |
| `--output-format json\|yaml\|table` | Output format (default: json when writing to file, table to stdout) |
| `--artifacts-dir DIR` | Save transaction artifacts to this directory |

**Network and function**

| Flag | Description |
|---|---|
| `--network NAME` | Target network (mainnet, testnet, devnet, local) |
| `--function ADDRESS::MODULE::NAME` | Move entry function to call |
| `--arg TYPE:VALUE` | Transaction argument in parsed form (repeatable) |
| `--type-arg TYPE` | Move type argument (repeatable) |

**Signer identity**

| Flag | Description |
|---|---|
| `--sender-address ADDRESS` | Sender account address |
| `--private-key HEX` | Private key (inline) |
| `--private-key-env VAR` | Read private key from environment variable |
| `--private-key-file FILE` | Read private key from file |
| `--profile NAME` | Load key and address from Aptos CLI profile |
| `--no-sign` | Skip signing (for dry-run or address-only simulation) |

**Behavior**

| Flag | Description |
|---|---|
| `--no-abi` | Disable ABI resolution |
| `--verbose` | Verbose output |
| `--quiet` | Suppress informational output |
| `--sdk-mode mock\|real` | Force mock (for conformance) or real SDK mode |

**Multi-sig flags**

| Flag | Description |
|---|---|
| `--multisig-action create-account\|propose\|approve\|execute` | On-chain multisig action |
| `--multisig-address ADDRESS` | On-chain multisig account address |
| `--multisig-owner-address ADDRESS` | Owner addresses for `create-account` (repeatable) |
| `--multisig-threshold N` | Approval threshold |
| `--multisig-sequence N` | Sequence number for `approve` |
| `--multisig-hash-only` | Include only the payload hash, not the full payload |

**Multi-key flags**

| Flag | Description |
|---|---|
| `--multi-key-public-key HEX` | Public keys in the N-key set (repeatable) |
| `--multi-key-signer INDEX:KEY` | Signer specification: index and private key (repeatable) |
| `--multi-key-threshold N` | Number of required signatures (M in M-of-N) |

## Argument format

- Parsed: `<type>:<value>` — e.g. `address:0x1`, `u64:1000`, `bool:true`
- Raw serialized: `raw:<hex>` — requires ABI mode to be enabled

## Behavioral rules

- `raw:<hex>` requires `--no-abi` to be absent (ABI mode must be on)
- `submit` requires signer material unless `--sdk-mode mock --no-sign` is used
- Output defaults to JSON when `--output FILE` is used, table when writing to stdout
- All implementations emit the same JSON shape; see [`output-schema.json`](output-schema.json) for the formal definition
- `multi-sig propose` and `execute` support entry-function payloads; script payloads are not currently supported

## Output schema

The normalized conformance projection that all implementations must produce is defined in [`spec/output-schema.json`](output-schema.json). The conformance runner (`conformance/run.py`) extracts this projection from each implementation's full JSON output and compares them.

## SDK targets

| Implementation | SDK |
|---|---|
| TypeScript | `@aptos-labs/ts-sdk` |
| Python | `aptos-python-sdk` |
| Go | `github.com/aptos-labs/aptos-go-sdk` |
| Rust | `aptos-rust-sdk` |
