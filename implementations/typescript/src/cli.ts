import fs from "node:fs";
import { sha3_256 } from "@noble/hashes/sha3";
import {
  Account,
  AccountAddress,
  Aptos,
  AptosConfig,
  Bool,
  Ed25519PrivateKey,
  Ed25519PublicKey,
  EntryFunction,
  FixedBytes,
  MultiKey,
  MultiKeyAccount,
  MultiAgentTransaction,
  MoveString,
  MoveVector,
  MultiSig,
  MultiSigTransactionPayload,
  Network,
  type PublicKey,
  Script,
  Serialized,
  SimpleTransaction,
  TransactionPayloadEntryFunction,
  TransactionPayloadMultiSig,
  TransactionPayloadScript,
  U128,
  U64,
  U8,
  buildTransaction,
  isUserTransactionResponse,
  parseTypeTag,
  RawTransaction,
  ChainId,
  Deserializer,
} from "@aptos-labs/ts-sdk";
import type { EntryFunctionArgument } from "@aptos-labs/ts-sdk";
import { ConfidentialAssetTransactionBuilder, TwistedEd25519PrivateKey } from "@aptos-labs/confidential-asset";

type Action = "simulate" | "submit" | "run" | "inspect" | "encode" | "decode" | "sign";
type TxnType = "single" | "multi-agent" | "multi-key" | "multi-sig" | "confidential-asset";
type OutputFormat = "json" | "yaml" | "table" | "ascii";
type MultisigAction = "create-account" | "propose" | "approve" | "execute";
type ConfidentialAssetAction = "register" | "deposit" | "withdraw" | "transfer" | "rollover" | "normalize" | "rotate";

type ParsedArg = { mode: "parsed"; raw: string; argType: string; value: string };
type RawArg = { mode: "raw"; raw: string; hex: string };
type ArgSpec = ParsedArg | RawArg;
type MultiKeySignerSpec = { index: number; privateKey: string; raw: string };

type InputSpec = {
  network: string;
  function: string;
  script_hex?: string;
  sender_address: string;
  args: string[];
  type_args: string[];
  secondary_signer_addresses: string[];
  abi_enabled: boolean;
  no_sign: boolean;
  hash?: string;
  fullnode?: string;
  multisig_action?: MultisigAction;
  multisig_address?: string;
  multisig_owner_addresses: string[];
  multisig_threshold?: number;
  multisig_sequence?: number;
  multisig_hash_only: boolean;
  multi_key_public_keys: string[];
  multi_key_signers: string[];
  multi_key_threshold?: number;
  confidential_action?: ConfidentialAssetAction;
  confidential_token_address?: string;
  confidential_decryption_key?: string;
  confidential_new_decryption_key?: string;
  confidential_amount?: string;
  confidential_recipient?: string;
  confidential_with_pause_incoming: boolean;
  confidential_memo?: string;
};

type CliState = {
  action: Action;
  txnType: TxnType;
  input?: string;
  inputFormat?: string;
  output?: string;
  outputFormat?: string;
  artifactsDir?: string;
  network?: string;
  fn?: string;
  scriptHex?: string;
  args: string[];
  typeArgs: string[];
  secondarySignerAddresses: string[];
  secondaryPrivateKeys: string[];
  secondaryPublicKeys: string[];
  senderAddress?: string;
  privateKey?: string;
  privateKeyEnv?: string;
  privateKeyFile?: string;
  publicKey?: string;
  publicKeyEnv?: string;
  publicKeyFile?: string;
  profile?: string;
  hash?: string;
  fullnode?: string;
  multisigAction?: MultisigAction;
  multisigAddress?: string;
  multisigOwnerAddresses: string[];
  multisigThreshold?: number;
  multisigSequence?: number;
  multisigHashOnly: boolean;
  multiKeyPublicKeys: string[];
  multiKeySigners: string[];
  multiKeyThreshold?: number;
  confidentialAction?: ConfidentialAssetAction;
  confidentialTokenAddress?: string;
  confidentialDecryptionKey?: string;
  confidentialNewDecryptionKey?: string;
  confidentialAmount?: string;
  confidentialRecipient?: string;
  confidentialWithPauseIncoming: boolean;
  confidentialMemo?: string;
  noSign: boolean;
  abiEnabled: boolean;
  verbose: boolean;
  quiet: boolean;
  sdkMode: "mock" | "sdk";
  sequenceNumber?: number;
  chainId?: number;
  maxGasAmount?: number;
  gasUnitPrice?: number;
  expirationTimestamp?: number;
  nonce?: string;
  inputBcs?: string;
  feePayerAddress?: string;
};

type AbiSummary = {
  fetched: boolean;
  module?: string;
  function?: string;
  parameter_count?: number;
  type_parameter_count?: number;
};

function fail(message: string): never {
  console.error(message);
  process.exit(2);
}

const USAGE = `usage: aptx <simulate|submit|run|inspect|encode|decode|sign> <txn-type> [flags]

txn-types: single, multi-agent, multi-key, multi-sig, confidential-asset

confidential-asset flags (see spec/confidential-asset.md for the full contract):
  --confidential-action <register|deposit|withdraw|transfer|rollover|normalize|rotate>
  --confidential-token-address <address>
  --confidential-decryption-key <hex>          (register, withdraw, transfer, normalize, rotate)
  --confidential-new-decryption-key <hex>      (rotate)
  --confidential-amount <u64>                  (deposit, withdraw, transfer)
  --confidential-recipient <address>           (transfer required; withdraw optional)
  --confidential-with-pause-incoming           (rollover; required before rotate)
  --confidential-memo <hex>                    (transfer, optional)

example: aptx run confidential-asset --network local --sender-address 0x.. --private-key 0x.. \\
  --confidential-action deposit --confidential-token-address 0xa --confidential-amount 1000`;

function printUsage(): never {
  console.error(USAGE);
  process.exit(2);
}

function parseArgList(argv: string[]): CliState {
  if (argv[0] === "--") {
    argv = argv.slice(1);
  }
  if (argv.length < 1) {
    printUsage();
  }
  const action = argv[0] as Action;
  const txnType = (action === "inspect" || action === "decode" || action === "sign" ? "single" : argv[1]) as TxnType;
  const start = (action === "inspect" || action === "decode" || action === "sign") ? 1 : 2;
  const state: CliState = {
    action,
    txnType,
    args: [],
    typeArgs: [],
    secondarySignerAddresses: [],
    secondaryPrivateKeys: [],
    secondaryPublicKeys: [],
    multisigOwnerAddresses: [],
    multisigHashOnly: false,
    multiKeyPublicKeys: [],
    multiKeySigners: [],
    confidentialWithPauseIncoming: false,
    noSign: false,
    abiEnabled: true,
    verbose: false,
    quiet: false,
    sdkMode: "sdk",
  };

  for (let i = start; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--input":
        state.input = next;
        i += 1;
        break;
      case "--input-format":
        state.inputFormat = next;
        i += 1;
        break;
      case "--output":
        state.output = next;
        i += 1;
        break;
      case "--output-format":
        state.outputFormat = next;
        i += 1;
        break;
      case "--artifacts-dir":
        state.artifactsDir = next;
        i += 1;
        break;
      case "--network":
        state.network = next;
        i += 1;
        break;
      case "--function":
        state.fn = next;
        i += 1;
        break;
      case "--script-hex":
        state.scriptHex = next;
        i += 1;
        break;
      case "--arg":
        state.args.push(next);
        i += 1;
        break;
      case "--type-arg":
        state.typeArgs.push(next);
        i += 1;
        break;
      case "--secondary-signer-address":
        state.secondarySignerAddresses.push(...splitMultiValue(next));
        i += 1;
        break;
      case "--secondary-private-key":
        state.secondaryPrivateKeys.push(next);
        i += 1;
        break;
      case "--secondary-public-key":
        state.secondaryPublicKeys.push(next);
        i += 1;
        break;
      case "--sender-address":
        state.senderAddress = next;
        i += 1;
        break;
      case "--private-key":
        state.privateKey = next;
        i += 1;
        break;
      case "--private-key-env":
        state.privateKeyEnv = next;
        i += 1;
        break;
      case "--private-key-file":
        state.privateKeyFile = next;
        i += 1;
        break;
      case "--public-key":
        state.publicKey = next;
        i += 1;
        break;
      case "--public-key-env":
        state.publicKeyEnv = next;
        i += 1;
        break;
      case "--public-key-file":
        state.publicKeyFile = next;
        i += 1;
        break;
      case "--profile":
        state.profile = next;
        i += 1;
        break;
      case "--hash":
        state.hash = next;
        i += 1;
        break;
      case "--fullnode":
        state.fullnode = next;
        i += 1;
        break;
      case "--multisig-action":
        state.multisigAction = next as MultisigAction;
        i += 1;
        break;
      case "--multisig-address":
        state.multisigAddress = next;
        i += 1;
        break;
      case "--multisig-owner-address":
        state.multisigOwnerAddresses.push(...splitMultiValue(next));
        i += 1;
        break;
      case "--multisig-threshold":
        state.multisigThreshold = Number(next);
        i += 1;
        break;
      case "--multisig-sequence":
        state.multisigSequence = Number(next);
        i += 1;
        break;
      case "--multisig-hash-only":
        state.multisigHashOnly = true;
        break;
      case "--multi-key-public-key":
        state.multiKeyPublicKeys.push(...splitMultiValue(next));
        i += 1;
        break;
      case "--multi-key-signer":
        state.multiKeySigners.push(next);
        i += 1;
        break;
      case "--multi-key-threshold":
        state.multiKeyThreshold = Number(next);
        i += 1;
        break;
      case "--confidential-action":
        state.confidentialAction = next as ConfidentialAssetAction;
        i += 1;
        break;
      case "--confidential-token-address":
        state.confidentialTokenAddress = next;
        i += 1;
        break;
      case "--confidential-decryption-key":
        state.confidentialDecryptionKey = next;
        i += 1;
        break;
      case "--confidential-new-decryption-key":
        state.confidentialNewDecryptionKey = next;
        i += 1;
        break;
      case "--confidential-amount":
        state.confidentialAmount = next;
        i += 1;
        break;
      case "--confidential-recipient":
        state.confidentialRecipient = next;
        i += 1;
        break;
      case "--confidential-with-pause-incoming":
        state.confidentialWithPauseIncoming = true;
        break;
      case "--confidential-memo":
        state.confidentialMemo = next;
        i += 1;
        break;
      case "--sdk-mode":
        state.sdkMode = (next as "mock" | "sdk") || "sdk";
        i += 1;
        break;
      case "--sequence-number":
        state.sequenceNumber = Number(next);
        i += 1;
        break;
      case "--chain-id":
        state.chainId = Number(next);
        i += 1;
        break;
      case "--max-gas-amount":
        state.maxGasAmount = Number(next);
        i += 1;
        break;
      case "--gas-unit-price":
        state.gasUnitPrice = Number(next);
        i += 1;
        break;
      case "--expiration-timestamp":
        state.expirationTimestamp = Number(next);
        i += 1;
        break;
      case "--nonce":
        state.nonce = next;
        i += 1;
        break;
      case "--input-bcs":
        state.inputBcs = next;
        i += 1;
        break;
      case "--fee-payer-address":
        state.feePayerAddress = next;
        i += 1;
        break;
      case "--no-sign":
        state.noSign = true;
        break;
      case "--no-abi":
        state.abiEnabled = false;
        break;
      case "--verbose":
        state.verbose = true;
        break;
      case "--quiet":
        state.quiet = true;
        break;
      case "--help":
        printUsage();
      default:
        fail(`unknown argument: ${arg}`);
    }
  }
  return state;
}

function parseScalar(value: string): unknown {
  const trimmed = value.trim();
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (/^-?\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed;
}

function splitMultiValue(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseSimpleYaml(text: string): Record<string, unknown> {
  const obj: Record<string, unknown> = {};
  let currentListKey: string | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, "  ");
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("- ")) {
      if (!currentListKey) fail("invalid yaml list item without key");
      const list = obj[currentListKey] as unknown[];
      list.push(parseScalar(trimmed.slice(2)));
      continue;
    }
    const idx = trimmed.indexOf(":");
    if (idx === -1) fail("invalid yaml line");
    const key = trimmed.slice(0, idx).trim();
    const rest = trimmed.slice(idx + 1).trim();
    if (!rest) {
      obj[key] = [];
      currentListKey = key;
    } else {
      obj[key] = parseScalar(rest);
      currentListKey = null;
    }
  }
  return obj;
}

function detectFormat(path: string | undefined, explicit: string | undefined, fallback: string): string {
  if (explicit && explicit !== "auto") return explicit;
  if (!path || path === "-") return fallback;
  if (path.endsWith(".yaml") || path.endsWith(".yml")) return "yaml";
  return "json";
}

function loadInput(path: string | undefined, format: string): Partial<InputSpec> {
  if (!path) return {};
  const text = path === "-" ? fs.readFileSync(0, "utf8") : fs.readFileSync(path, "utf8");
  if (format === "yaml") return parseSimpleYaml(text) as Partial<InputSpec>;
  return JSON.parse(text) as Partial<InputSpec>;
}

function parseArg(raw: string): ArgSpec {
  if (raw.startsWith("raw:")) {
    return { mode: "raw", raw, hex: raw.slice(4) };
  }
  const idx = raw.indexOf(":");
  if (idx === -1) fail(`invalid --arg syntax: ${raw}`);
  return { mode: "parsed", raw, argType: raw.slice(0, idx), value: raw.slice(idx + 1) };
}

function signingMode(state: CliState): string {
  if (state.noSign) return "none";
  if (state.multiKeySigners.length > 0) return "multi_key";
  if (state.privateKey) return "private_key";
  if (state.privateKeyEnv) return "private_key_env";
  if (state.privateKeyFile) return "private_key_file";
  if (state.profile) return "profile";
  return "none";
}

function requireValidState(state: CliState, spec: InputSpec): void {
  if (state.action === "encode" || state.action === "decode" || state.action === "sign") {
    return;
  }
  if (state.action === "inspect") {
    return;
  }
  if (state.txnType === "multi-sig") {
    if (!spec.multisig_action) fail("multi-sig requires --multisig-action");
    if (spec.script_hex) fail("multi-sig currently supports entry-function payloads only");
    switch (spec.multisig_action) {
      case "create-account":
        if (spec.multisig_owner_addresses.length === 0) {
          fail("multi-sig create-account requires at least one --multisig-owner-address");
        }
        if (!spec.multisig_threshold || spec.multisig_threshold < 1) {
          fail("multi-sig create-account requires --multisig-threshold >= 1");
        }
        if (spec.function || spec.args.length > 0 || spec.type_args.length > 0) {
          fail("multi-sig create-account does not accept --function, --arg, or --type-arg");
        }
        break;
      case "propose":
        if (!spec.multisig_address) fail("multi-sig propose requires --multisig-address");
        if (!spec.function) fail("multi-sig propose requires --function");
        break;
      case "approve":
        if (!spec.multisig_address) fail("multi-sig approve requires --multisig-address");
        if (!Number.isInteger(spec.multisig_sequence)) fail("multi-sig approve requires --multisig-sequence");
        if (spec.function || spec.args.length > 0 || spec.type_args.length > 0) {
          fail("multi-sig approve does not accept --function, --arg, or --type-arg");
        }
        break;
      case "execute":
        if (!spec.multisig_address) fail("multi-sig execute requires --multisig-address");
        if (!spec.function && (spec.args.length > 0 || spec.type_args.length > 0)) {
          fail("multi-sig execute requires --function when --arg or --type-arg is provided");
        }
        break;
    }
  } else if (state.txnType === "multi-key") {
    if (!spec.multi_key_threshold || spec.multi_key_threshold < 1) {
      fail("multi-key requires --multi-key-threshold >= 1");
    }
    if (spec.multi_key_public_keys.length === 0) {
      fail("multi-key requires at least one --multi-key-public-key");
    }
    if (spec.multi_key_threshold > spec.multi_key_public_keys.length) {
      fail("multi-key threshold cannot exceed public key count");
    }
    if ((state.action === "submit" || (state.action === "run" && !spec.no_sign)) && spec.multi_key_signers.length !== spec.multi_key_threshold) {
      fail("multi-key submit requires exactly threshold many --multi-key-signer values");
    }
  } else if (state.txnType === "confidential-asset") {
    if (spec.function || spec.script_hex || spec.args.length > 0 || spec.type_args.length > 0) {
      fail("confidential-asset does not accept --function, --script-hex, --arg, or --type-arg");
    }
    if (!spec.confidential_action) fail("confidential-asset requires --confidential-action");
    if (
      spec.confidential_action !== "register" &&
      spec.confidential_action !== "deposit" &&
      spec.confidential_action !== "withdraw" &&
      spec.confidential_action !== "transfer" &&
      spec.confidential_action !== "rollover" &&
      spec.confidential_action !== "normalize" &&
      spec.confidential_action !== "rotate"
    ) {
      fail(`unsupported confidential-asset action: ${spec.confidential_action}`);
    }
    if (!spec.confidential_token_address) fail("confidential-asset requires --confidential-token-address");
    if (
      (spec.confidential_action === "register" ||
        spec.confidential_action === "withdraw" ||
        spec.confidential_action === "transfer" ||
        spec.confidential_action === "normalize" ||
        spec.confidential_action === "rotate") &&
      !spec.confidential_decryption_key
    ) {
      fail(`confidential-asset ${spec.confidential_action} requires --confidential-decryption-key`);
    }
    if (spec.confidential_action === "rotate" && !spec.confidential_new_decryption_key) {
      fail("confidential-asset rotate requires --confidential-new-decryption-key");
    }
    if (
      (spec.confidential_action === "deposit" ||
        spec.confidential_action === "withdraw" ||
        spec.confidential_action === "transfer") &&
      !spec.confidential_amount
    ) {
      fail(`confidential-asset ${spec.confidential_action} requires --confidential-amount`);
    }
    if (spec.confidential_action === "transfer" && !spec.confidential_recipient) {
      fail("confidential-asset transfer requires --confidential-recipient");
    }
  } else {
    if (!spec.function && !spec.script_hex) fail("missing function or --script-hex");
  }
  if (
    state.txnType !== "single" &&
    state.txnType !== "multi-agent" &&
    state.txnType !== "multi-sig" &&
    state.txnType !== "multi-key" &&
    state.txnType !== "confidential-asset"
  ) {
    fail(`${state.txnType} is not implemented yet in the real TypeScript backend`);
  }
  if (state.txnType === "multi-agent" && spec.secondary_signer_addresses.length === 0) {
    fail("multi-agent requires at least one --secondary-signer-address");
  }
  if (
    state.txnType === "multi-agent" &&
    (state.action === "submit" || (state.action === "run" && !spec.no_sign)) &&
    state.secondaryPrivateKeys.length !== spec.secondary_signer_addresses.length
  ) {
    fail("multi-agent submit requires one --secondary-private-key per secondary signer address");
  }
  if (!spec.abi_enabled && !spec.script_hex) {
    for (const arg of spec.args) {
      if (arg.startsWith("raw:")) fail("raw:<hex> requires ABI mode");
    }
  }
  if ((state.action === "submit" || (state.action === "run" && !spec.no_sign)) && signingMode(state) === "none") {
    fail("submit requires signing material");
  }
}

function buildStableSeed(action: string, txnType: string, spec: InputSpec, signMode: string): string {
  return [
    action,
    txnType,
    spec.network,
    spec.function,
    spec.sender_address,
    spec.args.join(","),
    spec.type_args.join(","),
    spec.multisig_action ?? "",
    spec.multisig_address ?? "",
    spec.multisig_owner_addresses.join(","),
    String(spec.multisig_threshold ?? ""),
    String(spec.multisig_sequence ?? ""),
    String(spec.multisig_hash_only),
    spec.multi_key_public_keys.join(","),
    spec.multi_key_signers.join(","),
    String(spec.multi_key_threshold ?? ""),
    spec.confidential_action ?? "",
    spec.confidential_token_address ?? "",
    spec.confidential_amount ?? "",
    spec.confidential_recipient ?? "",
    String(spec.confidential_with_pause_incoming),
    String(spec.abi_enabled),
    signMode,
  ].join("|");
}

function stableDigest(seed: string): string {
  const mask = (1n << 128n) - 1n;
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(seed, "utf8")) {
    hash ^= BigInt(byte);
    hash = (hash * 0x100000001b3n) & mask;
    hash ^= hash >> 13n;
  }
  return hash.toString(16).padStart(32, "0").slice(0, 32);
}

function safeJson(value: unknown): string {
  return JSON.stringify(
    value,
    (_, item) => {
      if (typeof item === "bigint") return item.toString();
      if (item instanceof Uint8Array) return `0x${Buffer.from(item).toString("hex")}`;
      return item;
    },
    2,
  );
}

function renderYaml(value: unknown, indent = 0): string {
  const pad = " ".repeat(indent);
  if (Array.isArray(value)) {
    return value.map((item) => `${pad}- ${formatYamlScalar(item, indent + 2)}`).join("\n");
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([key, child]) => {
        if (Array.isArray(child) || (child && typeof child === "object")) {
          const rendered = renderYaml(child, indent + 2);
          return `${pad}${key}:\n${rendered}`;
        }
        return `${pad}${key}: ${formatYamlScalar(child, indent + 2)}`;
      })
      .join("\n");
  }
  return `${pad}${formatYamlScalar(value, indent)}`;
}

function formatYamlScalar(value: unknown, indent: number): string {
  if (value && typeof value === "object") return `\n${renderYaml(value, indent)}`;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "bigint") return value.toString();
  if (value === null || value === undefined) return "null";
  return String(value);
}

function renderTable(payload: Record<string, unknown>): string {
  const input = payload.input as Record<string, unknown>;
  const target = input.multisig_action
    ? `multisig:${String(input.multisig_action)}`
    : input.confidential_action
      ? `confidential:${String(input.confidential_action)}`
      : input.function
        ? String(input.function)
        : input.script_hex
          ? `script:${String(input.script_hex).slice(0, 18)}...`
          : "-";
  const rows: Array<[string, string]> = [
    ["implementation", String(payload.implementation)],
    ["sdk_backend", String(payload.sdk_backend)],
    ["action", String(payload.action)],
    ["txn_type", String(payload.txn_type)],
    ["target", target],
    ["sender", String(input.sender_address ?? "-")],
    ["vm_status", String((payload.result as Record<string, unknown>).vm_status ?? "-")],
    ["tx_hash", String((payload.result as Record<string, unknown>).tx_hash ?? "-")],
  ];
  const width = Math.max(...rows.map(([key]) => key.length));
  return rows.map(([key, value]) => `${key.padEnd(width)} | ${value}`).join("\n");
}

function renderAscii(payload: Record<string, unknown>): string {
  const result = payload.result as Record<string, unknown>;
  const input = payload.input as Record<string, unknown>;
  const target = input.multisig_action
    ? `multisig:${String(input.multisig_action)}`
    : input.confidential_action
      ? `confidential:${String(input.confidential_action)}`
      : input.function
        ? String(input.function)
        : input.script_hex
          ? `script:${String(input.script_hex).slice(0, 18)}...`
          : "-";
  const lines = [
    "+----------------------------------------------+",
    "| Aptos Transaction CLI                        |",
    "+----------------------------------------------+",
    `| action        | ${String(payload.action).padEnd(28)}|`,
    `| txn_type      | ${String(payload.txn_type).padEnd(28)}|`,
    `| target        | ${target.padEnd(28)}|`,
    `| sender        | ${String(input.sender_address ?? "-").padEnd(28)}|`,
    `| vm_status     | ${String(result.vm_status ?? "-").padEnd(28)}|`,
    `| tx_hash       | ${String(result.tx_hash ?? "-").padEnd(28)}|`,
    "+----------------------------------------------+",
  ];
  return lines.join("\n");
}

function writeArtifacts(dir: string | undefined, payload: Record<string, unknown>): void {
  if (!dir) return;
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(`${dir}/result.json`, safeJson(payload));
}

function decodeHex(hex: string): Uint8Array {
  const normalized = normalizeKeyHex(hex).replace(/^0x/, "");
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    fail(`invalid hex value: ${hex}`);
  }
  return Uint8Array.from(Buffer.from(normalized, "hex"));
}

function normalizeKeyHex(value: string): string {
  return value.trim().replace(/^ed25519-(priv|pub)-/, "");
}

function normalizeAddressInput(value: string): string {
  const trimmed = value.trim();
  if (!/^0x[0-9a-fA-F]+$/.test(trimmed)) {
    return trimmed;
  }
  const hex = trimmed.slice(2);
  if (hex.length >= 64) {
    return `0x${hex}`;
  }
  return `0x${hex.padStart(64, "0")}`;
}

function parseVectorU8(value: string): Uint8Array {
  const parsed = JSON.parse(value) as unknown;
  if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "number")) {
    fail(`invalid vector<u8> value: ${value}`);
  }
  return Uint8Array.from(parsed as number[]);
}

function parseFunctionId(value: string): { moduleAddress: string; moduleName: string; functionName: string } {
  const parts = value.split("::");
  if (parts.length !== 3) fail(`invalid function id: ${value}`);
  return { moduleAddress: parts[0], moduleName: parts[1], functionName: parts[2] };
}

function parseMultiKeySigner(raw: string): MultiKeySignerSpec {
  const idx = raw.indexOf(":");
  if (idx === -1) fail(`invalid --multi-key-signer syntax: ${raw}`);
  const index = Number(raw.slice(0, idx));
  if (!Number.isInteger(index) || index < 0) fail(`invalid multi-key signer index: ${raw}`);
  return { index, privateKey: raw.slice(idx + 1), raw };
}

function buildMultiKeyPublicKey(spec: InputSpec): MultiKey {
  if (!spec.multi_key_threshold || spec.multi_key_threshold < 1) {
    fail("multi-key requires --multi-key-threshold >= 1");
  }
  if (spec.multi_key_public_keys.length === 0) {
    fail("multi-key requires at least one --multi-key-public-key");
  }
  const publicKeys = spec.multi_key_public_keys.map((value) => new Ed25519PublicKey(normalizeKeyHex(value)));
  return new MultiKey({ publicKeys, signaturesRequired: spec.multi_key_threshold });
}

function buildMultiKeySigner(state: CliState, spec: InputSpec): MultiKeyAccount | undefined {
  if (spec.multi_key_signers.length === 0) return undefined;
  const multiKey = buildMultiKeyPublicKey(spec);
  const signerSpecs = spec.multi_key_signers.map(parseMultiKeySigner);
  const signers = signerSpecs.map((signerSpec) => {
    if (signerSpec.index >= spec.multi_key_public_keys.length) {
      fail(`multi-key signer index ${signerSpec.index} exceeds public key list`);
    }
    const signer = Account.fromPrivateKey({
      privateKey: new Ed25519PrivateKey(normalizeKeyHex(signerSpec.privateKey)),
      legacy: true,
    });
    const expectedPublicKey = new Ed25519PublicKey(normalizeKeyHex(spec.multi_key_public_keys[signerSpec.index]));
    if (signer.publicKey.toString() !== expectedPublicKey.toString()) {
      fail(`multi-key signer at index ${signerSpec.index} does not match --multi-key-public-key`);
    }
    return signer;
  });
  return new MultiKeyAccount({
    multiKey,
    signers,
    address: spec.sender_address,
  });
}

function buildEntryFunction(spec: InputSpec, parsedArgs: ArgSpec[], typeArgs: ReturnType<typeof parseTypeTag>[]): EntryFunction {
  const functionArgs: EntryFunctionArgument[] = parsedArgs.map(toEntryArgument);
  const { moduleAddress, moduleName, functionName } = parseFunctionId(spec.function);
  return EntryFunction.build(`${moduleAddress}::${moduleName}`, functionName, typeArgs, functionArgs);
}

function buildSimplePayload(
  spec: InputSpec,
  parsedArgs: ArgSpec[],
  typeArgs: ReturnType<typeof parseTypeTag>[],
): TransactionPayloadEntryFunction | TransactionPayloadScript {
  if (spec.script_hex) {
    return new TransactionPayloadScript(new Script(decodeHex(spec.script_hex), typeArgs, parsedArgs.map(toScriptArgument)));
  }
  return new TransactionPayloadEntryFunction(buildEntryFunction(spec, parsedArgs, typeArgs));
}

async function fetchNextMultisigAddress(aptos: Aptos, ownerAddress: string): Promise<AccountAddress> {
  const response = await aptos.viewJson<[string]>({
    payload: {
      function: "0x1::multisig_account::get_next_multisig_account_address",
      functionArguments: [ownerAddress],
    },
  });
  return AccountAddress.from(response[0]);
}

async function buildMultisigPayload(
  aptos: Aptos,
  spec: InputSpec,
  parsedArgs: ArgSpec[],
  typeArgs: ReturnType<typeof parseTypeTag>[],
): Promise<{
  payload:
    | TransactionPayloadEntryFunction
    | TransactionPayloadScript
    | TransactionPayloadMultiSig;
  expectedMultisigAddress?: string;
}> {
  switch (spec.multisig_action) {
    case "create-account": {
      const expectedMultisigAddress = (await fetchNextMultisigAddress(aptos, spec.sender_address)).toString();
      const additionalOwners = spec.multisig_owner_addresses.map((address) => AccountAddress.fromString(address));
      const metadataKeys = new MoveVector<MoveString>([]);
      const metadataValues = new MoveVector<MoveVector<U8>>([]);
      return {
        payload: new TransactionPayloadEntryFunction(
          EntryFunction.build("0x1::multisig_account", "create_with_owners", [], [
            new MoveVector(additionalOwners),
            new U64(BigInt(spec.multisig_threshold ?? 0)),
            metadataKeys,
            metadataValues,
          ]),
        ),
        expectedMultisigAddress,
      };
    }
    case "propose": {
      const multisigAddress = AccountAddress.fromString(spec.multisig_address!);
      const innerPayload = new MultiSigTransactionPayload(buildEntryFunction(spec, parsedArgs, typeArgs));
      const proposalBytes = spec.multisig_hash_only ? innerPayload.bcsToBytes() : innerPayload.bcsToBytes();
      const payloadBytes = spec.multisig_hash_only ? MoveVector.U8(sha3_256(proposalBytes)) : MoveVector.U8(proposalBytes);
      return {
        payload: new TransactionPayloadEntryFunction(
          EntryFunction.build(
            "0x1::multisig_account",
            spec.multisig_hash_only ? "create_transaction_with_hash" : "create_transaction",
            [],
            [multisigAddress, payloadBytes],
          ),
        ),
      };
    }
    case "approve":
      return {
        payload: new TransactionPayloadEntryFunction(
          EntryFunction.build("0x1::multisig_account", "approve_transaction", [], [
            AccountAddress.fromString(spec.multisig_address!),
            new U64(BigInt(spec.multisig_sequence!)),
          ]),
        ),
      };
    case "execute": {
      const multisigAddress = AccountAddress.fromString(spec.multisig_address!);
      const innerPayload = spec.function
        ? new MultiSigTransactionPayload(buildEntryFunction(spec, parsedArgs, typeArgs))
        : undefined;
      return {
        payload: new TransactionPayloadMultiSig(new MultiSig(multisigAddress, innerPayload)),
      };
    }
    default:
      fail(`unsupported multi-sig action: ${spec.multisig_action}`);
  }
}

function must<T>(value: T | undefined, flagName: string): T {
  if (value === undefined) {
    fail(`confidential-asset requires ${flagName}`);
  }
  return value;
}

async function buildConfidentialAssetTransaction(
  aptos: Aptos,
  spec: InputSpec,
  options: { maxGasAmount: number; gasUnitPrice?: number },
): Promise<SimpleTransaction> {
  const builder = new ConfidentialAssetTransactionBuilder(aptos.config);
  const sender = spec.sender_address;
  const tokenAddress = must(spec.confidential_token_address, "--confidential-token-address");
  switch (spec.confidential_action) {
    case "register": {
      const decryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_decryption_key, "--confidential-decryption-key"),
      );
      return builder.registerBalance({ sender, tokenAddress, decryptionKey, options });
    }
    case "deposit": {
      const amount = BigInt(must(spec.confidential_amount, "--confidential-amount"));
      return builder.deposit({ sender, tokenAddress, amount, options });
    }
    case "withdraw": {
      const decryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_decryption_key, "--confidential-decryption-key"),
      );
      const amount = BigInt(must(spec.confidential_amount, "--confidential-amount"));
      return builder.withdraw({
        sender,
        senderDecryptionKey: decryptionKey,
        tokenAddress,
        amount,
        recipient: spec.confidential_recipient,
        options,
      });
    }
    case "transfer": {
      const decryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_decryption_key, "--confidential-decryption-key"),
      );
      const amount = BigInt(must(spec.confidential_amount, "--confidential-amount"));
      const recipient = must(spec.confidential_recipient, "--confidential-recipient");
      return builder.transfer({
        sender,
        recipient,
        tokenAddress,
        amount,
        senderDecryptionKey: decryptionKey,
        memo: spec.confidential_memo ? decodeHex(spec.confidential_memo) : undefined,
        options,
      });
    }
    case "rollover":
      return builder.rolloverPendingBalance({
        sender,
        tokenAddress,
        withPauseIncoming: spec.confidential_with_pause_incoming,
        options,
      });
    case "normalize": {
      const decryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_decryption_key, "--confidential-decryption-key"),
      );
      return builder.normalizeBalance({
        sender,
        senderDecryptionKey: decryptionKey,
        tokenAddress,
        options,
      });
    }
    case "rotate": {
      const decryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_decryption_key, "--confidential-decryption-key"),
      );
      const newDecryptionKey = new TwistedEd25519PrivateKey(
        must(spec.confidential_new_decryption_key, "--confidential-new-decryption-key"),
      );
      return builder.rotateEncryptionKey({
        sender,
        senderDecryptionKey: decryptionKey,
        newSenderDecryptionKey: newDecryptionKey,
        tokenAddress,
        options,
      });
    }
    default:
      fail(`unsupported confidential-asset action: ${spec.confidential_action}`);
  }
}

function toEntryArgument(arg: ArgSpec): EntryFunctionArgument {
  if (arg.mode === "raw") {
    return new FixedBytes(arg.hex);
  }
  switch (arg.argType) {
    case "address":
      return AccountAddress.fromString(normalizeAddressInput(arg.value));
    case "u8":
      return new U8(Number(arg.value));
    case "u64":
      return new U64(BigInt(arg.value));
    case "u128":
      return new U128(BigInt(arg.value));
    case "bool":
      return new Bool(arg.value === "true");
    case "string":
      return new MoveString(arg.value);
    case "hex":
      return MoveVector.U8(decodeHex(arg.value));
    case "vector<u8>":
      return MoveVector.U8(parseVectorU8(arg.value));
    default:
      fail(`unsupported argument type: ${arg.argType}`);
  }
}

function toScriptArgument(arg: ArgSpec) {
  if (arg.mode === "raw") {
    return new Serialized(arg.hex);
  }
  switch (arg.argType) {
    case "address":
      return AccountAddress.fromString(normalizeAddressInput(arg.value));
    case "u8":
      return new U8(Number(arg.value));
    case "u64":
      return new U64(BigInt(arg.value));
    case "u128":
      return new U128(BigInt(arg.value));
    case "bool":
      return new Bool(arg.value === "true");
    case "string":
      return new MoveString(arg.value);
    case "hex":
      return MoveVector.U8(decodeHex(arg.value));
    case "vector<u8>":
      return MoveVector.U8(parseVectorU8(arg.value));
    default:
      fail(`unsupported script argument type: ${arg.argType}`);
  }
}

function readPrivateKey(state: CliState): string | undefined {
  if (state.privateKey) return state.privateKey;
  if (state.privateKeyEnv) {
    const value = process.env[state.privateKeyEnv];
    if (!value) fail(`environment variable ${state.privateKeyEnv} is not set`);
    return value;
  }
  if (state.privateKeyFile) {
    return fs.readFileSync(state.privateKeyFile, "utf8").trim();
  }
  return undefined;
}

function buildSigner(state: CliState, spec: InputSpec): Account | MultiKeyAccount | undefined {
  if (state.txnType === "multi-key") {
    return buildMultiKeySigner(state, spec);
  }
  const privateKey = readPrivateKey(state);
  if (!privateKey) return undefined;
  return Account.fromPrivateKey({
    privateKey: new Ed25519PrivateKey(normalizeKeyHex(privateKey)),
    address: spec.sender_address,
    legacy: true,
  });
}

function readPublicKey(state: CliState): string | undefined {
  if (state.publicKey) return state.publicKey;
  if (state.publicKeyEnv) {
    const value = process.env[state.publicKeyEnv];
    if (!value) fail(`environment variable ${state.publicKeyEnv} is not set`);
    return value;
  }
  if (state.publicKeyFile) {
    return fs.readFileSync(state.publicKeyFile, "utf8").trim();
  }
  return undefined;
}

function buildSimulationPublicKey(
  state: CliState,
  spec: InputSpec,
  signer: Account | MultiKeyAccount | undefined,
): PublicKey | undefined {
  if (state.txnType === "multi-key") {
    return signer?.publicKey ?? buildMultiKeyPublicKey(spec);
  }
  if (signer?.publicKey instanceof Ed25519PublicKey) {
    return signer.publicKey;
  }
  const publicKey = readPublicKey(state);
  if (!publicKey) return undefined;
  return new Ed25519PublicKey(normalizeKeyHex(publicKey));
}

function buildSecondarySigners(state: CliState, spec: InputSpec): Account[] {
  if (state.secondaryPrivateKeys.length === 0) return [];
  if (state.secondaryPrivateKeys.length !== spec.secondary_signer_addresses.length) {
    fail("secondary private key count must match secondary signer address count");
  }
  return state.secondaryPrivateKeys.map((privateKey, index) =>
    Account.fromPrivateKey({
      privateKey: new Ed25519PrivateKey(normalizeKeyHex(privateKey)),
      address: spec.secondary_signer_addresses[index],
      legacy: true,
    }),
  );
}

function buildSecondarySimulationPublicKeys(
  state: CliState,
  secondarySigners: Account[],
  secondaryAddresses: string[],
): Array<Ed25519PublicKey | undefined> | undefined {
  if (secondarySigners.length > 0) {
    return secondarySigners.map((signer) => signer.publicKey as Ed25519PublicKey);
  }
  if (state.secondaryPublicKeys.length === 0) return undefined;
  if (state.secondaryPublicKeys.length !== secondaryAddresses.length) {
    fail("secondary public key count must match secondary signer address count");
  }
  return state.secondaryPublicKeys.map((publicKey) => new Ed25519PublicKey(normalizeKeyHex(publicKey)));
}

function resolveNetwork(name: string): Network {
  switch (name.toLowerCase()) {
    case "mainnet":
      return Network.MAINNET;
    case "testnet":
      return Network.TESTNET;
    case "devnet":
      return Network.DEVNET;
    case "local":
    case "localnet":
      return Network.LOCAL;
    default:
      return Network.CUSTOM;
  }
}

function createClient(spec: InputSpec): Aptos {
  const network = resolveNetwork(spec.network);
  return new Aptos(
    new AptosConfig({
      network,
      fullnode: spec.fullnode,
      clientConfig: { http2: false },
    }),
  );
}

async function resolveAbiSummary(aptos: Aptos, spec: InputSpec): Promise<AbiSummary> {
  if (!spec.abi_enabled || !spec.function || spec.script_hex) {
    return { fetched: false };
  }
  const { moduleAddress, moduleName, functionName } = parseFunctionId(spec.function);
  const moduleBytecode = await aptos.getAccountModule({
    accountAddress: moduleAddress,
    moduleName,
  });
  const exposed = moduleBytecode.abi?.exposed_functions.find((item) => item.name === functionName);
  if (!exposed) {
    fail(`function ${spec.function} not found in remote ABI`);
  }
  return {
    fetched: true,
    module: `${moduleAddress}::${moduleName}`,
    function: functionName,
    parameter_count: exposed.params.length,
    type_parameter_count: exposed.generic_type_params.length,
  };
}

async function runMock(state: CliState, spec: InputSpec): Promise<Record<string, unknown>> {
  const parsedArgs = spec.args.map(parseArg);
  const signMode = signingMode(state);
  const seed = buildStableSeed(state.action, state.txnType, spec, signMode);
  const digest = stableDigest(seed);
  return {
    cli: "aptx",
    implementation: "typescript",
    sdk_backend: "@aptos-labs/ts-sdk",
    sdk_mode: "mock",
    action: state.action,
    txn_type: state.txnType,
    abi_enabled: spec.abi_enabled,
    input: {
      network: spec.network,
      function: spec.function,
      script_hex: spec.script_hex,
      sender_address: spec.sender_address,
      args: spec.args,
      parsed_args: parsedArgs,
      type_args: spec.type_args,
      secondary_signer_addresses: spec.secondary_signer_addresses,
      multisig_action: spec.multisig_action,
      multisig_address: spec.multisig_address,
      multisig_owner_addresses: spec.multisig_owner_addresses,
      multisig_threshold: spec.multisig_threshold,
      multisig_sequence: spec.multisig_sequence,
      multisig_hash_only: spec.multisig_hash_only,
      multi_key_public_keys: spec.multi_key_public_keys,
      multi_key_signers: spec.multi_key_signers,
      multi_key_threshold: spec.multi_key_threshold,
      confidential_action: spec.confidential_action,
      confidential_token_address: spec.confidential_token_address,
      confidential_amount: spec.confidential_amount,
      confidential_recipient: spec.confidential_recipient,
      confidential_with_pause_incoming: spec.confidential_with_pause_incoming,
      confidential_memo: spec.confidential_memo,
      hash: spec.hash,
      fullnode: spec.fullnode,
    },
    signing: {
      mode: signMode,
      provided: signMode !== "none",
      redacted: true,
    },
    abi: { fetched: false },
    result: {
      mode: state.action === "run" ? (spec.no_sign ? "simulate" : "submit") : state.action,
      success: true,
      vm_status: "Executed successfully",
      tx_hash: `0x${digest.slice(0, 32)}`,
      gas_used: spec.function.length + spec.args.length * 111 + spec.type_args.length * 37,
      notes: ["mock backend active", "sdk integration point reserved"],
    },
  };
}

async function runInspect(aptos: Aptos, state: CliState, spec: InputSpec): Promise<Record<string, unknown>> {
  if (spec.hash) {
    const transaction = await aptos.getTransactionByHash({ transactionHash: spec.hash });
    const committed = isUserTransactionResponse(transaction);
    return {
      cli: "aptx",
      implementation: "typescript",
      sdk_backend: "@aptos-labs/ts-sdk",
      sdk_mode: "sdk",
      action: "inspect",
      txn_type: "single",
      abi_enabled: spec.abi_enabled,
      input: {
        network: spec.network,
        hash: spec.hash,
        fullnode: spec.fullnode,
      },
      signing: {
        mode: signingMode(state),
        provided: false,
        redacted: true,
      },
      abi: { fetched: false },
      result: {
        mode: "inspect",
        success: committed ? transaction.success : true,
        vm_status: committed ? transaction.vm_status : "pending",
        tx_hash: transaction.hash,
        notes: ["fetched transaction by hash"],
        response: transaction,
      },
    };
  }
  const ledger = await aptos.getLedgerInfo();
  return {
    cli: "aptx",
    implementation: "typescript",
    sdk_backend: "@aptos-labs/ts-sdk",
    sdk_mode: "sdk",
    action: "inspect",
    txn_type: "single",
    abi_enabled: spec.abi_enabled,
    input: {
      network: spec.network,
      fullnode: spec.fullnode,
    },
    signing: {
      mode: "none",
      provided: false,
      redacted: true,
    },
    abi: { fetched: false },
    result: {
      mode: "inspect",
      success: true,
      vm_status: "ledger_info",
      tx_hash: "-",
      notes: ["fetched ledger info"],
      response: ledger,
    },
  };
}

async function runReal(state: CliState, spec: InputSpec): Promise<Record<string, unknown>> {
  const aptos = createClient(spec);
  if (state.action === "inspect") {
    return runInspect(aptos, state, spec);
  }

  const signer = buildSigner(state, spec);
  const simulationPublicKey = buildSimulationPublicKey(state, spec, signer);
  const secondarySigners = buildSecondarySigners(state, spec);
  const secondarySimulationPublicKeys = buildSecondarySimulationPublicKeys(
    state,
    secondarySigners,
    spec.secondary_signer_addresses,
  );
  const txnOptions = {
    maxGasAmount: state.maxGasAmount ?? 200_000,
    ...(state.gasUnitPrice != null ? { gasUnitPrice: state.gasUnitPrice } : {}),
  };

  let abi: AbiSummary;
  let parsedArgs: ArgSpec[] = [];
  let typeArgs: ReturnType<typeof parseTypeTag>[] = [];
  let payloadPlan: { expectedMultisigAddress?: string } = {};
  let transaction: SimpleTransaction | MultiAgentTransaction;

  if (state.txnType === "confidential-asset") {
    abi = { fetched: false };
    transaction = await buildConfidentialAssetTransaction(aptos, spec, txnOptions);
  } else {
    abi = await resolveAbiSummary(aptos, spec);
    parsedArgs = spec.args.map(parseArg);
    typeArgs = spec.type_args.map((value) => parseTypeTag(value));
    const builtPayloadPlan =
      state.txnType === "multi-sig"
        ? await buildMultisigPayload(aptos, spec, parsedArgs, typeArgs)
        : { payload: buildSimplePayload(spec, parsedArgs, typeArgs) };
    payloadPlan = builtPayloadPlan;
    const payloadInstance = builtPayloadPlan.payload;
    transaction = await (state.txnType === "multi-agent"
      ? buildTransaction({
          aptosConfig: aptos.config,
          sender: spec.sender_address,
          payload: payloadInstance,
          options: txnOptions,
          secondarySignerAddresses: spec.secondary_signer_addresses,
        })
      : buildTransaction({
          aptosConfig: aptos.config,
          sender: spec.sender_address,
          payload: payloadInstance,
          options: txnOptions,
        }));
  }

  const payload: Record<string, unknown> = {
    cli: "aptx",
    implementation: "typescript",
    sdk_backend: "@aptos-labs/ts-sdk",
    sdk_mode: "sdk",
    action: state.action,
    txn_type: state.txnType,
    abi_enabled: spec.abi_enabled,
    input: {
      network: spec.network,
      function: spec.function,
      script_hex: spec.script_hex,
      sender_address: spec.sender_address,
      args: spec.args,
      parsed_args: parsedArgs,
      type_args: spec.type_args,
      secondary_signer_addresses: spec.secondary_signer_addresses,
      multisig_action: spec.multisig_action,
      multisig_address: spec.multisig_address,
      multisig_owner_addresses: spec.multisig_owner_addresses,
      multisig_threshold: spec.multisig_threshold,
      multisig_sequence: spec.multisig_sequence,
      multisig_hash_only: spec.multisig_hash_only,
      confidential_action: spec.confidential_action,
      confidential_token_address: spec.confidential_token_address,
      confidential_amount: spec.confidential_amount,
      confidential_recipient: spec.confidential_recipient,
      confidential_with_pause_incoming: spec.confidential_with_pause_incoming,
      confidential_memo: spec.confidential_memo,
      fullnode: spec.fullnode,
    },
    signing: {
      mode: signingMode(state),
      provided: signer !== undefined,
      redacted: true,
    },
    abi,
    result: {
      mode: state.action,
      success: true,
      vm_status: "built",
      tx_hash: "-",
      notes: ["real SDK backend active"],
    },
  };

  const result = payload.result as Record<string, unknown>;
  const input = payload.input as Record<string, unknown>;
  input.sequence_number = String(transaction.rawTransaction.sequence_number);
  input.max_gas_amount = String(transaction.rawTransaction.max_gas_amount);
  input.gas_unit_price = String(transaction.rawTransaction.gas_unit_price);
  input.expiration_timestamp_secs = String(transaction.rawTransaction.expiration_timestamp_secs);
  if (payloadPlan.expectedMultisigAddress) {
    input.expected_multisig_address = payloadPlan.expectedMultisigAddress;
  }

  if (state.action === "simulate" || (state.action === "run" && spec.no_sign)) {
    const simulation =
      state.txnType === "multi-agent"
        ? await aptos.transaction.simulate.multiAgent({
            signerPublicKey: simulationPublicKey,
            secondarySignersPublicKeys: secondarySimulationPublicKeys,
            transaction,
          })
        : await aptos.transaction.simulate.simple({
            signerPublicKey: simulationPublicKey,
            transaction,
          });
    const first = simulation[0];
    result.mode = "simulate";
    result.success = first.success;
    result.vm_status = first.vm_status;
    result.tx_hash = first.hash;
    result.gas_used = first.gas_used;
    result.notes = ["simulated transaction"];
    result.response = first;
    if (payloadPlan.expectedMultisigAddress) {
      result.multisig_address = payloadPlan.expectedMultisigAddress;
    }
    return payload;
  }

  if (!signer) {
    fail("missing signer for submit path");
  }

  if (state.action === "submit") {
    const submitted =
      state.txnType === "multi-agent"
        ? await aptos.transaction.submit.multiAgent({
            transaction,
            senderAuthenticator: aptos.transaction.sign({ signer, transaction }),
            additionalSignersAuthenticators: secondarySigners.map((secondarySigner) =>
              aptos.transaction.sign({ signer: secondarySigner, transaction }),
            ),
          })
        : await aptos.signAndSubmitTransaction({
            signer,
            transaction,
          });
    result.mode = "submit";
    result.success = true;
    result.vm_status = "pending";
    result.tx_hash = submitted.hash;
    result.notes = ["submitted transaction"];
    result.response = submitted;
    if (payloadPlan.expectedMultisigAddress) {
      result.multisig_address = payloadPlan.expectedMultisigAddress;
    }
    return payload;
  }

  const simulation =
    state.txnType === "multi-agent"
      ? await aptos.transaction.simulate.multiAgent({
          signerPublicKey: simulationPublicKey ?? signer.publicKey,
          secondarySignersPublicKeys: secondarySimulationPublicKeys,
          transaction,
        })
      : await aptos.transaction.simulate.simple({
          signerPublicKey: simulationPublicKey ?? signer.publicKey,
          transaction,
        });
  const simulated = simulation[0];
  const submitted =
    state.txnType === "multi-agent"
      ? await aptos.transaction.submit.multiAgent({
          transaction,
          senderAuthenticator: aptos.transaction.sign({ signer, transaction }),
          additionalSignersAuthenticators: secondarySigners.map((secondarySigner) =>
            aptos.transaction.sign({ signer: secondarySigner, transaction }),
          ),
        })
      : await aptos.signAndSubmitTransaction({
          signer,
          transaction,
        });
  const executed = await aptos.waitForTransaction({
    transactionHash: submitted.hash,
  });
  result.mode = "run";
  result.success = executed.success;
  result.vm_status = executed.vm_status;
  result.tx_hash = executed.hash;
  result.gas_used = executed.gas_used;
  result.notes = ["simulated transaction", "submitted transaction", "waited for execution"];
  result.response = {
    simulation: simulated,
    submission: submitted,
    execution: executed,
  };
  if (payloadPlan.expectedMultisigAddress) {
    result.multisig_address = payloadPlan.expectedMultisigAddress;
  }
  return payload;
}

async function runEncode(state: CliState, spec: InputSpec): Promise<Record<string, unknown>> {
  const seqNum = BigInt(state.sequenceNumber ?? 0);
  const chainIdVal = state.chainId ?? 4;
  const maxGas = BigInt(state.maxGasAmount ?? 200_000);
  const gasPrice = BigInt(state.gasUnitPrice ?? 100);
  const expiration = BigInt(state.expirationTimestamp ?? 9_999_999_999);
  const sender = AccountAddress.fromString(spec.sender_address);
  const chainId = new ChainId(chainIdVal);

  const parsedArgs = spec.args.map(parseArg);
  const typeArgs = spec.type_args.map((v) => parseTypeTag(v));
  const payload = buildSimplePayload(spec, parsedArgs, typeArgs);

  const rawTxn = new RawTransaction(sender, seqNum, payload, maxGas, gasPrice, expiration, chainId);

  return {
    action: "encode",
    txn_type: state.txnType,
    bcs: "0x" + Buffer.from(rawTxn.bcsToBytes()).toString("hex"),
    sender: spec.sender_address,
    function: spec.function,
    chain_id: chainIdVal,
    sequence_number: Number(seqNum),
    max_gas_amount: Number(maxGas),
    gas_unit_price: Number(gasPrice),
    expiration_timestamp: Number(expiration),
  };
}

async function runDecode(state: CliState): Promise<Record<string, unknown>> {
  if (!state.inputBcs) fail("decode requires --input-bcs <hex>");
  const hexStr = state.inputBcs.startsWith("0x") ? state.inputBcs.slice(2) : state.inputBcs;
  const bytes = Uint8Array.from(Buffer.from(hexStr, "hex"));
  const des = new Deserializer(bytes);
  const rawTxn = RawTransaction.deserialize(des);

  const MAX_U64 = 18446744073709551615n;
  const isOrderless = rawTxn.sequence_number === MAX_U64;

  let fn = "";
  try {
    // TransactionPayloadEntryFunction.entryFunction gives EntryFunction.
    // EntryFunction extends Serializable so .toString() returns BCS hex — must use .identifier property.
    const p = rawTxn.payload as {
      entryFunction?: {
        module_name?: { address?: { toString(): string }; name?: { identifier?: string } };
        function_name?: { identifier?: string };
      };
    };
    const ef = p.entryFunction;
    if (ef) {
      const addr = ef.module_name?.address?.toString() ?? "";
      const mod = ef.module_name?.name?.identifier ?? "";
      const fname = ef.function_name?.identifier ?? "";
      fn = `${addr}::${mod}::${fname}`;
    }
  } catch {
    fn = "";
  }

  return {
    action: "decode",
    txn_type: isOrderless ? "orderless" : "single",
    sender: rawTxn.sender.toString(),
    function: fn,
    chain_id: rawTxn.chain_id.chainId,
    sequence_number: isOrderless ? "max_u64" : Number(rawTxn.sequence_number),
    max_gas_amount: Number(rawTxn.max_gas_amount),
    gas_unit_price: Number(rawTxn.gas_unit_price),
    expiration_timestamp: Number(rawTxn.expiration_timestamp_secs),
    is_orderless: isOrderless,
  };
}

async function runSign(state: CliState): Promise<Record<string, unknown>> {
  if (!state.inputBcs) fail("sign requires --input-bcs <hex>");
  const keyHex = readPrivateKey(state);
  if (!keyHex) fail("sign requires --private-key <hex>");

  const hexStr = state.inputBcs.startsWith("0x") ? state.inputBcs.slice(2) : state.inputBcs;
  const bytes = Uint8Array.from(Buffer.from(hexStr, "hex"));
  const des = new Deserializer(bytes);
  const rawTxn = RawTransaction.deserialize(des);

  // Signing message: sha3_256("APTOS::RawTransaction") || bcs_bytes
  const domainSep = sha3_256(new TextEncoder().encode("APTOS::RawTransaction"));
  const rawTxnBytes = rawTxn.bcsToBytes();
  const signingMsg = new Uint8Array(domainSep.length + rawTxnBytes.length);
  signingMsg.set(domainSep);
  signingMsg.set(rawTxnBytes, domainSep.length);

  const privateKey = new Ed25519PrivateKey(normalizeKeyHex(keyHex));
  const signature = privateKey.sign(signingMsg);
  const publicKey = privateKey.publicKey();

  return {
    action: "sign",
    txn_type: state.txnType,
    public_key: publicKey.toString(),
    signature: signature.toString(),
  };
}

async function main(): Promise<void> {
  const state = parseArgList(process.argv.slice(2));
  const inputFormat = detectFormat(state.input, state.inputFormat, "json");
  const fileInput = loadInput(state.input, inputFormat);
  const senderAddressInput = state.senderAddress ?? (fileInput.sender_address ? String(fileInput.sender_address) : "");
  const spec: InputSpec = {
    network: state.network ?? String(fileInput.network ?? "testnet"),
    function: state.fn ?? String(fileInput.function ?? ""),
    script_hex: state.scriptHex ?? (fileInput.script_hex ? String(fileInput.script_hex) : undefined),
    sender_address: normalizeAddressInput(senderAddressInput || "0x0"),
    args: state.args.length > 0 ? state.args : ((fileInput.args as string[]) ?? []),
    type_args: state.typeArgs.length > 0 ? state.typeArgs : ((fileInput.type_args as string[]) ?? []),
    secondary_signer_addresses:
      state.secondarySignerAddresses.length > 0
        ? state.secondarySignerAddresses.map(normalizeAddressInput)
        : (((fileInput.secondary_signer_addresses as string[]) ?? []).map(normalizeAddressInput)),
    abi_enabled: state.abiEnabled && fileInput.abi_enabled !== false,
    no_sign: state.noSign || fileInput.no_sign === true,
    hash: state.hash ?? (fileInput.hash ? String(fileInput.hash) : undefined),
    fullnode: state.fullnode ?? (fileInput.fullnode ? String(fileInput.fullnode) : undefined),
    multisig_action: state.multisigAction ?? (fileInput.multisig_action as MultisigAction | undefined),
    multisig_address: state.multisigAddress
      ? normalizeAddressInput(state.multisigAddress)
      : (fileInput.multisig_address ? normalizeAddressInput(String(fileInput.multisig_address)) : undefined),
    multisig_owner_addresses:
      state.multisigOwnerAddresses.length > 0
        ? state.multisigOwnerAddresses.map(normalizeAddressInput)
        : (((fileInput.multisig_owner_addresses as string[]) ?? []).map(normalizeAddressInput)),
    multisig_threshold:
      state.multisigThreshold ?? (fileInput.multisig_threshold !== undefined ? Number(fileInput.multisig_threshold) : undefined),
    multisig_sequence:
      state.multisigSequence ?? (fileInput.multisig_sequence !== undefined ? Number(fileInput.multisig_sequence) : undefined),
    multisig_hash_only: state.multisigHashOnly || fileInput.multisig_hash_only === true,
    multi_key_public_keys:
      state.multiKeyPublicKeys.length > 0
        ? state.multiKeyPublicKeys
        : ((fileInput.multi_key_public_keys as string[]) ?? []),
    multi_key_signers:
      state.multiKeySigners.length > 0
        ? state.multiKeySigners
        : ((fileInput.multi_key_signers as string[]) ?? []),
    multi_key_threshold:
      state.multiKeyThreshold ?? (fileInput.multi_key_threshold !== undefined ? Number(fileInput.multi_key_threshold) : undefined),
    confidential_action: state.confidentialAction ?? (fileInput.confidential_action as ConfidentialAssetAction | undefined),
    confidential_token_address: state.confidentialTokenAddress
      ? normalizeAddressInput(state.confidentialTokenAddress)
      : (fileInput.confidential_token_address
          ? normalizeAddressInput(String(fileInput.confidential_token_address))
          : undefined),
    confidential_decryption_key:
      state.confidentialDecryptionKey ??
      (fileInput.confidential_decryption_key ? String(fileInput.confidential_decryption_key) : undefined),
    confidential_new_decryption_key:
      state.confidentialNewDecryptionKey ??
      (fileInput.confidential_new_decryption_key ? String(fileInput.confidential_new_decryption_key) : undefined),
    confidential_amount:
      state.confidentialAmount ?? (fileInput.confidential_amount !== undefined ? String(fileInput.confidential_amount) : undefined),
    confidential_recipient: state.confidentialRecipient
      ? normalizeAddressInput(state.confidentialRecipient)
      : (fileInput.confidential_recipient ? normalizeAddressInput(String(fileInput.confidential_recipient)) : undefined),
    confidential_with_pause_incoming: state.confidentialWithPauseIncoming || fileInput.confidential_with_pause_incoming === true,
    confidential_memo:
      state.confidentialMemo ?? (fileInput.confidential_memo ? String(fileInput.confidential_memo) : undefined),
  };
  if (state.txnType === "multi-key" && !senderAddressInput && spec.multi_key_public_keys.length > 0 && spec.multi_key_threshold) {
    spec.sender_address = buildMultiKeyPublicKey(spec).authKey().derivedAddress().toString();
  }
  requireValidState(state, spec);

  let payload: Record<string, unknown>;
  if (state.action === "encode") {
    payload = await runEncode(state, spec);
  } else if (state.action === "decode") {
    payload = await runDecode(state);
  } else if (state.action === "sign") {
    payload = await runSign(state);
  } else {
    payload = state.sdkMode === "mock" ? await runMock(state, spec) : await runReal(state, spec);
  }
  writeArtifacts(state.artifactsDir, payload);
  const outputFormat = detectFormat(
    state.output,
    state.outputFormat,
    state.output ? "json" : "table",
  ) as OutputFormat;
  const rendered =
    outputFormat === "json"
      ? safeJson(payload)
      : outputFormat === "yaml"
        ? renderYaml(payload)
        : outputFormat === "ascii"
          ? renderAscii(payload)
          : renderTable(payload);

  if (state.output && state.output !== "-") {
    fs.writeFileSync(state.output, rendered + "\n");
  } else if (!state.quiet) {
    process.stdout.write(rendered + "\n");
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exit(1);
});
