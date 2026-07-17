/**
 * Confidential Asset live integration test.
 *
 * Drives the `aptx` CLI's `confidential-asset` txn-type end to end against a real network
 * (localnet by default): register -> deposit -> rollover -> transfer -> rollover -> withdraw.
 * Balance assertions after each mutating step use `@aptos-labs/confidential-asset` directly
 * (decrypting on-chain state), independent of the CLI, so the check doesn't just trust the
 * CLI's own "success" report.
 *
 * Run:  pnpm test:confidential-asset
 */

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Account, Aptos, AptosConfig, Network } from "@aptos-labs/ts-sdk";
import { ConfidentialAsset, TwistedEd25519PrivateKey } from "@aptos-labs/confidential-asset";

const FUNDING_AMOUNT = 100_000_000;
const DEPOSIT_AMOUNT = 2_000_000n;
const TRANSFER_AMOUNT = 500_000n;
const WITHDRAW_AMOUNT = TRANSFER_AMOUNT;
const IMPLEMENTATION_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

type CliRuntime = "node" | "deno";
type MoveOption<T> = { vec: T[] };
type MoveObject = { inner: string };

function resolveNetwork(name: string): Network {
  switch (name.toLowerCase()) {
    case "mainnet":
      return Network.MAINNET;
    case "testnet":
      return Network.TESTNET;
    case "local":
    case "localnet":
      return Network.LOCAL;
    default:
      return Network.DEVNET;
  }
}

function createClient(): Aptos {
  const networkName = process.env.APTX_TEST_NETWORK ?? "local";
  const fullnode = process.env.APTX_TEST_FULLNODE;
  return new Aptos(
    new AptosConfig({
      network: resolveNetwork(networkName),
      fullnode,
      clientConfig: { http2: false },
    }),
  );
}

function fullnodeUrl(): string {
  return process.env.APTX_TEST_FULLNODE ?? "http://127.0.0.1:8080/v1";
}

function faucetUrl(): string {
  return process.env.APTX_TEST_FAUCET ?? "http://127.0.0.1:8081";
}

async function fundAccount(address: string, amount = FUNDING_AMOUNT): Promise<void> {
  const response = await fetch(`${faucetUrl()}/fund`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ address, amount }),
  });
  if (!response.ok) {
    throw new Error(`fund account failed: ${response.status} ${await response.text()}`);
  }
  const payload = (await response.json()) as { txn_hashes?: string[] };
  const txnHash = payload.txn_hashes?.[0];
  if (!txnHash) {
    throw new Error(`fund account response missing txn hash: ${JSON.stringify(payload)}`);
  }
  await waitForTransaction(txnHash);
}

async function waitForTransaction(txHash: string): Promise<void> {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const response = await fetch(`${fullnodeUrl()}/transactions/by_hash/${txHash}`);
    if (response.status === 404) {
      await sleep(1000);
      continue;
    }
    if (!response.ok) {
      throw new Error(`transaction lookup failed: ${response.status} ${await response.text()}`);
    }
    const payload = (await response.json()) as { type?: string; success?: boolean; vm_status?: string };
    if (payload.type === "pending_transaction") {
      await sleep(1000);
      continue;
    }
    if (payload.success === false) {
      throw new Error(`transaction ${txHash} failed: ${payload.vm_status}`);
    }
    return;
  }
  throw new Error(`timed out waiting for transaction ${txHash}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getAptFaMetadataAddress(aptos: Aptos): Promise<string> {
  const [result] = await aptos.view<[MoveOption<MoveObject>]>({
    payload: {
      function: "0x1::coin::paired_metadata",
      typeArguments: ["0x1::aptos_coin::AptosCoin"],
      functionArguments: [],
    },
  });
  if (result.vec.length === 0) {
    throw new Error("APT fungible asset metadata not found (0x1::coin::paired_metadata returned none)");
  }
  return result.vec[0].inner;
}

function runCli(runtime: CliRuntime, args: string[]) {
  const command =
    runtime === "node" ? process.execPath : path.resolve(IMPLEMENTATION_DIR, "scripts/run-deno.sh");
  const commandArgs =
    runtime === "node" ? ["--experimental-strip-types", "src/cli.ts", ...args] : args;
  const stdout = execFileSync(command, commandArgs, {
    cwd: IMPLEMENTATION_DIR,
    env: process.env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(stdout) as {
    input: Record<string, unknown>;
    result: Record<string, unknown>;
  };
}

function assertCliSuccess(runtime: CliRuntime, label: string, payload: { result: Record<string, unknown> }): void {
  if (payload.result.success !== true) {
    throw new Error(`${runtime} ${label} failed: ${JSON.stringify(payload.result)}`);
  }
}

function assertEqual(label: string, actual: bigint, expected: bigint): void {
  if (actual !== expected) {
    throw new Error(`${label}: got ${actual} want ${expected}`);
  }
}

function confidentialAssetFlags(args: {
  action: string;
  tokenAddress: string;
  decryptionKey?: TwistedEd25519PrivateKey;
  amount?: bigint;
  recipient?: string;
  withPauseIncoming?: boolean;
}): string[] {
  const flags = ["--confidential-action", args.action, "--confidential-token-address", args.tokenAddress];
  if (args.decryptionKey) flags.push("--confidential-decryption-key", args.decryptionKey.toString());
  if (args.amount !== undefined) flags.push("--confidential-amount", args.amount.toString());
  if (args.recipient) flags.push("--confidential-recipient", args.recipient);
  if (args.withPauseIncoming) flags.push("--confidential-with-pause-incoming");
  return flags;
}

function baseFlags(senderAddress: string, privateKey: string): string[] {
  return [
    "--network",
    process.env.APTX_TEST_NETWORK ?? "local",
    "--fullnode",
    fullnodeUrl(),
    "--output-format",
    "json",
    "--sender-address",
    senderAddress,
    "--private-key",
    privateKey,
  ];
}

async function main(): Promise<void> {
  const aptos = createClient();
  const alice = Account.generate();
  const bob = Account.generate();
  const aliceDk = TwistedEd25519PrivateKey.generate();
  const bobDk = TwistedEd25519PrivateKey.generate();

  await fundAccount(alice.accountAddress.toString());
  await fundAccount(bob.accountAddress.toString());

  const tokenAddress = await getAptFaMetadataAddress(aptos);
  const confidentialAsset = new ConfidentialAsset({ config: aptos.config });

  // Runtime-parity smoke check: simulate (non-mutating) the same register call via both
  // node and deno, mirroring the pattern used by live-multikey.ts / live-multisig.ts.
  for (const runtime of ["node", "deno"] as const) {
    const simulated = runCli(runtime, [
      "simulate",
      "confidential-asset",
      ...baseFlags(alice.accountAddress.toString(), String(alice.privateKey)),
      ...confidentialAssetFlags({ action: "register", tokenAddress, decryptionKey: aliceDk }),
    ]);
    assertCliSuccess(runtime, "simulate register", simulated);
  }

  // Mutating flow, driven once via node.
  assertCliSuccess(
    "node",
    "run register (alice)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(alice.accountAddress.toString(), String(alice.privateKey)),
      ...confidentialAssetFlags({ action: "register", tokenAddress, decryptionKey: aliceDk }),
    ]),
  );

  assertCliSuccess(
    "node",
    "run register (bob)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(bob.accountAddress.toString(), String(bob.privateKey)),
      ...confidentialAssetFlags({ action: "register", tokenAddress, decryptionKey: bobDk }),
    ]),
  );

  assertCliSuccess(
    "node",
    "run deposit (alice)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(alice.accountAddress.toString(), String(alice.privateKey)),
      ...confidentialAssetFlags({ action: "deposit", tokenAddress, amount: DEPOSIT_AMOUNT }),
    ]),
  );

  assertCliSuccess(
    "node",
    "run rollover (alice)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(alice.accountAddress.toString(), String(alice.privateKey)),
      ...confidentialAssetFlags({ action: "rollover", tokenAddress }),
    ]),
  );

  const aliceAfterDeposit = await confidentialAsset.getBalance({
    accountAddress: alice.accountAddress,
    tokenAddress,
    decryptionKey: aliceDk,
  });
  assertEqual("alice available after rollover", aliceAfterDeposit.availableBalance(), DEPOSIT_AMOUNT);
  assertEqual("alice pending after rollover", aliceAfterDeposit.pendingBalance(), 0n);

  assertCliSuccess(
    "node",
    "run transfer (alice -> bob)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(alice.accountAddress.toString(), String(alice.privateKey)),
      ...confidentialAssetFlags({
        action: "transfer",
        tokenAddress,
        decryptionKey: aliceDk,
        amount: TRANSFER_AMOUNT,
        recipient: bob.accountAddress.toString(),
      }),
    ]),
  );

  const aliceAfterTransfer = await confidentialAsset.getBalance({
    accountAddress: alice.accountAddress,
    tokenAddress,
    decryptionKey: aliceDk,
  });
  assertEqual(
    "alice available after transfer",
    aliceAfterTransfer.availableBalance(),
    DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
  );

  const bobAfterTransfer = await confidentialAsset.getBalance({
    accountAddress: bob.accountAddress,
    tokenAddress,
    decryptionKey: bobDk,
  });
  assertEqual("bob pending after transfer", bobAfterTransfer.pendingBalance(), TRANSFER_AMOUNT);

  assertCliSuccess(
    "node",
    "run rollover (bob)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(bob.accountAddress.toString(), String(bob.privateKey)),
      ...confidentialAssetFlags({ action: "rollover", tokenAddress }),
    ]),
  );

  const bobAfterRollover = await confidentialAsset.getBalance({
    accountAddress: bob.accountAddress,
    tokenAddress,
    decryptionKey: bobDk,
  });
  assertEqual("bob available after rollover", bobAfterRollover.availableBalance(), TRANSFER_AMOUNT);
  assertEqual("bob pending after rollover", bobAfterRollover.pendingBalance(), 0n);

  const bobAptBefore = await aptos.getAccountAPTAmount({ accountAddress: bob.accountAddress });

  assertCliSuccess(
    "node",
    "run withdraw (bob)",
    runCli("node", [
      "run",
      "confidential-asset",
      ...baseFlags(bob.accountAddress.toString(), String(bob.privateKey)),
      ...confidentialAssetFlags({ action: "withdraw", tokenAddress, decryptionKey: bobDk, amount: WITHDRAW_AMOUNT }),
    ]),
  );

  const bobAfterWithdraw = await confidentialAsset.getBalance({
    accountAddress: bob.accountAddress,
    tokenAddress,
    decryptionKey: bobDk,
  });
  assertEqual(
    "bob available after withdraw",
    bobAfterWithdraw.availableBalance(),
    TRANSFER_AMOUNT - WITHDRAW_AMOUNT,
  );

  // Bob's own APT balance also pays gas for the withdraw transaction itself, so the observed
  // delta is the withdrawn amount minus that gas fee, not an exact match.
  const bobAptAfter = await aptos.getAccountAPTAmount({ accountAddress: bob.accountAddress });
  const bobAptDelta = Number(bobAptAfter) - Number(bobAptBefore);
  if (bobAptDelta <= 0 || bobAptDelta > Number(WITHDRAW_AMOUNT)) {
    throw new Error(
      `bob APT balance delta after withdraw: got ${bobAptDelta}, want a positive value <= ${WITHDRAW_AMOUNT} (withdrawn amount minus gas)`,
    );
  }

  process.stdout.write(
    JSON.stringify(
      {
        status: "ok",
        tested: ["typescript-confidential-asset-node", "typescript-confidential-asset-deno-simulate"],
        tokenAddress,
        aliceAddress: alice.accountAddress.toString(),
        bobAddress: bob.accountAddress.toString(),
      },
      null,
      2,
    ) + "\n",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? (error.stack ?? error.message) : String(error);
  process.stderr.write(`${message}\n`);
  process.exit(1);
});
