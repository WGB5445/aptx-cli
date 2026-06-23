/**
 * Keyless BCS roundtrip verification.
 *
 * Tests all keyless crypto types for correct BCS serialization/deserialization
 * without requiring a real OIDC flow, prover service, or network access.
 *
 * Run:  pnpm test:keyless-bcs
 */

import {
  EphemeralKeyPair,
  KeylessPublicKey,
  KeylessSignature,
  EphemeralCertificate,
  ZeroKnowledgeSig,
  Groth16Zkp,
  ZkProof,
  EphemeralPublicKey,
  EphemeralSignature,
} from "@aptos-labs/ts-sdk/keyless";
import {
  Serializer,
  Deserializer,
  AccountAddress,
  Ed25519PrivateKey,
  AnyPublicKey,
} from "@aptos-labs/ts-sdk";
import { EphemeralCertificateVariant, ZkpVariant } from "@aptos-labs/ts-sdk";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string): void {
  if (condition) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${msg}`);
    failed++;
  }
}

function hexEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  return a.every((v, i) => v === b[i]);
}

function bcsRoundtrip<T>(
  obj: { serialize(s: Serializer): void },
  deserialize: (d: Deserializer) => T,
): { original: Uint8Array; recovered: T } {
  const ser = new Serializer();
  obj.serialize(ser);
  const bytes = ser.toUint8Array();
  const des = new Deserializer(bytes);
  const recovered = deserialize(des);
  return { original: bytes, recovered };
}

// ---------------------------------------------------------------------------
// 1. EphemeralKeyPair
// ---------------------------------------------------------------------------

console.log("\n=== 1. EphemeralKeyPair ===");

const ekp = EphemeralKeyPair.generate();
assert(typeof ekp.nonce === "string" && ekp.nonce.length > 0, "nonce is a non-empty string");
assert(ekp.expiryDateSecs > Date.now() / 1000, "expiry is in the future");
assert(ekp.blinder.length === 31, "blinder is 31 bytes");
assert(!ekp.isExpired(), "newly generated EPK is not expired");

// BCS roundtrip
const { original: ekpBytes, recovered: ekp2 } = bcsRoundtrip(ekp, EphemeralKeyPair.deserialize);
assert(ekp2.nonce === ekp.nonce, "EphemeralKeyPair nonce survives BCS roundtrip");
assert(ekp2.expiryDateSecs === ekp.expiryDateSecs, "EphemeralKeyPair expiry survives BCS roundtrip");
assert(hexEq(ekp2.blinder, ekp.blinder), "EphemeralKeyPair blinder survives BCS roundtrip");
console.log(`  → BCS bytes: ${ekpBytes.length} bytes`);

// Known-key determinism: same key → same nonce
const fixedPriv = new Ed25519PrivateKey("0x0101010101010101010101010101010101010101010101010101010101010101");
const ekpA = new EphemeralKeyPair({ privateKey: fixedPriv, expiryDateSecs: 9_999_999_999, blinder: new Uint8Array(31) });
const ekpB = new EphemeralKeyPair({ privateKey: fixedPriv, expiryDateSecs: 9_999_999_999, blinder: new Uint8Array(31) });
assert(ekpA.nonce === ekpB.nonce, "Same key+expiry+blinder → same nonce (deterministic)");
console.log(`  → deterministic nonce: ${ekpA.nonce.slice(0, 20)}…`);

// ---------------------------------------------------------------------------
// 2. KeylessPublicKey
// ---------------------------------------------------------------------------

console.log("\n=== 2. KeylessPublicKey ===");

const ISS = "https://accounts.google.com";
const ID_COMMIT = new Uint8Array(32).fill(0xab); // fake 32-byte idCommitment

const kpk = new KeylessPublicKey(ISS, ID_COMMIT);
assert(kpk.iss === ISS, "iss field set correctly");
assert(kpk.idCommitment.length === 32, "idCommitment is 32 bytes");

const { original: kpkBytes, recovered: kpk2 } = bcsRoundtrip(kpk, KeylessPublicKey.deserialize);
assert(kpk2.iss === ISS, "KeylessPublicKey iss survives BCS roundtrip");
assert(hexEq(kpk2.idCommitment, ID_COMMIT), "KeylessPublicKey idCommitment survives BCS roundtrip");
console.log(`  → BCS bytes: ${kpkBytes.length} bytes`);

// Address derivation is deterministic
const addr1 = kpk.authKey().derivedAddress();
const addr2 = new KeylessPublicKey(ISS, ID_COMMIT).authKey().derivedAddress();
assert(addr1.toString() === addr2.toString(), "address derivation is deterministic");
console.log(`  → derived address: ${addr1.toString()}`);

// ---------------------------------------------------------------------------
// 3. Groth16Zkp
// ---------------------------------------------------------------------------

console.log("\n=== 3. Groth16Zkp ===");

// Use all-zeros as a syntactically valid (but cryptographically invalid) proof
const a = new Uint8Array(32);
const b = new Uint8Array(64);
const c = new Uint8Array(32);
const zkp = new Groth16Zkp({ a, b, c });

const { original: zkpBytes, recovered: zkp2 } = bcsRoundtrip(zkp, Groth16Zkp.deserialize);
assert(hexEq(zkp2.a.data, a), "Groth16Zkp.a survives BCS roundtrip");
assert(hexEq(zkp2.b.data, b), "Groth16Zkp.b survives BCS roundtrip");
assert(hexEq(zkp2.c.data, c), "Groth16Zkp.c survives BCS roundtrip");
assert(zkpBytes.length === 128, `Groth16Zkp is 128 bytes (got ${zkpBytes.length})`);
console.log(`  → BCS bytes: ${zkpBytes.length} bytes`);

// ---------------------------------------------------------------------------
// 4. ZkProof (wraps Groth16Zkp with variant tag)
// ---------------------------------------------------------------------------

console.log("\n=== 4. ZkProof ===");

const zkProof = new ZkProof(zkp, ZkpVariant.Groth16);
const { original: zkProofBytes, recovered: zkProof2 } = bcsRoundtrip(zkProof, ZkProof.deserialize);
assert(zkProof2.variant === ZkpVariant.Groth16, "ZkProof variant survives BCS roundtrip");
assert(zkProofBytes.length === 129, `ZkProof is 129 bytes (1 variant tag + 128 proof, got ${zkProofBytes.length})`);
console.log(`  → BCS bytes: ${zkProofBytes.length} bytes`);

// ---------------------------------------------------------------------------
// 5. ZeroKnowledgeSig
// ---------------------------------------------------------------------------

console.log("\n=== 5. ZeroKnowledgeSig ===");

const zks = new ZeroKnowledgeSig({
  proof: zkProof,
  expHorizonSecs: 10_000_000,
});

const { original: zksBytes, recovered: zks2 } = bcsRoundtrip(zks, ZeroKnowledgeSig.deserialize);
assert(zks2.expHorizonSecs === 10_000_000, "ZeroKnowledgeSig expHorizonSecs survives BCS roundtrip");
assert(zks2.extraField === undefined, "ZeroKnowledgeSig extraField is absent when not set");
assert(zks2.overrideAudVal === undefined, "ZeroKnowledgeSig overrideAudVal is absent when not set");
assert(zks2.trainingWheelsSignature === undefined, "ZeroKnowledgeSig trainingWheelsSignature absent when not set");
console.log(`  → BCS bytes: ${zksBytes.length} bytes`);

// From-bytes deserialization
const zks3 = ZeroKnowledgeSig.fromBytes(zksBytes);
assert(zks3.expHorizonSecs === 10_000_000, "ZeroKnowledgeSig.fromBytes round-trips correctly");

// ---------------------------------------------------------------------------
// 6. KeylessSignature (simulation)
// ---------------------------------------------------------------------------

console.log("\n=== 6. KeylessSignature (simulation) ===");

const simSig = KeylessSignature.getSimulationSignature();
assert(KeylessSignature.isSignature(simSig), "getSimulationSignature returns a KeylessSignature");
assert(typeof simSig.jwtHeader === "string", "jwtHeader is a string");
assert(simSig.expiryDateSecs === 0, "simulation signature has expiryDateSecs=0");

// BCS roundtrip
const { original: simSigBytes, recovered: simSig2 } = bcsRoundtrip(simSig, KeylessSignature.deserialize);
assert(simSig2.jwtHeader === simSig.jwtHeader, "KeylessSignature jwtHeader survives BCS roundtrip");
assert(simSig2.expiryDateSecs === simSig.expiryDateSecs, "KeylessSignature expiryDateSecs survives BCS roundtrip");
console.log(`  → BCS bytes: ${simSigBytes.length} bytes`);
console.log(`  → jwtHeader: ${simSig.jwtHeader}`);

// bcsToBytes convenience
const bcsBytes = simSig.bcsToBytes();
assert(hexEq(bcsBytes, simSigBytes), "bcsToBytes() matches manual serializer output");

// ---------------------------------------------------------------------------
// 7. EphemeralPublicKey and EphemeralSignature
// ---------------------------------------------------------------------------

console.log("\n=== 7. EphemeralPublicKey / EphemeralSignature ===");

const epk = ekp.getPublicKey();
const { original: epkBytes, recovered: epk2 } = bcsRoundtrip(epk, EphemeralPublicKey.deserialize);
assert(hexEq(epkBytes, epk2.bcsToBytes()), "EphemeralPublicKey BCS roundtrip is stable");
console.log(`  → EphemeralPublicKey BCS bytes: ${epkBytes.length}`);

// Sign a known message and roundtrip the signature
const testMsg = new Uint8Array(32).fill(0xff);
const eSig = ekp.sign(testMsg);
const { original: eSigBytes, recovered: eSig2 } = bcsRoundtrip(eSig, EphemeralSignature.deserialize);
assert(hexEq(eSigBytes, eSig2.bcsToBytes()), "EphemeralSignature BCS roundtrip is stable");
console.log(`  → EphemeralSignature BCS bytes: ${eSigBytes.length}`);

// ---------------------------------------------------------------------------
// 8. AnyPublicKey wrapping KeylessPublicKey
// ---------------------------------------------------------------------------

console.log("\n=== 8. AnyPublicKey(Keyless) BCS roundtrip ===");

const anyKpk = new AnyPublicKey(kpk);
const { original: anyBytes, recovered: any2 } = bcsRoundtrip(anyKpk, AnyPublicKey.deserialize);
assert(AnyPublicKey.isPublicKey(any2), "AnyPublicKey.isPublicKey holds after roundtrip");
// Inner key should equal the original
assert(hexEq(anyBytes, any2.bcsToBytes()), "AnyPublicKey(Keyless) BCS is stable across roundtrip");
console.log(`  → AnyPublicKey(Keyless) BCS bytes: ${anyBytes.length}`);

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n${"=".repeat(50)}`);
console.log(`Results: ${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
console.log("All keyless BCS tests passed.");
