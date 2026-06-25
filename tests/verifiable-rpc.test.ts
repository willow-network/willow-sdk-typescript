/**
 * Unit tests for the verifiable-RPC transformation orchestration:
 * content-addressed circuit/VK fetch + SHA-256 pin, per-chunk verification,
 * chunk chaining, and the final-output-root === state_root binding. The wasm
 * GKR verifier itself is exercised separately; here we mock it + `fetch` to
 * test the orchestration logic (chaining + fail-closed behavior) without a
 * live indexer.
 */

import { gzipSync } from "node:zlib";
import { sha256 } from "@noble/hashes/sha256";
import {
  verifyTransformationProofs,
  type GkrProofData,
  type GkrVerifier,
} from "../src/verifiable-rpc";

const arr = (u: Uint8Array): number[] => Array.from(u);
const fill = (n: number, b: number): Uint8Array => new Uint8Array(n).fill(b);

const CIRCUIT = new Uint8Array([1, 2, 3, 4, 5]);
const VK = new Uint8Array([9, 8, 7]);
const CV = sha256(CIRCUIT); // == verification_key_hash the prover commits to
const BASE = "http://indexer.test";

function installFetch(circuit: Uint8Array, vk: Uint8Array): void {
  (globalThis as { fetch?: unknown }).fetch = async (url: string) => {
    const gz = gzipSync(Buffer.from(url.includes("/circuit/") ? circuit : vk));
    return {
      ok: true,
      arrayBuffer: async () => Uint8Array.from(gz).buffer,
    };
  };
}

function mkProof(start: number, output: number, cv: Uint8Array = CV): GkrProofData {
  return {
    proof_version: 1,
    proof: [1, 2, 3],
    public_inputs: {
      output_root: arr(fill(32, output)),
      block_range: [100, 200],
      config_hash: arr(fill(32, 0x33)),
      starting_state_root: arr(fill(32, start)),
    },
    verification_key_hash: arr(cv),
    proof_size_bytes: 3,
    generation_time_ms: 0,
    gpu_accelerated: false,
  };
}

const okVerifier: GkrVerifier = { verify_full_proof_explicit: () => {} };
const failVerifier: GkrVerifier = {
  verify_full_proof_explicit: () => {
    throw new Error("proof rejected");
  },
};

describe("verifyTransformationProofs", () => {
  beforeEach(() => installFetch(CIRCUIT, VK));

  it("accepts a single proof whose output_root equals state_root", async () => {
    const sr = fill(32, 0xaa);
    await expect(
      verifyTransformationProofs(BASE, [mkProof(0x00, 0xaa)], sr, okVerifier),
    ).resolves.toBeUndefined();
  });

  it("accepts a chained pair (start[i+1] === output[i]) ending at state_root", async () => {
    const sr = fill(32, 0xcc);
    const chained = [mkProof(0x00, 0xbb), mkProof(0xbb, 0xcc)];
    await expect(
      verifyTransformationProofs(BASE, chained, sr, okVerifier),
    ).resolves.toBeUndefined();
  });

  it("rejects a broken chain", async () => {
    const sr = fill(32, 0xcc);
    const broken = [mkProof(0x00, 0xbb), mkProof(0x99, 0xcc)]; // 0x99 !== 0xbb
    await expect(
      verifyTransformationProofs(BASE, broken, sr, okVerifier),
    ).rejects.toThrow(/chain/i);
  });

  it("rejects when the final output_root !== state_root", async () => {
    const sr = fill(32, 0xaa);
    await expect(
      verifyTransformationProofs(BASE, [mkProof(0x00, 0xbb)], sr, okVerifier),
    ).rejects.toThrow(/state_root/i);
  });

  it("surfaces a verifier rejection as a transformation failure", async () => {
    const sr = fill(32, 0xaa);
    await expect(
      verifyTransformationProofs(BASE, [mkProof(0x00, 0xaa)], sr, failVerifier),
    ).rejects.toThrow(/did not verify/i);
  });

  it("rejects a circuit whose SHA-256 does not match verification_key_hash", async () => {
    const sr = fill(32, 0xaa);
    // verification_key_hash claims 0xEE*32, but the served circuit hashes to CV.
    await expect(
      verifyTransformationProofs(BASE, [mkProof(0x00, 0xaa, fill(32, 0xee))], sr, okVerifier),
    ).rejects.toThrow(/SHA-256|match/i);
  });
});
