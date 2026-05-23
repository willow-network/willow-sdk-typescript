import { keccak_256 } from "@noble/hashes/sha3";
import { encodeRlp, getBytes } from "ethers";

import { verifyMptProof } from "../src/eth-state/mpt";
import { verifyStateProof } from "../src/eth-state";
import type { StateProof } from "../src/eth-state/types";

describe("mpt", () => {
  it("rejects when root hash doesn't match first node", () => {
    const r = verifyMptProof(
      new Uint8Array(32),
      new Uint8Array(32),
      new Uint8Array([0x80]),
      [new Uint8Array([0xc0])],
    );
    expect(r.ok).toBe(false);
    expect(r.error).toContain("hash mismatch");
  });

  it("rejects when proof list is empty", () => {
    const r = verifyMptProof(new Uint8Array(32), new Uint8Array(32), new Uint8Array(), []);
    expect(r.ok).toBe(false);
    expect(r.error).toContain("proof is empty");
  });

  it("rejects malformed leaf path (wrong length)", () => {
    const r = verifyMptProof(
      new Uint8Array([1, 2, 3]),
      new Uint8Array(32),
      new Uint8Array([0x80]),
      [new Uint8Array([0xc0])],
    );
    expect(r.ok).toBe(false);
    expect(r.error).toContain("root must be 32 bytes");
  });

  it("verifies a single-leaf trie (key matches leaf exactly)", () => {
    // Build a single-leaf trie: leaf node = [encoded_path, value]
    // Key: keccak256("hello") -> nibbles cover the whole key path
    const keyHash = keccak_256(getBytes("0x68656c6c6f")); // "hello"
    // Encode the entire key path as a leaf:
    // Prefix is 0x20 (leaf, even nibble count). Then all 32 bytes of keyHash.
    const encodedPath = new Uint8Array(33);
    encodedPath[0] = 0x20;
    encodedPath.set(keyHash, 1);
    const value = getBytes("0xabcdef");
    const leafNode = getBytes(encodeRlp([encodedPath, value]));
    const root = keccak_256(leafNode);
    const r = verifyMptProof(root, keyHash, value, [leafNode]);
    expect(r.ok).toBe(true);
  });
});

describe("verifyStateProof", () => {
  it("rejects tampered balance with empty proof_nodes", () => {
    const proof: StateProof = {
      address: Array.from({ length: 20 }, () => 0),
      block_number: 1,
      block_hash: Array.from({ length: 32 }, () => 0),
      state_root: Array.from({ length: 32 }, () => 0),
      account_proof: {
        key: Array.from({ length: 32 }, () => 0),
        value: [],
        proof_nodes: [],
      },
      account_state: {
        nonce: 0,
        balance: Array.from({ length: 32 }, () => 0xff), // tampered
        storage_hash: Array.from({ length: 32 }, () => 0),
        code_hash: Array.from({ length: 32 }, () => 0),
      },
      storage_proofs: [],
    };
    expect(() => verifyStateProof(proof)).toThrow();
  });
});
