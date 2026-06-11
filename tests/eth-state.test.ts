import { keccak_256 } from "@noble/hashes/sha3";
import { encodeRlp, getBytes } from "ethers";

import { verifyMptProof } from "../src/eth-state/mpt";
import { EthOperations, StateVerifyMode, verifyStateProof } from "../src/eth-state";
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

/** Build a single-leaf trie [encodedPath, value] keyed by keccak256(rawKey). */
function singleLeafTrie(rawKey: Uint8Array, value: Uint8Array): {
  root: Uint8Array;
  node: Uint8Array;
} {
  const keyHash = keccak_256(rawKey);
  const encodedPath = new Uint8Array(33);
  encodedPath[0] = 0x20; // leaf, even nibble count
  encodedPath.set(keyHash, 1);
  const node = getBytes(encodeRlp([encodedPath, value]));
  return { root: keccak_256(node), node };
}

describe("verifyStateProof — odd-length hex scalars", () => {
  it("verifies a storage slot whose value hex is odd-length (0x5)", () => {
    // Account leaf: nonce 5 (hex "5", odd), balance 0xabc (odd), so both
    // rlpEncodeAccount scalars exercise the even-length padding.
    const nonce = 5;
    const balance = Array.from({ length: 32 }, () => 0);
    balance[31] = 0x0a;
    balance[30] = 0x0b;
    balance[29] = 0x0c; // balance = 0x0c0b0a (still trims internally)

    const slotBytes = new Uint8Array(32); // slot index 0
    // Storage value 0x05 — minimal hex "5" is odd-length; padding -> "05".
    const value = new Uint8Array(32);
    value[31] = 0x05;
    const storageLeafValue = getBytes(encodeRlp("0x05"));
    const storage = singleLeafTrie(slotBytes, storageLeafValue);

    const address = new Uint8Array(20); // all zero
    // Account state [nonce, balance, storageRoot, codeHash].
    const accountState = {
      nonce,
      balance,
      storage_hash: Array.from(storage.root),
      code_hash: Array.from(keccak_256(new Uint8Array())),
    };
    // Build the account leaf with the SAME even-length scalar encoding the
    // verifier uses so the account-proof MPT walk succeeds.
    const balHex = Buffer.from(balance).toString("hex").replace(/^0+/, "");
    const balScalar = balHex.length === 0 ? "0x" : "0x" + (balHex.length % 2 ? "0" + balHex : balHex);
    const accLeaf = getBytes(
      encodeRlp([
        "0x05",
        balScalar,
        "0x" + Buffer.from(storage.root).toString("hex"),
        "0x" + Buffer.from(accountState.code_hash).toString("hex"),
      ]),
    );
    const account = singleLeafTrie(address, accLeaf);

    const proof: StateProof = {
      address: Array.from(address),
      block_number: 1,
      block_hash: Array.from({ length: 32 }, () => 0),
      state_root: Array.from(account.root),
      account_proof: {
        key: Array.from(keccak_256(address)),
        value: Array.from(accLeaf),
        proof_nodes: [Array.from(account.node)],
      },
      account_state: accountState,
      storage_proofs: [
        {
          slot: Array.from(slotBytes),
          value: Array.from(value),
          proof: {
            key: Array.from(keccak_256(slotBytes)),
            value: Array.from(storageLeafValue),
            proof_nodes: [Array.from(storage.node)],
          },
        },
      ],
    };

    // Before the fix this threw on the odd-length "0x5" RLP scalar.
    expect(() => verifyStateProof(proof)).not.toThrow();
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

describe("EthOperations", () => {
  const mockFetch = jest.fn();
  global.fetch = mockFetch as unknown as typeof fetch;

  // Minimal envelope: one account proof carrying one storage slot whose
  // value is 1. Verification is skipped via StateVerifyMode.Disabled.
  const envelope = {
    state_proofs: [
      {
        address: Array.from({ length: 20 }, () => 0),
        block_number: 1,
        block_hash: Array.from({ length: 32 }, () => 0),
        state_root: Array.from({ length: 32 }, () => 0),
        account_proof: { key: [], value: [], proof_nodes: [] },
        account_state: {
          nonce: 0,
          balance: [],
          storage_hash: Array.from({ length: 32 }, () => 0),
          code_hash: Array.from({ length: 32 }, () => 0),
        },
        storage_proofs: [
          {
            slot: Array.from({ length: 32 }, () => 0),
            value: [1],
            proof: { key: [], value: [], proof_nodes: [] },
          },
        ],
      },
    ],
  };

  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(envelope),
    } as Response);
  });

  it("withMode returns a new instance and leaves the original untouched", () => {
    const strict = new EthOperations("http://indexer:3032");
    const anchorOnly = strict.withMode(StateVerifyMode.AnchorOnly);

    expect(anchorOnly).not.toBe(strict);
    expect(anchorOnly).toBeInstanceOf(EthOperations);
    // The original still verifies strictly: the all-zero proof in the
    // envelope must fail its MPT walk.
    return expect(
      strict.getState("0x" + "11".repeat(20), [], 1),
    ).rejects.toThrow();
  });

  it("encodes slot indexes > 255 as full 32-byte big-endian words", async () => {
    const eth = new EthOperations("http://indexer:3032").withMode(
      StateVerifyMode.Disabled,
    );
    await eth.erc20TotalSupply("0x" + "11".repeat(20), 300, 1);

    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(body.slots).toEqual(["0x" + "00".repeat(30) + "012c"]);
  });

  it("rejects negative or non-integer slot indexes", async () => {
    const eth = new EthOperations("http://indexer:3032").withMode(
      StateVerifyMode.Disabled,
    );
    await expect(
      eth.erc20TotalSupply("0x" + "11".repeat(20), -1, 1),
    ).rejects.toThrow(/non-negative integer/);
    await expect(
      eth.erc20Balance("0x" + "11".repeat(20), "0x" + "22".repeat(20), 1.5, 1),
    ).rejects.toThrow(/non-negative integer/);
  });
});
