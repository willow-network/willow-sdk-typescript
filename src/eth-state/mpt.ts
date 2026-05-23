/**
 * Minimal Ethereum Merkle Patricia Trie inclusion verifier.
 *
 * Walks an EIP-1186-shaped proof from a known root to a key's leaf and
 * checks the recovered leaf value matches the expected RLP encoding.
 * Handles branch (17-element), leaf, and extension nodes. Does not
 * handle inline-embedded nodes (sub-32-byte nodes packed into a parent
 * slot rather than referenced by hash) — those don't occur at the
 * depths we serve from `eth_getProof` for live mainnet state.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { decodeRlp, getBytes, hexlify } from "ethers";

/** RLP-decoded MPT node: branch = 17 entries, leaf/extension = 2 entries. */
type RlpNode = Uint8Array | RlpNode[];

export interface MptVerifyResult {
  ok: boolean;
  error?: string;
}

/**
 * Verify `expectedValue` is found at `keyHash` in the trie rooted at `root`.
 *
 * @param root - 32-byte root hash.
 * @param keyHash - 32-byte keccak256(originalKey).
 * @param expectedValue - RLP-encoded value at the leaf.
 * @param proofNodes - Ordered RLP-encoded nodes from root to leaf.
 */
export function verifyMptProof(
  root: Uint8Array,
  keyHash: Uint8Array,
  expectedValue: Uint8Array,
  proofNodes: Uint8Array[],
): MptVerifyResult {
  if (root.length !== 32) {
    return { ok: false, error: `root must be 32 bytes, got ${root.length}` };
  }
  if (keyHash.length !== 32) {
    return { ok: false, error: `key must be 32 bytes, got ${keyHash.length}` };
  }
  if (proofNodes.length === 0) {
    return { ok: false, error: "proof is empty" };
  }

  const nibbles = bytesToNibbles(keyHash);
  let expected: Uint8Array = root;
  let nibbleIdx = 0;

  for (let i = 0; i < proofNodes.length; i++) {
    const node = proofNodes[i];
    const hash = keccak_256(node);
    if (!bytesEqual(hash, expected)) {
      return {
        ok: false,
        error: `node ${i}: hash mismatch (got ${hexlify(hash)}, expected ${hexlify(expected)})`,
      };
    }

    let decoded: RlpNode;
    try {
      decoded = decodeRlp(node) as RlpNode;
    } catch (e) {
      return { ok: false, error: `node ${i}: rlp decode failed: ${e}` };
    }
    if (!Array.isArray(decoded)) {
      return { ok: false, error: `node ${i}: rlp root is not a list` };
    }

    if (decoded.length === 17) {
      // Branch node.
      if (nibbleIdx === nibbles.length) {
        // Key exhausted → terminator slot.
        const value = asBytes(decoded[16]);
        return checkValue(value, expectedValue);
      }
      const next = decoded[nibbles[nibbleIdx++]];
      const nextBytes = asBytes(next);
      if (nextBytes.length === 0) {
        // Empty slot → key not present. Treat as mismatch unless caller
        // explicitly wanted an absence proof (not exposed in V1).
        return checkValue(new Uint8Array(), expectedValue);
      }
      if (nextBytes.length !== 32) {
        return {
          ok: false,
          error: `node ${i}: inline-embedded child not supported (len ${nextBytes.length})`,
        };
      }
      expected = nextBytes;
    } else if (decoded.length === 2) {
      const encodedPath = asBytes(decoded[0]);
      const { path, isLeaf } = decodeCompactPath(encodedPath);
      const remaining = nibbles.slice(nibbleIdx);
      if (path.length > remaining.length || !nibbleSliceEquals(path, remaining, path.length)) {
        return checkValue(new Uint8Array(), expectedValue);
      }
      nibbleIdx += path.length;
      const second = decoded[1];
      if (isLeaf) {
        if (nibbleIdx !== nibbles.length) {
          return checkValue(new Uint8Array(), expectedValue);
        }
        return checkValue(asBytes(second), expectedValue);
      }
      // Extension.
      const ref = asBytes(second);
      if (ref.length !== 32) {
        return {
          ok: false,
          error: `node ${i}: inline-embedded extension child not supported (len ${ref.length})`,
        };
      }
      expected = ref;
    } else {
      return {
        ok: false,
        error: `node ${i}: unexpected RLP shape (len ${decoded.length})`,
      };
    }
  }

  return { ok: false, error: "proof exhausted without reaching leaf" };
}

function checkValue(actual: Uint8Array, expected: Uint8Array): MptVerifyResult {
  if (bytesEqual(actual, expected)) {
    return { ok: true };
  }
  return {
    ok: false,
    error: `leaf value mismatch (got ${hexlify(actual)}, expected ${hexlify(expected)})`,
  };
}

function bytesToNibbles(b: Uint8Array): number[] {
  const out = new Array<number>(b.length * 2);
  for (let i = 0; i < b.length; i++) {
    out[2 * i] = (b[i] >> 4) & 0x0f;
    out[2 * i + 1] = b[i] & 0x0f;
  }
  return out;
}

function nibbleSliceEquals(a: number[], b: number[], len: number): boolean {
  for (let i = 0; i < len; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * MPT compact-encoded path → (nibbles, isLeaf). Top nibble of the first
 * byte tells us node type and whether the path has an odd nibble count:
 *   0x0_ extension, even   | 0x1_ extension, odd  (low nibble starts path)
 *   0x2_ leaf, even        | 0x3_ leaf, odd       (low nibble starts path)
 */
function decodeCompactPath(encoded: Uint8Array): { path: number[]; isLeaf: boolean } {
  if (encoded.length === 0) {
    return { path: [], isLeaf: false };
  }
  const first = encoded[0];
  const flag = (first >> 4) & 0x0f;
  const isLeaf = flag >= 2;
  const odd = (flag & 1) === 1;
  const nibbles: number[] = [];
  if (odd) {
    nibbles.push(first & 0x0f);
  }
  for (let i = 1; i < encoded.length; i++) {
    nibbles.push((encoded[i] >> 4) & 0x0f);
    nibbles.push(encoded[i] & 0x0f);
  }
  return { path: nibbles, isLeaf };
}

function asBytes(v: RlpNode): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) {
    // Nested arrays shouldn't appear in well-formed proofs at the spots
    // where we expect bytes; treat as empty.
    return new Uint8Array();
  }
  // ethers returns hex strings from decodeRlp for byte leaves; normalize.
  if (typeof v === "string") return getBytes(v);
  return new Uint8Array();
}
