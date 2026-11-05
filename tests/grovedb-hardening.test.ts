/**
 * Hardening regressions for the GroveDB verifier: malformed input must fail
 * with a clean, typed error (or a root mismatch) — never silently produce a
 * plausible-looking result.
 */
import * as fs from 'fs';
import * as path from 'path';

import {
  verifyGroveDBProof,
  verifyProofAgainstRoot,
  quickVerify,
  executeMerkProof,
  decodeGroveDBProof,
  decodeMerkOps,
  executeMerkProofWithQuery,
  hexToBytes,
  hashToHex,
  valueHash,
  hashEquals,
  encodeVarint,
  decodeVarint,
  decodeVarint64,
  GroveDBVerificationError,
  VarintError,
} from '../src/grovedb';
import { verifyItemProof, verifyQueryProof } from '../src/proof';

const fx = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', 'partial-proof-live.json'), 'utf8'),
) as { proofHex: string; stateRootHex: string };

const norm = (h: string) => h.replace(/^0x/, '').toLowerCase();

describe('truncated input', () => {
  it('rejects every truncation of a valid GroveDB proof', () => {
    const full = hexToBytes(fx.proofHex);
    // Sweep truncation points (every 7 bytes keeps the suite fast while still
    // landing inside varints, length prefixes, hashes, and op payloads).
    for (let len = 0; len < full.length; len += 7) {
      expect(() => verifyGroveDBProof(full.slice(0, len))).toThrow(GroveDBVerificationError);
    }
  });

  it('never lets a truncated merk proof yield the committed root', () => {
    // Truncations of the inner merk-proof bytes can land exactly between ops,
    // which decodes as a shorter-but-well-formed op list. The security property
    // is that no truncation reproduces the committed root hash.
    const proof = decodeGroveDBProof(hexToBytes(fx.proofHex));
    const merk = proof.proof.rootLayer.merkProof;
    for (let len = 0; len < merk.length; len += 3) {
      const truncated = merk.slice(0, len);
      let root: string | null = null;
      try {
        const { executeMerkProofWithQuery } = require('../src/grovedb/executor');
        root = hashToHex(executeMerkProofWithQuery(truncated).rootHash);
      } catch (e) {
        expect(
          e instanceof GroveDBVerificationError || e instanceof VarintError,
        ).toBe(true);
      }
      if (root !== null) {
        expect(root).not.toBe(norm(fx.stateRootHex));
      }
    }
  });

  it('throws a clean error when a KV node is cut off mid-header', () => {
    // 0x03 = Push(KV) with no key length byte following.
    expect(() => decodeMerkOps(new Uint8Array([0x03]))).toThrow(
      'Unexpected end of data reading key length',
    );
    // 0x07 = Push(KVValueHashFeatureType) cut off before the feature byte.
    const kvNoFeature = new Uint8Array([0x07, 0x01, 0x61, 0x00, 0x01, 0x62, ...new Array(32).fill(0)]);
    expect(() => decodeMerkOps(kvNoFeature)).toThrow('Unexpected end of data reading feature type');
  });
});

describe('varint bounds', () => {
  it('round-trips values at and beyond 2^31 (32-bit bitwise ops would corrupt these)', () => {
    for (const v of [2 ** 31 - 1, 2 ** 31, 2 ** 32 + 5, 2 ** 45, Number.MAX_SAFE_INTEGER]) {
      expect(decodeVarint(encodeVarint(v)).value).toBe(v);
    }
  });

  it('rejects varints that exceed Number.MAX_SAFE_INTEGER instead of returning a wrong value', () => {
    // 2^60: eight 0x80-continuation bytes then a final byte.
    const huge = new Uint8Array([0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x10]);
    expect(() => decodeVarint(huge)).toThrow(VarintError);
  });

  it('throws (never returns NaN) on a long all-0x80 run that would overflow the shift', () => {
    // 12 continuation bytes: 2**shift would reach Infinity and 0*Infinity=NaN.
    const allContinuation = new Uint8Array(new Array(12).fill(0x80));
    expect(() => decodeVarint(allContinuation)).toThrow(VarintError);
    // And it is a real throw, not a NaN value slipping past the guard.
    let decoded: number | undefined;
    try {
      decoded = decodeVarint(allContinuation).value;
    } catch {
      decoded = -1;
    }
    expect(Number.isNaN(decoded)).toBe(false);
    expect(decoded).toBe(-1);
  });

  it('decodes u64::MAX and rejects anything past it', () => {
    const u64max = new Uint8Array([...new Array(9).fill(0xff), 0x01]);
    expect(decodeVarint64(u64max).value).toBe((1n << 64n) - 1n);

    const past = new Uint8Array([...new Array(9).fill(0xff), 0x7f]);
    expect(() => decodeVarint64(past)).toThrow('exceeds u64 range');

    const eleven = new Uint8Array(new Array(11).fill(0x80));
    expect(() => decodeVarint64(eleven)).toThrow('too long');
  });
});

describe('layer recursion cap', () => {
  it('rejects pathologically nested layer proofs instead of overflowing the stack', () => {
    // Craft: variant 0, then N nested layers of (empty merk, 1 entry, empty key),
    // an innermost empty layer, and the trailing ProveOptions bool.
    const DEPTH = 80;
    const bytes: number[] = [0x00];
    for (let i = 0; i < DEPTH; i++) bytes.push(0x00, 0x01, 0x00);
    bytes.push(0x00, 0x00); // innermost layer: empty merk, no lower layers
    bytes.push(0x00); // decrease_limit_on_empty_sub_query_result = false
    expect(() => decodeGroveDBProof(new Uint8Array(bytes))).toThrow(/maximum depth/);
  });
});

describe('valid proof still verifies after hardening', () => {
  it('recomputes the committed root from the live fixture', () => {
    const { rootHash, results } = verifyGroveDBProof(hexToBytes(fx.proofHex));
    expect(norm(hashToHex(rootHash))).toBe(norm(fx.stateRootHex));
    expect(results.length).toBeGreaterThan(0);
  });
});

describe('value-bearing leaf binding', () => {
  // Encode a single-node Merk proof: Push(KVValueHash(key, value, valueHash)).
  // The node hash for this variant is kv_digest_to_kv_hash(key, valueHash) —
  // the `value` bytes never enter the root — so a server can swap `value`
  // freely while keeping the committed `valueHash` and an identical root.
  const encodeKVValueHashLeaf = (
    key: Uint8Array,
    value: Uint8Array,
    valHash: Uint8Array,
  ): Uint8Array =>
    new Uint8Array([
      0x04, // OP_PUSH_KVVALUEHASH
      key.length,
      ...key,
      (value.length >> 8) & 0xff,
      value.length & 0xff,
      ...value,
      ...valHash,
    ]);

  // Wrap a single merk proof as a complete GroveDBProof V0 (bincode 2):
  // variant 0, root layer = (merk byteVec, empty lower-layer map), prove
  // options bool = false. The merk proof here is well under 251 bytes, so the
  // bincode varint length is a single byte.
  const wrapAsGroveDBProof = (merk: Uint8Array): Uint8Array =>
    // trailing 0x01 = decrease_limit_on_empty_sub_query_result, the chain's default
    // (every real proof carries it; the verifier pins it)
    new Uint8Array([0x00, merk.length, ...merk, 0x00, 0x01]);

  const key = new TextEncoder().encode('balance');
  const realValue = new TextEncoder().encode('1000');
  const evilValue = new TextEncoder().encode('9999999');
  const committedHash = valueHash(realValue);

  it('produces a byte-identical root for an honest and a forged leaf', () => {
    const honestMerk = encodeKVValueHashLeaf(key, realValue, committedHash);
    const forgedMerk = encodeKVValueHashLeaf(key, evilValue, committedHash);

    // Sanity: the forgery keeps the value bytes distinct from the committed one.
    expect(hashEquals(valueHash(evilValue), committedHash)).toBe(false);

    // Both proofs reconstruct to the same root — a root-only check is fooled.
    const honestRoot = hashToHex(executeMerkProofWithQuery(honestMerk).rootHash);
    const forgedRoot = hashToHex(executeMerkProofWithQuery(forgedMerk).rootHash);
    expect(forgedRoot).toBe(honestRoot);
  });

  it('rejects a forged leaf whose value does not hash to its committed valueHash', () => {
    const forged = wrapAsGroveDBProof(encodeKVValueHashLeaf(key, evilValue, committedHash));
    expect(() => verifyGroveDBProof(forged)).toThrow(GroveDBVerificationError);
    expect(() => verifyGroveDBProof(forged)).toThrow(/does not hash to its committed valueHash/);
  });

  it('surfaces tree-shaped bytes on a value hash only as a tree, which binds nothing', async () => {
    // A tree's value hash can't be re-derived from its bytes alone, so the
    // leaf check skips tree elements; their bytes must then never stand for a
    // value. Tree(Some("x"), None) in place of the committed Item:
    const treeBytes = new Uint8Array([0x02, 0x01, 0x01, 0x78, 0x00]);
    const proof = wrapAsGroveDBProof(encodeKVValueHashLeaf(key, treeBytes, committedHash));
    // Unbound: surfaced as a subtree with neither bytes nor an element.
    const { results } = verifyGroveDBProof(proof);
    expect(results.map((r) => [r.tree, r.value, r.element])).toEqual([[true, null, null]]);
    const proofHex = Buffer.from(proof).toString('hex');
    await expect(verifyItemProof(proofHex, 'balance', 1000)).rejects.toThrow(/not the KV node/);
    await expect(verifyItemProof(proofHex, 'balance', treeBytes)).rejects.toThrow(/not the KV node/);
    await expect(verifyQueryProof(proofHex, [{ balance: 1000 }])).rejects.toThrow(/not committed/);
  });

  it('accepts the honest leaf and surfaces the real value at the same root', () => {
    const honestMerk = encodeKVValueHashLeaf(key, realValue, committedHash);
    const honest = wrapAsGroveDBProof(honestMerk);
    const { rootHash, results } = verifyGroveDBProof(honest, { deserializeElements: false });
    expect(hashToHex(rootHash)).toBe(hashToHex(executeMerkProofWithQuery(honestMerk).rootHash));
    const match = results.find((r) => r.value && hashEquals(r.value, realValue));
    expect(match).toBeDefined();
  });
});

describe('opaque proof nodes', () => {
  // A Hash node stands for a whole pruned subtree: merk's Tree::hash returns
  // its stored hash and ignores children, so nothing may be attached to it.
  const bob = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', 'nested_single_key_user_bob.json'), 'utf8'),
  ) as { path: string[]; key: string; proof_hex: string; expected_root_hex: string };
  const enc = (s: string) => new TextEncoder().encode(s);
  const bobPath = bob.path.map(enc);

  // The fixture's root as a Hash node with a made-up subtree under it, down to
  // a different value for user:bob at the fixture's path.
  const HASH_PARENT =
    '005401b3919503bca50efc2b8ae6fc643d4c57a2c527e04b0bfa102b9079c3084a0269040973756267726f76657300050201017800908ee3ea4f90b0786f56fdb9e4ee07aca782ade89e30fc861aab53d85076968011010973756267726f7665732f04066d792d73756200050201017800c0443d5e00404774059bfea49101762310601b326a01442b418c493fbd5a9ed201066d792d7375622d04046461746100050201017800624d3ac133927b2263aa2c62ffd1e63a4069944eef70edaf6a0bdd2276653a9b010464617461240308757365723a626f62001800157b2262616c616e6365223a3939393939393939397d000001';

  const hashNode = [0x01, ...new Array(32).fill(0xab)]; // Push(Hash)
  const kvNode = [0x03, 1, 1, 0, 0]; // Push(KV(key 0x01, empty value))
  const kvHashNode = [0x02, ...new Array(32).fill(0xcd)]; // Push(KVHash)
  const kvDigestNode = [0x05, 1, 2, ...new Array(32).fill(0xef)]; // Push(KVDigest(key 0x02))

  it('refuses a proof that hangs a subtree under a Hash node', () => {
    const forged = hexToBytes(HASH_PARENT);
    expect(() =>
      verifyProofAgainstRoot(forged, hexToBytes(bob.expected_root_hex), { expectedPath: bobPath }),
    ).toThrow(/hash node can't have children/);
    expect(() => verifyGroveDBProof(forged)).toThrow(GroveDBVerificationError);
    expect(() => quickVerify(forged)).toThrow(/hash node can't have children/);
  });

  it.each([
    ['Child', [...hashNode, ...kvNode, 0x11]],
    ['Parent', [...kvNode, ...hashNode, 0x10]],
    ['ParentInverted', [...kvNode, ...hashNode, 0x12]],
    ['ChildInverted', [...hashNode, ...kvNode, 0x13]],
  ])('refuses %s attaching a child to a Hash node', (_op, ops) => {
    expect(() => executeMerkProof(new Uint8Array(ops as number[]))).toThrow(
      /hash node can't have children/,
    );
  });

  it('lets KVHash and KVDigest nodes take children, which their hashes cover', () => {
    expect(() => executeMerkProof(new Uint8Array([...kvNode, ...kvHashNode, 0x10]))).not.toThrow();
    expect(() => executeMerkProof(new Uint8Array([...kvNode, ...kvDigestNode, 0x10]))).not.toThrow();
    // A Hash node as a child is fine: it is a pruned sibling.
    expect(() => executeMerkProof(new Uint8Array([...hashNode, ...kvNode, 0x10]))).not.toThrow();
  });

  it('still verifies the genuine proof at the same root', () => {
    const r = verifyProofAgainstRoot(hexToBytes(bob.proof_hex), hexToBytes(bob.expected_root_hex), {
      expectedPath: bobPath,
    });
    const hit = r.results.find((x) => new TextDecoder().decode(x.key) === bob.key);
    expect(hit).toBeDefined();
  });
});
