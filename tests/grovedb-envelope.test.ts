/**
 * Envelope-descent regression tests over REAL grovedb 3.1.0 proofs
 * (tests/fixtures/grovedb/envelope-real-proofs.json, minted by
 * willow/zkvm/willow-state-guest/genfix over the Willow indexed-data layout
 * [subgroves, aave-v3-lending, indexed, Supply]).
 *
 * The gap: grovedb's verifier looks the next layer up by the envelope's
 * `lower_layers` map key, which is not hash-bound. Rename or drop the entry
 * for a subtree on the query path and the proof verifies to the SAME root with
 * an EMPTY result set — "K = V" becomes "K is absent". `checkEnvelope` closes
 * it by requiring a layer for every path segment.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  verifyGroveDBProof,
  decodeGroveDBProof,
  checkEnvelope,
  hexToBytes,
  hashToHex,
} from '../src/grovedb';
import { verifyItemProof, verifyQueryProof } from '../src/proof';

interface Fixture {
  root: string;
  path: string[];
  key?: string;
  proof: string;
  proof_renamed_layer: string;
  proof_dropped_layer: string;
  proof_opts_flipped: string;
}

const FIXTURES: Record<string, Fixture> = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', 'envelope-real-proofs.json'), 'utf8'),
);
const enc = (s: string) => new TextEncoder().encode(s);
const pathOf = (f: Fixture) => f.path.map(enc);

describe('GroveDB envelope descent', () => {
  test('real proofs verify to the root at their path', () => {
    for (const [name, n] of [['single-key', 1], ['range-all', 5], ['absent-key', 0], ['range-limit-2', 2]] as const) {
      const f = FIXTURES[name];
      const r = verifyGroveDBProof(hexToBytes(f.proof), { expectedPath: pathOf(f) });
      expect(hashToHex(r.rootHash)).toBe(f.root);
      expect(r.results.length).toBe(n);
    }
  });

  test('without the path check the renamed layer is caught only by leaf binding', () => {
    // The TS verifier already refused this: a tree node with no lower layer
    // falls into the leaf branch, and its value bytes do not hash to the
    // committed valueHash. The path check turns that incidental catch into a
    // stated property with a precise error.
    const f = FIXTURES['single-key'];
    expect(() => verifyGroveDBProof(hexToBytes(f.proof_renamed_layer))).toThrow(
      /does not hash to its committed valueHash/,
    );
  });

  test('renamed lower layer is rejected at the query path', () => {
    for (const name of ['single-key', 'range-all', 'absent-key']) {
      const f = FIXTURES[name];
      expect(() => verifyGroveDBProof(hexToBytes(f.proof_renamed_layer), { expectedPath: pathOf(f) })).toThrow(
        /does not descend/,
      );
      expect(() => checkEnvelope(decodeGroveDBProof(hexToBytes(f.proof_renamed_layer)), pathOf(f))).toThrow();
    }
  });

  test('dropped lower layer is rejected at the query path', () => {
    for (const name of ['single-key', 'range-all', 'absent-key']) {
      const f = FIXTURES[name];
      expect(() => verifyGroveDBProof(hexToBytes(f.proof_dropped_layer), { expectedPath: pathOf(f) })).toThrow(
        /does not descend/,
      );
    }
  });

  test('a shorter or longer path is rejected', () => {
    const f = FIXTURES['single-key'];
    expect(() => verifyGroveDBProof(hexToBytes(f.proof), { expectedPath: pathOf(f).slice(0, 3) })).toThrow(
      /unexpected lower layers/,
    );
    expect(() => verifyGroveDBProof(hexToBytes(f.proof), { expectedPath: [...pathOf(f), enc('x')] })).toThrow(
      /does not descend/,
    );
  });

  test('non-default prove_options is rejected even without a path', () => {
    const f = FIXTURES['single-key'];
    expect(() => verifyGroveDBProof(hexToBytes(f.proof_opts_flipped))).toThrow(/prove_options/);
  });

  test('verifyItemProof descends when given the path', async () => {
    const f = FIXTURES['single-key'];
    const root = await verifyItemProof(f.proof, f.key!, undefined, f.path);
    expect(root).toBe(f.root);
    await expect(verifyItemProof(f.proof_renamed_layer, f.key!, undefined, f.path)).rejects.toThrow(
      /does not descend/,
    );
    await expect(verifyItemProof(f.proof_dropped_layer, f.key!, undefined, f.path)).rejects.toThrow(
      /does not descend/,
    );
  });

  test('verifyQueryProof descends when options.path is given', async () => {
    const f = FIXTURES['range-all'];
    expect(await verifyQueryProof(f.proof, [], { path: f.path })).toBe(f.root);
    await expect(verifyQueryProof(f.proof_renamed_layer, [], { path: f.path })).rejects.toThrow(/does not descend/);
  });
});
