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

  test('without the path check a renamed layer is refused as one no proven key holds', () => {
    // grovedb puts a lower layer only under a key its layer proves with a
    // value, so a layer under any other key is refused even without a path.
    for (const name of ['single-key', 'range-all', 'absent-key']) {
      const f = FIXTURES[name];
      expect(() => verifyGroveDBProof(hexToBytes(f.proof_renamed_layer))).toThrow(
        /a key this layer does not prove/,
      );
    }
  });

  test('a tree proven without its lower layer verifies, as grovedb returns it', () => {
    // proof_dropped_layer is byte for byte grovedb's proof of the Supply tree
    // element itself (no subquery on it): its value hash is the layered one,
    // combine_hash(value_hash(bytes), subtree root), so it is not a leaf check.
    const f = FIXTURES['single-key'];
    const bytes = hexToBytes(f.proof_dropped_layer);
    for (const deserializeElements of [true, false]) {
      const r = verifyGroveDBProof(bytes, { deserializeElements });
      expect(hashToHex(r.rootHash)).toBe(f.root);
      expect(r.results.length).toBe(1);
      expect(r.results[0].path.map((p) => new TextDecoder().decode(p))).toEqual(f.path.slice(0, 3));
      expect(new TextDecoder().decode(r.results[0].key)).toBe(f.path[3]);
      if (deserializeElements) expect(r.results[0].element?.type).toBe('Tree');
    }
    // At the tree's own path it verifies; at the path below it, it doesn't descend.
    expect(() => verifyGroveDBProof(bytes, { expectedPath: pathOf(f).slice(0, 3) })).not.toThrow();
    expect(() => verifyGroveDBProof(bytes, { expectedPath: pathOf(f) })).toThrow(/does not descend/);
  });

  test('a tree proven without its lower layer binds no document', async () => {
    const f = FIXTURES['single-key'];
    const parent = f.path.slice(0, 3);
    expect(await verifyItemProof(f.proof_dropped_layer, f.path[3], undefined, parent)).toBe(f.root);
    await expect(verifyItemProof(f.proof_dropped_layer, f.path[3], { a: 1 }, parent)).rejects.toThrow(
      /does not match the returned data/,
    );
    await expect(verifyQueryProof(f.proof_dropped_layer, [{ a: 1 }], { path: parent })).rejects.toThrow(
      /not committed by the proof/,
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
