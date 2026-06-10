/**
 * Regression test for the AVL-balance false negative.
 *
 * A GroveDB query proof is a *partial* reconstruction of the tree: only the
 * queried path is expanded; sibling subtrees collapse to single hash nodes
 * (height 0). Such a reconstruction is legitimately unbalanced, so asserting the
 * AVL height-balance property in `executeOps()` produced false negatives —
 * valid proofs over large/deep subtrees were rejected with
 * "Expected proof to result in a valid AVL tree".
 *
 * `partial-proof-live.json` is a real, deep-subtree proof captured from a live
 * Willow indexer (subgrove `yieldnest-vaults-eth`, a single Deposit entity) that
 * the buggy verifier rejected. The existing Rust-generated fixtures only cover
 * small balanced trees, which is exactly why the bug shipped. The verifier must
 * now (a) recompute the committed root from this proof, and (b) still reject any
 * tampering.
 */
import * as fs from 'fs';
import * as path from 'path';

import { verifyGroveDBProof, hexToBytes, hashToHex } from '../src/grovedb';

const fx = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'fixtures', 'grovedb', 'partial-proof-live.json'),
    'utf8',
  ),
) as { proofHex: string; stateRootHex: string; key: string; path: string };

const norm = (h: string) => h.replace(/^0x/, '').toLowerCase();

describe('GroveDB partial-proof verification (AVL-balance regression)', () => {
  it('recomputes the committed root from a deep-subtree (unbalanced) partial proof', () => {
    const { rootHash, results } = verifyGroveDBProof(hexToBytes(fx.proofHex));
    expect(norm(hashToHex(rootHash))).toBe(norm(fx.stateRootHex));
    expect(results.length).toBeGreaterThan(0);
  });

  it('rejects a tampered proof (root binding still enforced)', () => {
    const bytes = hexToBytes(fx.proofHex);
    bytes[bytes.length >> 1] ^= 0xff; // flip one byte in the middle
    expect(() => verifyGroveDBProof(bytes)).toThrow();
  });
});
