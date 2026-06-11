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
 * `partial-proof-live.json` is produced by the Rust generator in
 * `tests/fixtures/grovedb/generator/` (pinned to the GroveDB release the chain
 * uses): a single-key proof into an entity tree with a few hundred keys at
 * `subgroves/demo-vault-events/indexed/Deposit`, so the partial reconstruction
 * is deep and unbalanced — exactly the shape the buggy verifier rejected. The
 * other Rust-generated fixtures only cover small balanced trees, which is why
 * the bug shipped. The verifier must now (a) recompute the committed root from
 * this proof, and (b) still reject any tampering.
 */
import * as fs from 'fs';
import * as path from 'path';

import {
  verifyGroveDBProof,
  decodeGroveDBProof,
  executeOps,
  MerkDecoder,
  Tree,
  LayerProof,
  hexToBytes,
  hashToHex,
} from '../src/grovedb';

const fx = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'fixtures', 'grovedb', 'partial-proof-live.json'),
    'utf8',
  ),
) as { proofHex: string; stateRootHex: string; key: string; path: string };

const norm = (h: string) => h.replace(/^0x/, '').toLowerCase();

function structuralHeight(tree: Tree | undefined): number {
  if (!tree) return 0;
  return 1 + Math.max(structuralHeight(tree.left?.tree), structuralHeight(tree.right?.tree));
}

/** Root-node imbalance of each layer's reconstructed merk tree, recursively. */
function layerRootImbalances(layer: LayerProof): number[] {
  const imbalances: number[] = [];
  if (layer.merkProof.length > 0) {
    const tree = executeOps(new MerkDecoder(layer.merkProof), false);
    imbalances.push(
      Math.abs(structuralHeight(tree.left?.tree) - structuralHeight(tree.right?.tree)),
    );
  }
  for (const lower of layer.lowerLayers.values()) {
    imbalances.push(...layerRootImbalances(lower));
  }
  return imbalances;
}

describe('GroveDB partial-proof verification (AVL-balance regression)', () => {
  it('recomputes the committed root from a deep-subtree (unbalanced) partial proof', () => {
    const { rootHash, results } = verifyGroveDBProof(hexToBytes(fx.proofHex));
    expect(norm(hashToHex(rootHash))).toBe(norm(fx.stateRootHex));
    expect(results.length).toBeGreaterThan(0);
  });

  it('fixture is genuinely unbalanced — it would have tripped the old AVL assertion', () => {
    const decoded = decodeGroveDBProof(hexToBytes(fx.proofHex));
    const imbalances = layerRootImbalances(decoded.proof.rootLayer);
    expect(Math.max(...imbalances)).toBeGreaterThan(1);
  });

  it('rejects a tampered proof (root binding still enforced)', () => {
    const bytes = hexToBytes(fx.proofHex);
    bytes[bytes.length >> 1] ^= 0xff; // flip one byte in the middle
    expect(() => verifyGroveDBProof(bytes)).toThrow();
  });
});
