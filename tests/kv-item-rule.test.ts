/**
 * A key's value is the payload of the Item grovedb proves at the key, as a
 * `KV` node. A reference at the key is proven as a `KVRefValueHash` node
 * whose value is the element it points to, which is not stored at the key;
 * an Item given as another node is not how grovedb proves one. Every check
 * of one key's value takes it from the `KV` node alone.
 */
import { combineHash, hexToBytes, kvDigestToKvHash, nodeHash, valueHash, NULL_HASH } from '../src/grovedb';
import { GroveDBProofVerifier, subgroveDataPath, verifyItemProof } from '../src/proof';
import { ProofVerifier } from '../src/light-client/verifier';
import { chainProof, enc, hex, itemElement, op, oneItemLayer } from './helpers/grove-proof';

const PATH = subgroveDataPath('s1');
const DOC = { owner: 'alice', n: 1 };
const PAYLOAD = enc(JSON.stringify(DOC));
const KEY = enc('k');

/** The proofs of `s1`'s key `k` holding DOC's payload, each with its root (hex). */
function leaves() {
  const element = itemElement(PAYLOAD);
  // A reference at the key, whose target holds DOC.
  const refHash = valueHash(enc('a reference element'));
  const reference = {
    ops: Uint8Array.from([
      0x06, KEY.length, ...KEY, element.length >> 8, element.length & 0xff, ...element, ...refHash,
    ]),
    root: nodeHash(kvDigestToKvHash(KEY, combineHash(refHash, valueHash(element))), NULL_HASH, NULL_HASH),
  };
  // The Item given as a KVValueHash node (same root as KV).
  const valueHashNode = {
    ops: Uint8Array.from(op.kvValueHash(KEY, element, valueHash(element))),
    root: nodeHash(kvDigestToKvHash(KEY, valueHash(element)), NULL_HASH, NULL_HASH),
  };
  const kv = oneItemLayer('k', PAYLOAD);
  const prove = (leaf: { ops: Uint8Array; root: Uint8Array }) => {
    const { proof, root } = chainProof(PATH, leaf.ops, leaf.root, KEY);
    return { proof: hex(proof), root: hex(root) };
  };
  return { reference: prove(reference), valueHashNode: prove(valueHashNode), kv: prove(kv) };
}

describe("one key's value is taken only from the KV node holding an Item", () => {
  const { reference, valueHashNode, kv } = leaves();

  it('verifyItemProof and GroveDBProofVerifier.verifyItemProof', async () => {
    for (const other of [reference, valueHashNode]) {
      await expect(verifyItemProof(other.proof, 'k', DOC, PATH)).rejects.toThrow(/not the KV node/);
      await expect(verifyItemProof(other.proof, 'k', PAYLOAD, PATH)).rejects.toThrow(/not the KV node/);
      const result = await new GroveDBProofVerifier().verifyItemProof(other.proof, 'k', DOC, PATH);
      expect(result.valid).toBe(false);
    }
    await expect(verifyItemProof(kv.proof, 'k', DOC, PATH)).resolves.toBe(kv.root);
    await expect(new GroveDBProofVerifier().verifyItemProof(kv.proof, 'k', DOC, PATH)).resolves.toMatchObject({
      valid: true,
      rootHash: kv.root,
    });
  });

  it('ProofVerifier.verifyInclusionProof', async () => {
    const verifier = new ProofVerifier();
    const path = PATH.map(enc);
    for (const other of [reference, valueHashNode]) {
      expect(
        await verifier.verifyInclusionProof(KEY, PAYLOAD, hexToBytes(other.proof), hexToBytes(other.root), path),
      ).toBe(false);
    }
    expect(await verifier.verifyInclusionProof(KEY, PAYLOAD, hexToBytes(kv.proof), hexToBytes(kv.root), path)).toBe(
      true,
    );
  });
});
