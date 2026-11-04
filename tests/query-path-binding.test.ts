/**
 * A proof binds what it proves to a path: a query's documents must be proven
 * at the queried path, a key's value or absence at the key's path.
 *
 * The state below is built as grovedb builds one (tests/helpers/grove-proof):
 * three subgroves under `subgroves`, A and B with data and C with an empty
 * data tree. Every proof here verifies to that one honest root; the ones a
 * malicious API could send carry another subgrove's data, or a value at a
 * prefix of the path, beside (or instead of) the queried data.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  verifyGroveDBProof,
  verifyKeyAbsence,
  deserializeElement,
  hexToBytes,
  hashToHex,
  valueHash,
} from '../src/grovedb';
import { verifyItemProof, verifyQueryProof, verifyQueryResponse, subgroveDataPath } from '../src/proof';
import { ProofVerifier } from '../src/light-client/verifier';
import { WillowData, extendQueryResponse } from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';
import {
  Merk,
  LayerProof,
  enc,
  groveProof,
  hex,
  itemElement,
  op,
  pathProof,
  treeElement,
} from './helpers/grove-proof';

const DOC_A1 = { owner: 'alice', n: 1 };
const DOC_A2 = { owner: 'alice', n: 2 };
const DOC_B1 = { owner: 'mallory', n: 999 };
const META = { note: 'subgrove metadata' };

const dataA = new Merk([
  { key: 'a1', item: JSON.stringify(DOC_A1) },
  { key: 'a2', item: JSON.stringify(DOC_A2) },
]);
const dataB = new Merk([{ key: 'b1', item: JSON.stringify(DOC_B1) }]);
const sgA = new Merk([
  { key: 'data', tree: dataA },
  { key: 'meta', item: JSON.stringify(META) },
]);
const sgB = new Merk([{ key: 'data', tree: dataB }]);
const sgC = new Merk([{ key: 'data', tree: new Merk([]) }]);
const subgroves = new Merk([
  { key: 'sg-a', tree: sgA },
  { key: 'sg-b', tree: sgB },
  { key: 'sg-c', tree: sgC },
]);
const state = new Merk([{ key: 'subgroves', tree: subgroves }]);
const ROOT = hex(state.rootHash());

const PATH_A = subgroveDataPath('sg-a');
const PATH_B = subgroveDataPath('sg-b');
const PATH_C = subgroveDataPath('sg-c');
const bytesOf = (p: string[]) => p.map(enc);

/** The honest proof of a query on `path` revealing `reveal`. */
const honest = (p: string[], reveal: string[]) => groveProof(pathProof(state, p, reveal));

/** The root layer and `subgroves` layer revealing `ids`, with these layers under them. */
function underSubgroves(ids: string[], lower: Array<[string, LayerProof]>): Uint8Array {
  return groveProof({
    merk: state.prove(['subgroves']),
    lower: [['subgroves', { merk: subgroves.prove(ids), lower }]],
  });
}

/** A query on A answered with A's data and B's beside it. */
const BOTH = underSubgroves(
  ['sg-a', 'sg-b'],
  [
    ['sg-a', pathProof(sgA, ['data'], ['a1', 'a2'])],
    ['sg-b', pathProof(sgB, ['data'], ['b1'])],
  ],
);

/** A query on A answered with B's data alone. */
const ONLY_B = underSubgroves(['sg-b'], [['sg-b', pathProof(sgB, ['data'], ['b1'])]]);

/** A query on A whose answer also reveals the `meta` item one level up. */
const WITH_META = underSubgroves(
  ['sg-a'],
  [['sg-a', { merk: sgA.prove(['data', 'meta']), lower: [['data', { merk: dataA.prove(['a1', 'a2']) }]] }]],
);

describe('the synthetic state', () => {
  it('every proof verifies to the one honest root', () => {
    for (const proof of [honest(PATH_A, ['a1', 'a2']), honest(PATH_B, ['b1']), honest(PATH_C, []), BOTH, ONLY_B, WITH_META]) {
      expect(hashToHex(verifyGroveDBProof(proof).rootHash)).toBe(ROOT);
    }
  });
});

describe('query documents bind only at the queried path', () => {
  it('an honest proof binds its documents at the path', async () => {
    await expect(verifyQueryProof(hex(honest(PATH_A, ['a1', 'a2'])), [DOC_A1, DOC_A2], { path: PATH_A })).resolves.toBe(ROOT);
    await expect(verifyQueryProof(hex(honest(PATH_B, ['b1'])), [DOC_B1], { path: PATH_B })).resolves.toBe(ROOT);
  });

  it("refuses another subgrove's data beside the queried one", async () => {
    // Without the path, B's document binds to a value the proof proves.
    await expect(verifyQueryProof(hex(BOTH), [DOC_B1])).resolves.toBe(ROOT);
    await expect(verifyQueryProof(hex(BOTH), [DOC_B1], { path: PATH_A })).rejects.toThrow(/off the query path/);
    await expect(verifyQueryProof(hex(BOTH), [DOC_A1], { path: PATH_A })).rejects.toThrow(/off the query path/);
  });

  it("refuses another subgrove's data instead of the queried one", async () => {
    await expect(verifyQueryProof(hex(ONLY_B), [DOC_B1])).resolves.toBe(ROOT);
    await expect(verifyQueryProof(hex(ONLY_B), [DOC_B1], { path: PATH_A })).rejects.toThrow(/off the query path/);
    await expect(verifyQueryProof(hex(ONLY_B), [], { path: PATH_A })).rejects.toThrow(/off the query path/);
  });

  it('binds no document to a value proven above the path', async () => {
    await expect(verifyQueryProof(hex(WITH_META), [META])).resolves.toBe(ROOT);
    await expect(verifyQueryProof(hex(WITH_META), [META], { path: PATH_A })).rejects.toThrow(/not committed by the proof/);
    await expect(verifyQueryProof(hex(WITH_META), [DOC_A1, DOC_A2], { path: PATH_A })).resolves.toBe(ROOT);
  });

  it('takes path segments as bytes too', async () => {
    await expect(verifyQueryProof(hex(BOTH), [DOC_B1], { path: bytesOf(PATH_A) })).rejects.toThrow(/off the query path/);
    await expect(verifyQueryProof(hex(honest(PATH_A, ['a1'])), [DOC_A1], { path: bytesOf(PATH_A) })).resolves.toBe(ROOT);
  });

  it('verifyQueryResponse and extendQueryResponse take the path', async () => {
    const response = { documents: [DOC_B1], total: 1, offset: 0, limit: 100, proof: hex(BOTH) };
    await expect(verifyQueryResponse(response, { path: PATH_A })).rejects.toThrow(/off the query path/);
    await expect(extendQueryResponse(response, 'sg-a').verifyProof()).rejects.toThrow(/off the query path/);
    await expect(extendQueryResponse(response).verifyProof()).resolves.toBe(ROOT);
  });

  it('an empty subgrove: the proof ends at its data tree, proven empty', async () => {
    const proof = honest(PATH_C, []);
    await expect(verifyQueryProof(hex(proof), [], { path: PATH_C })).resolves.toBe(ROOT);
    await expect(verifyQueryProof(hex(proof), [DOC_A1], { path: PATH_C })).rejects.toThrow(/not committed/);
  });

  it('a non-empty data tree proven without its lower layer does not stand for an empty result', async () => {
    const dropped = underSubgroves(['sg-a'], [['sg-a', { merk: sgA.prove(['data']) }]]);
    expect(hashToHex(verifyGroveDBProof(dropped).rootHash)).toBe(ROOT);
    await expect(verifyQueryProof(hex(dropped), [], { path: PATH_A })).rejects.toThrow(/does not descend/);
  });

  it('a non-empty data tree claimed empty is refused', async () => {
    // Tree(None) bytes on the real (layered) value hash of A's data tree.
    const entry = sgA.get('data') as { key: string; tree: Merk };
    const forgedSgA = Uint8Array.from([
      ...op.kvValueHash(enc('data'), treeElement(null), Merk.layeredValueHash(entry)),
      ...op.hash(hexToBytes(hashOfMeta())),
      op.child,
    ]);
    const proof = underSubgroves(['sg-a'], [['sg-a', { merk: forgedSgA }]]);
    expect(() => verifyGroveDBProof(proof)).toThrow(/Empty subtree does not hash/);
    await expect(verifyQueryProof(hex(proof), [], { path: PATH_A })).rejects.toThrow(/Empty subtree does not hash/);
  });
});

/** The node hash of sg-a's `meta` node (a leaf, the right child of `data`). */
function hashOfMeta(): string {
  // Proving `data` alone leaves `meta` as one Hash op at the end: 0x01 + 32 bytes, then Child.
  const ops = sgA.prove(['data']);
  return hex(ops.slice(ops.length - 33, ops.length - 1));
}

describe('WillowData binds query results to the queried subgrove', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  const reply = (body: unknown) =>
    ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

  function data(): WillowData {
    const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
    // A light client that trusts the honest root.
    (d as any).lightClient = {
      getLatestChainHeight: async () => 7,
      getVerifiedRootHashAtHeight: async () => ROOT,
    };
    return d;
  }

  function serveQuery(proof: Uint8Array, documents: unknown[]) {
    global.fetch = jest.fn(async () =>
      reply({ success: true, data: { documents, total: documents.length, offset: 0, limit: 100, proof: hex(proof), height: 7 } }),
    ) as unknown as typeof fetch;
  }

  it('query returns documents proven in the subgrove', async () => {
    serveQuery(honest(PATH_A, ['a1', 'a2']), [DOC_A1, DOC_A2]);
    const result = await data().query('sg-a', {});
    expect(result.documents).toEqual([DOC_A1, DOC_A2]);
  });

  it("query refuses another subgrove's documents at the same root", async () => {
    serveQuery(BOTH, [DOC_B1]);
    await expect(data().query('sg-a', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
    serveQuery(ONLY_B, [DOC_B1]);
    await expect(data().query('sg-a', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
    serveQuery(WITH_META, [META]);
    await expect(data().query('sg-a', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
  });

  it('queryHistoricalVerified is unsupported, and sends nothing', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const historicalQuery = { path: PATH_A.map((s) => Array.from(enc(s))), query_type: 'get_path' };
    await expect(data().queryHistoricalVerified('sg-a', 'cp', historicalQuery)).rejects.toMatchObject({
      code: 'UNSUPPORTED_OPERATION',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('subtree bytes are bound or not given', () => {
  // An item's real value hash, under other bytes, on a KVValueHash node:
  // the node hash (so the root) is unchanged whatever the bytes.
  const itemA1 = itemElement(enc(JSON.stringify(DOC_A1)));
  const forgedAt = (bytes: Uint8Array) =>
    groveProof({
      merk: Uint8Array.from([
        ...op.kvValueHash(enc('a1'), bytes, valueHash(itemA1)),
        ...op.hash(hexToBytes(rightOfA1())),
        op.child,
      ]),
    });
  const dataRoot = hex(dataA.rootHash());

  it('refuses tree-shaped bytes with trailing bytes on an item value hash', () => {
    // Tree(None, None), then other bytes: as a tree it would skip the leaf check.
    const forged = Uint8Array.from([0x02, 0x00, 0x00, ...enc(JSON.stringify({ owner: 'mallory' }))]);
    expect(() => deserializeElement(forged)).toThrow(/Trailing bytes/);
    for (const deserializeElements of [true, false]) {
      expect(() => verifyGroveDBProof(forgedAt(forged), { deserializeElements })).toThrow(
        /does not hash to its committed valueHash/,
      );
    }
  });

  it('refuses an empty-tree claim on an item value hash', () => {
    expect(() => verifyGroveDBProof(forgedAt(treeElement(null)))).toThrow(/Empty subtree does not hash/);
  });

  it('gives a non-empty subtree without its lower layer no bytes, marked as a subtree', async () => {
    const proof = forgedAt(treeElement(enc('x')));
    for (const deserializeElements of [true, false]) {
      const r = verifyGroveDBProof(proof, { deserializeElements });
      expect(hashToHex(r.rootHash)).toBe(dataRoot);
      expect(r.results.map((e) => [e.tree, e.value, e.element])).toEqual([[true, null, null]]);
    }
    await expect(verifyItemProof(hex(proof), 'a1', DOC_A1)).rejects.toThrow(/does not match/);
    await expect(verifyItemProof(hex(proof), 'a1', undefined)).resolves.toBe(dataRoot);
  });

  it('gives an empty subtree its bytes, marked as a subtree, binding no value', () => {
    const r = verifyGroveDBProof(honest(PATH_C, []), { deserializeElements: false });
    const entry = r.results.find((e) => new TextDecoder().decode(e.key) === 'data')!;
    expect(entry.tree).toBe(true);
    expect(entry.value).toEqual(treeElement(null));
    expect(entry.element).toBeNull();
  });
});

/** The node hash of dataA's `a2` (a leaf, the right child of `a1`). */
function rightOfA1(): string {
  const ops = dataA.prove(['a1']);
  return hex(ops.slice(ops.length - 33, ops.length - 1));
}

describe('ProofVerifier binds a key, its path, and its value', () => {
  const verifier = new ProofVerifier();
  const root = hexToBytes(ROOT);
  const pathA = bytesOf(PATH_A);
  const pathB = bytesOf(PATH_B);
  const a1 = enc(JSON.stringify(DOC_A1));
  const b1 = enc(JSON.stringify(DOC_B1));
  const proofA1 = honest(PATH_A, ['a1']);
  const proofB1 = honest(PATH_B, ['b1']);

  it('verifyInclusionProof: true only for the key, path, and value the proof proves', async () => {
    expect(await verifier.verifyInclusionProof(enc('a1'), a1, proofA1, root, pathA)).toBe(true);
    expect(await verifier.verifyInclusionProof(enc('b1'), b1, proofB1, root, pathB)).toBe(true);
    // A valid proof at the trusted root, of something else:
    expect(await verifier.verifyInclusionProof(enc('a1'), b1, proofA1, root, pathA)).toBe(false);
    expect(await verifier.verifyInclusionProof(enc('a2'), enc(JSON.stringify(DOC_A2)), proofA1, root, pathA)).toBe(false);
    expect(await verifier.verifyInclusionProof(enc('b1'), b1, proofB1, root, pathA)).toBe(false);
    expect(await verifier.verifyInclusionProof(enc('b1'), b1, BOTH, root, pathB)).toBe(false);
    expect(await verifier.verifyInclusionProof(enc('a1'), a1, proofA1, new Uint8Array(32), pathA)).toBe(false);
  });

  it('verifyAbsenceProof: true only when the key has no place in the proven layer', async () => {
    const both = honest(PATH_A, ['a1', 'a2']);
    // Before the first key, between the two, after the last: all adjacent.
    for (const key of ['a0', 'a15', 'a3']) {
      expect(await verifier.verifyAbsenceProof(enc(key), both, root, pathA)).toBe(true);
    }
    // a1 alone leaves a2's node as a pruned subtree, which could hold a15 or a3.
    expect(await verifier.verifyAbsenceProof(enc('a0'), proofA1, root, pathA)).toBe(true);
    expect(await verifier.verifyAbsenceProof(enc('a15'), proofA1, root, pathA)).toBe(false);
    expect(await verifier.verifyAbsenceProof(enc('a3'), proofA1, root, pathA)).toBe(false);
    // A present key is not absent; nor is a key at another path's proof.
    expect(await verifier.verifyAbsenceProof(enc('a1'), both, root, pathA)).toBe(false);
    expect(await verifier.verifyAbsenceProof(enc('a2'), proofA1, root, pathA)).toBe(false);
    expect(await verifier.verifyAbsenceProof(enc('a0'), proofB1, root, pathA)).toBe(false);
    expect(await verifier.verifyAbsenceProof(enc('a0'), BOTH, root, pathA)).toBe(false);
    expect(await verifier.verifyAbsenceProof(enc('a0'), both, new Uint8Array(32), pathA)).toBe(false);
    // Nothing is under an empty subtree.
    expect(await verifier.verifyAbsenceProof(enc('any'), honest(PATH_C, []), root, bytesOf(PATH_C))).toBe(true);
  });

  it('a whole layer pruned to its root hash proves nothing absent', async () => {
    const pruned = groveProof(pathProof(state, ['subgroves', 'sg-a', 'data'], []));
    expect(hashToHex(verifyGroveDBProof(pruned).rootHash)).toBe(ROOT);
    expect(await verifier.verifyAbsenceProof(enc('a1'), pruned, root, pathA)).toBe(false);
    expect(() => verifyKeyAbsence(pruned, pathA, enc('a1'))).toThrow(/does not prove/);
  });

  it('requires a path', async () => {
    await expect(verifier.verifyInclusionProof(enc('a1'), a1, proofA1, root, undefined as any)).rejects.toMatchObject({
      code: 'PATH_REQUIRED',
    });
    await expect(verifier.verifyAbsenceProof(enc('a0'), proofA1, root, undefined as any)).rejects.toMatchObject({
      code: 'PATH_REQUIRED',
    });
  });

  it('verifyQueryProof binds its query result to values the proof proves', async () => {
    const proof = { proof: honest(PATH_A, ['a1', 'a2']), pathQuery: {}, height: 3 };
    expect((await verifier.verifyQueryProof(proof, root, [a1])).success).toBe(true);
    expect((await verifier.verifyQueryProof({ ...proof, queryResult: [a1] }, root)).success).toBe(true);
    expect((await verifier.verifyQueryProof(proof, root, [b1])).success).toBe(false);
    expect((await verifier.verifyQueryProof(proof, new Uint8Array(32), [a1])).success).toBe(false);
  });
});

describe('absence over real grovedb proofs', () => {
  const FIXTURES = JSON.parse(
    fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', 'envelope-real-proofs.json'), 'utf8'),
  ) as Record<string, { root: string; path: string[]; key?: string; proof: string }>;
  const verifier = new ProofVerifier();

  it("grovedb's proof of an absent key proves it absent, and no other", async () => {
    const f = FIXTURES['absent-key'];
    const proof = hexToBytes(f.proof);
    const p = f.path.map(enc);
    expect(await verifier.verifyAbsenceProof(enc('0xdoesnotexist-0'), proof, hexToBytes(f.root), p)).toBe(true);
    expect(await verifier.verifyAbsenceProof(enc('0xdoesnotexist-0'), proof, hexToBytes(f.root), p.slice(0, 3))).toBe(false);
  });

  it("grovedb's proof of a present key does not prove it absent", async () => {
    const f = FIXTURES['single-key'];
    const proof = hexToBytes(f.proof);
    expect(await verifier.verifyAbsenceProof(enc(f.key!), proof, hexToBytes(f.root), f.path.map(enc))).toBe(false);
  });
});
