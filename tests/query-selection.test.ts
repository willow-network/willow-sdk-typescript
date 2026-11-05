/**
 * A query's result is verified as its whole result: the proof must reveal
 * the subgrove's entire data tree, and the documents and `total` must be
 * exactly what the API's query selects from it, in its order.
 *
 * The API's selection (with a proof): every item in the data tree whose bytes
 * serde_json (with `arbitrary_precision`) reads as JSON, kept when its field
 * equals the one exact-match filter, sorted stably by the one sort field,
 * then `offset` and `limit` (default 100). Numbers compare by their text.
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  verifyQuerySelection,
  verifyQueryProof,
  subgroveDataPath,
  QueryNotVerifiableError,
  QueryResultNotVerifiableError,
} from '../src/proof';
import { querySelection, selectDocuments } from '../src/proof/query-selection';
import { parseNodeJson, canonicalNumber, nodeJsonToJs } from '../src/proof/node-json';
import {
  verifyCompleteLayer,
  verifyGroveDBProof,
  combineHash,
  kvDigestToKvHash,
  kvHash,
  nodeHash,
  valueHash,
  hexToBytes,
  hashToHex,
  NULL_HASH,
} from '../src/grovedb';
import { WillowData } from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';
import { QueryRequest } from '../src/types';
import {
  Merk,
  LayerProof,
  chainProof as chainProofTo,
  enc,
  groveProof,
  hex,
  itemElement,
  op,
  pathProof,
  treeElement,
} from './helpers/grove-proof';

/** Seven documents a–g: odd ones active, `n` their index. */
const DOCS = ['a', 'b', 'c', 'd', 'e', 'f', 'g'].map((key, i) => ({
  key,
  doc: { id: key, status: i % 2 ? 'active' : 'inactive', n: i, meta: { kind: i < 3 ? 'low' : 'high' } },
}));

/** A state with subgrove `s1` holding `entries` as its data, and an empty `s2`. */
function stateWith(entries: Array<{ key: string; item: string }>) {
  const data = new Merk(entries);
  const s1 = new Merk([{ key: 'data', tree: data }, { key: 'meta', item: '{}' }]);
  const s2 = new Merk([{ key: 'data', tree: new Merk([]) }]);
  const subgroves = new Merk([{ key: 's1', tree: s1 }, { key: 's2', tree: s2 }]);
  const root = new Merk([{ key: 'subgroves', tree: subgroves }]);
  return { data, s1, subgroves, root, ROOT: hex(root.rootHash()), keys: entries.map((e) => e.key) };
}

const S = stateWith(DOCS.map(({ key, doc }) => ({ key, item: JSON.stringify(doc) })));
const PATH = subgroveDataPath('s1');
const FULL = hex(groveProof(pathProof(S.root, PATH, S.keys)));
const docsOf = (...keys: string[]) => keys.map((k) => DOCS.find((d) => d.key === k)!.doc);

function response(proof: string, documents: unknown[], total: number, offset = 0, limit = 100) {
  return { documents: documents as Record<string, unknown>[], total, offset, limit, proof };
}

/** A proof of subgrove `s1` whose data layer is `dataOps` (root `dataRoot`, root key `rootKey`). */
function chainProof(dataOps: Uint8Array, dataRoot: Uint8Array, rootKey: string): Uint8Array {
  return chainProofTo(['subgroves', 's1', 'data'], dataOps, dataRoot, enc(rootKey)).proof;
}

const KV_REF = (key: Uint8Array, value: Uint8Array, vh: Uint8Array) => [
  0x06,
  key.length,
  ...key,
  value.length >> 8,
  value.length & 0xff,
  ...value,
  ...vh,
];

describe('a partial or altered result is refused', () => {
  it('a data layer collapsed to one Hash node, with no documents', async () => {
    const lone: LayerProof = {
      merk: S.root.prove(['subgroves']),
      lower: [['subgroves', { merk: S.subgroves.prove(['s1']), lower: [['s1', {
        merk: S.s1.prove(['data']),
        lower: [['data', { merk: Uint8Array.from(op.hash(S.data.rootHash())) }]],
      }]] }]],
    };
    const proof = hex(groveProof(lone));
    // Membership alone passes it: no document, nothing to bind.
    await expect(verifyQueryProof(proof, [], { path: PATH })).resolves.toBe(S.ROOT);
    await expect(verifyQuerySelection('s1', {}, response(proof, [], 0))).rejects.toThrow(
      /does not reveal the whole subtree.*Hash node/,
    );
  });

  it('a proof revealing one document, the rest hidden', async () => {
    const proof = hex(groveProof(pathProof(S.root, PATH, ['b'])));
    await expect(verifyQuerySelection('s1', {}, response(proof, docsOf('b'), 1))).rejects.toThrow(
      /does not reveal the whole subtree/,
    );
  });

  it('the whole data tree with a subset, a duplicate, a filtered-out document, or none', async () => {
    const active = { filters: { status: 'active' } };
    const cases: Array<[QueryRequest, unknown[], number]> = [
      [{}, docsOf('b'), 1],
      [{}, docsOf('b'), 7],
      [{}, [], 0],
      [{}, docsOf('b', 'b'), 2],
      [active, docsOf('a'), 1],
      [active, docsOf('b', 'd'), 3],
      [active, docsOf('b', 'd', 'f', 'a'), 4],
    ];
    for (const [query, documents, total] of cases) {
      await expect(verifyQuerySelection('s1', query, response(FULL, documents, total))).rejects.toThrow();
    }
  });

  it('the right documents with the wrong total, order, offset, or limit', async () => {
    const all = docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g');
    await expect(verifyQuerySelection('s1', {}, response(FULL, all, 8))).rejects.toThrow(/total/);
    await expect(verifyQuerySelection('s1', {}, response(FULL, [...all].reverse(), 7))).rejects.toThrow(
      /index 0/,
    );
    await expect(verifyQuerySelection('s1', {}, response(FULL, all, 7, 1))).rejects.toThrow(/offset and limit/);
    await expect(verifyQuerySelection('s1', {}, response(FULL, all, 7, 0, 7))).rejects.toThrow(/offset and limit/);
  });

  it('a hidden value (KVDigest) or an item passed off as a subtree without its lower layer', async () => {
    const a = itemElement(enc(JSON.stringify(DOCS[0].doc)));
    const digest = Uint8Array.from(op.kvDigest(enc('a'), valueHash(a)));
    const digestRoot = nodeHash(kvDigestToKvHash(enc('a'), valueHash(a)), NULL_HASH, NULL_HASH);
    await expect(
      verifyQuerySelection('s1', {}, response(hex(chainProof(digest, digestRoot, 'a')), [], 0)),
    ).rejects.toThrow(/KVDigest node/);

    // The item's own value hash, under tree bytes: the root is the item's.
    const asTree = Uint8Array.from(op.kvValueHash(enc('a'), treeElement(enc('x')), valueHash(a)));
    const itemRoot = nodeHash(kvHash(enc('a'), a), NULL_HASH, NULL_HASH);
    const proof = chainProof(asTree, itemRoot, 'a');
    const honest = chainProof(Uint8Array.from(op.kv(enc('a'), a)), itemRoot, 'a');
    // Both verify to one root.
    expect(hashToHex(verifyGroveDBProof(proof).rootHash)).toBe(hashToHex(verifyGroveDBProof(honest).rootHash));
    await expect(verifyQuerySelection('s1', {}, response(hex(proof), [], 0))).rejects.toThrow(
      /subtree without its lower layer/,
    );
    await expect(
      verifyQuerySelection('s1', {}, response(hex(honest), docsOf('a'), 1)),
    ).resolves.toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('an honest result verifies', () => {
  it('every document, in key order', async () => {
    const all = docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g');
    await expect(verifyQuerySelection('s1', {}, response(FULL, all, 7))).resolves.toBe(S.ROOT);
  });

  it('an exact-match filter, on a top-level or a dotted field', async () => {
    await expect(
      verifyQuerySelection('s1', { filters: { status: 'active' } }, response(FULL, docsOf('b', 'd', 'f'), 3)),
    ).resolves.toBe(S.ROOT);
    await expect(
      verifyQuerySelection('s1', { filters: { 'meta.kind': 'low' } }, response(FULL, docsOf('a', 'b', 'c'), 3)),
    ).resolves.toBe(S.ROOT);
    await expect(
      verifyQuerySelection('s1', { filters: { status: 'none' } }, response(FULL, [], 0)),
    ).resolves.toBe(S.ROOT);
  });

  it('a sort, with offset and limit', async () => {
    const desc: QueryRequest = { sort: { field: 'n', order: 'desc' } };
    await expect(
      verifyQuerySelection('s1', desc, response(FULL, docsOf('g', 'f', 'e', 'd', 'c', 'b', 'a'), 7)),
    ).resolves.toBe(S.ROOT);
    await expect(
      verifyQuerySelection('s1', { ...desc, offset: 2, limit: 3 }, response(FULL, docsOf('e', 'd', 'c'), 7, 2, 3)),
    ).resolves.toBe(S.ROOT);
    // Equal sort values keep key order, in either direction.
    await expect(
      verifyQuerySelection(
        's1',
        { sort: { field: 'status', order: 'desc' } },
        response(FULL, docsOf('a', 'c', 'e', 'g', 'b', 'd', 'f'), 7),
      ),
    ).resolves.toBe(S.ROOT);
  });

  it('a limit of 100 when none is given', async () => {
    const many = Array.from({ length: 105 }, (_, i) => ({ key: `k${String(i).padStart(3, '0')}`, item: JSON.stringify({ i }) }));
    const big = stateWith(many);
    const proof = hex(groveProof(pathProof(big.root, PATH, big.keys)));
    const first100 = many.slice(0, 100).map((e) => JSON.parse(e.item));
    await expect(verifyQuerySelection('s1', {}, response(proof, first100, 105))).resolves.toBe(big.ROOT);
    await expect(
      verifyQuerySelection('s1', {}, response(proof, [...first100, { i: 100 }], 105)),
    ).rejects.toThrow(/105 documents|101 documents/);
  });

  it('an empty subgrove: no documents, total 0', async () => {
    const proof = hex(groveProof(pathProof(S.root, subgroveDataPath('s2'), [])));
    await expect(verifyQuerySelection('s2', {}, response(proof, [], 0))).resolves.toBe(S.ROOT);
    await expect(verifyQuerySelection('s2', {}, response(proof, docsOf('a'), 1))).rejects.toThrow();
  });

  it("grovedb's own range_full proof reveals its whole subtree", () => {
    const f = JSON.parse(
      fs.readFileSync(path.join(__dirname, 'fixtures/grovedb/range_full_apps_data.json'), 'utf8'),
    );
    const layer = verifyCompleteLayer(hexToBytes(f.proof_hex), f.path.map(enc));
    expect(hashToHex(layer.rootHash)).toBe(f.expected_root_hex);
    expect(layer.entries.map((e) => new TextDecoder().decode(e.key))).toEqual(f.expected_keys);
    expect(layer.entries.map((e) => e.element?.type)).toEqual(['Item', 'Item', 'Item']);
    // Its values ("value-alpha", …) are not JSON: the API selects none of them.
    expect(selectDocuments(layer.entries, querySelection({})).documents).toEqual([]);
  });
});

describe("the API's reading of documents", () => {
  /** The documents the API selects from items holding `texts`, under keys k0, k1, …. */
  const select = (texts: string[], query: QueryRequest = {}) => {
    const entries = texts.map((t, i) => ({
      key: enc(`k${i}`),
      value: itemElement(enc(t)),
      element: { type: 'Item' as const, value: enc(t), flags: null },
      reference: false,
    }));
    return selectDocuments(entries, querySelection({ ...query, include_proof: true })).documents.map(nodeJsonToJs);
  };

  it('numbers compare by their text, as serde_json keeps it', () => {
    expect(canonicalNumber('1E5')).toBe('1e+5');
    expect(canonicalNumber('1e-5')).toBe('1e-5');
    expect(canonicalNumber('-0')).toBe('0');
    expect(canonicalNumber('-0.0')).toBe('-0.0');
    expect(canonicalNumber('18446744073709551615')).toBe('18446744073709551615');
    expect(canonicalNumber('18446744073709551616')).toBe('18446744073709551616');
    const docs = ['{"n":1}', '{"n":1.0}', '{"n":1e0}', '{"n":-0}', '{"n":0.0}', '{"n":0}'];
    expect(select(docs, { filters: { n: 1 } })).toHaveLength(1);
    expect(select(docs, { filters: { n: 0 } })).toHaveLength(2); // -0 and 0
    expect(select(docs, { filters: { n: 100000 } })).toHaveLength(0);
  });

  it('documents the API cannot read are not selected', () => {
    const lone = '{"s":"\\ud800"}';
    const deep = (n: number) => '['.repeat(n) + ']'.repeat(n);
    expect(parseNodeJson(enc(lone))).toBeNull();
    expect(parseNodeJson(enc('{"s":"\\ud83d\\ude00"}'))).not.toBeNull();
    expect(parseNodeJson(Uint8Array.from([0xef, 0xbb, 0xbf, ...enc('{}')]))).toBeNull();
    expect(parseNodeJson(Uint8Array.from([0x22, 0xff, 0x22]))).toBeNull();
    expect(parseNodeJson(enc(deep(127)))).not.toBeNull();
    expect(parseNodeJson(enc(deep(128)))).toBeNull();
    expect(parseNodeJson(enc('{"a":1,}'))).toBeNull();
    expect(parseNodeJson(enc('01'))).toBeNull();
    expect(select([lone, '{"ok":true}', 'value-alpha', deep(128), deep(127)])).toEqual([
      { ok: true },
      JSON.parse(deep(127)),
    ]);
  });

  it("an object whose first key is serde_json's private token is not reproduced", () => {
    for (const doc of [
      '{"$serde_json::private::Number":"1"}',
      '{"$serde_json::private::RawValue":"1"}',
      '{"a":{"$serde_json::private::Number":"1","b":2}}',
      '[{"$serde_json::private::\\u004eumber":"1"}]',
    ]) {
      expect(() => select([doc])).toThrow(/first key is "\$serde_json::private::(Number|RawValue)"/);
    }
    // Anywhere else, or any other key, is an ordinary key, as serde_json reads it.
    const ordinary = [
      '{"$serde_json::private::z":1}',
      '{"a":1,"$serde_json::private::Number":"1"}',
      '{"$serde_json::private::Numbers":"1"}',
      '{"$serde_json::private::number":"1"}',
    ];
    expect(select(ordinary)).toEqual(ordinary.map((t) => JSON.parse(t)));
  });

  it('strings sort by code point; mixed sort values are refused unless all compare equal', async () => {
    const astral = '{"s":"\\ud83d\\ude00"}'; // U+1F600
    const high = '{"s":"\\uffff"}';
    expect(select([astral, high], { sort: { field: 's', order: 'asc' } })).toEqual(
      select([high, astral]),
    );
    expect(() => select(['{"v":1}', '{"v":"x"}', '{"v":2}'], { sort: { field: 'v', order: 'asc' } })).toThrow(
      /not all numbers or all strings/,
    );
    expect(() => select(['{"v":1}', '{}', '{"v":2}'], { sort: { field: 'v', order: 'asc' } })).toThrow(
      /not all numbers or all strings/,
    );
    // Every pair equal: key order stands.
    expect(select(['{"v":1}', '{"v":"x"}', '{}'], { sort: { field: 'v', order: 'asc' } })).toEqual(
      select(['{"v":1}', '{"v":"x"}', '{}']),
    );
  });

  it('a reference is not an item to the API', async () => {
    const a = itemElement(enc(JSON.stringify({ id: 'a' })));
    const target = itemElement(enc(JSON.stringify({ id: 'target' })));
    const refElementHash = valueHash(Uint8Array.from([0x01, 0x00, 0x01, 0x01, 0x78, 0x00, 0x00]));
    const ops = Uint8Array.from([...op.kv(enc('a'), a), ...KV_REF(enc('r'), target, refElementHash), op.child]);
    const refHash = nodeHash(
      kvDigestToKvHash(enc('r'), combineHash(refElementHash, valueHash(target))),
      NULL_HASH,
      NULL_HASH,
    );
    const dataRoot = nodeHash(kvHash(enc('a'), a), NULL_HASH, refHash);
    const proof = hex(chainProof(ops, dataRoot, 'a'));
    const layer = verifyCompleteLayer(hexToBytes(proof), PATH.map(enc));
    expect(layer.entries.map((e) => e.reference)).toEqual([false, true]);
    await expect(verifyQuerySelection('s1', {}, response(proof, [{ id: 'a' }], 1))).resolves.toMatch(/^[0-9a-f]{64}$/);
    await expect(
      verifyQuerySelection('s1', {}, response(proof, [{ id: 'a' }, { id: 'target' }], 2)),
    ).rejects.toThrow();
  });
});

describe('a number JavaScript cannot carry exactly does not verify', () => {
  const one = (text: string) => {
    const state = stateWith([{ key: 'x', item: `{"v":${text}}` }]);
    const proof = hex(groveProof(pathProof(state.root, PATH, state.keys)));
    return verifyQuerySelection('s1', {}, response(proof, [JSON.parse(`{"v":${text}}`)], 1));
  };

  it('a number whose double is written as another value is refused', async () => {
    // 2^53 + 1 parses to 2^53, and u64::MAX to 2^64, which JavaScript writes 18446744073709552000.
    for (const text of [
      '0.12345678901234567890',
      '1.0000000000000000001',
      '0.33333333333333331',
      '1e-400',
      '9007199254740993',
      '18446744073709551615',
    ]) {
      await expect(one(text)).rejects.toThrow(/holds the number .*, which JavaScript can't carry exactly/);
    }
  });

  it('one of at most 15 significant digits verifies', async () => {
    for (const text of ['0.123456789012345', '1.5', '-2.5e-300', '9007199254740991']) {
      await expect(one(text)).resolves.toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('every number JavaScript writes verifies, at 16 and 17 significant digits too', async () => {
    for (const value of [1.1 * 1.1, 1 / 3, 0.1 + 0.2, 1e-320]) {
      await expect(one(String(value))).resolves.toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it('an integer beyond 2^53 - 1 that JavaScript writes verifies', async () => {
    for (const value of [1e18, 2 ** 53, Date.now() * 1e6, 2 ** 64, -(2 ** 60), 1e21]) {
      await expect(one(String(value))).resolves.toMatch(/^[0-9a-f]{64}$/);
    }
    await expect(one('1000000000000000000')).resolves.toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('the proof and its root are checked before the selection is run', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  /** A self-consistent state of `items`, served with no documents. */
  function forged(items: Array<{ key: string; item: string }>) {
    const state = stateWith(items);
    const proof = hex(groveProof(pathProof(state.root, PATH, state.keys)));
    global.fetch = jest.fn(async () => {
      const body = { success: true, data: { ...response(proof, [], 0), height: 7 } };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    }) as unknown as typeof fetch;
    return { proof, root: state.ROOT };
  }

  function dataAt(root: string) {
    const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
    const rootAt = jest.fn(async () => root);
    (d as any).lightClient = { getLatestChainHeight: async () => 7, getVerifiedRootHashAtHeight: rootAt };
    return { d, rootAt };
  }

  const irreproducible: Array<[string, Array<{ key: string; item: string }>, QueryRequest]> = [
    ['a private token', [{ key: 'x', item: '{"$serde_json::private::Number":"1"}' }], {}],
    [
      'mixed sort values',
      [
        { key: 'x', item: '{"v":1}' },
        { key: 'y', item: '{"v":"a"}' },
        { key: 'z', item: '{"v":2}' },
      ],
      { sort: { field: 'v', order: 'asc' } },
    ],
  ];

  it.each(irreproducible)('a forged proof with %s fails verification', async (_, items, query) => {
    forged(items);
    const { d, rootAt } = dataAt('ab'.repeat(32));
    await expect(d.query('s1', query)).rejects.toMatchObject({
      code: 'PROOF_VERIFICATION_FAILED',
      message: expect.stringMatching(/root hash mismatch/),
    });
    expect(rootAt).toHaveBeenCalledWith(7);
  });

  it.each(irreproducible)(
    'the same data at the verified root is QUERY_RESULT_NOT_VERIFIABLE, not a query to read unverified (%s)',
    async (_, items, query) => {
      const { root } = forged(items);
      const err = await dataAt(root).d.query('s1', query).catch((e) => e);
      expect(err).toBeInstanceOf(QueryResultNotVerifiableError);
      expect(err).not.toBeInstanceOf(QueryNotVerifiableError);
      expect(err).toMatchObject({ code: 'QUERY_RESULT_NOT_VERIFIABLE', rootHash: root });
      expect(err.message).not.toMatch(/queryUnverified/);
    },
  );

  it('verifyQuerySelection checks expectedRootHash first, and reports the root it ran the selection at', async () => {
    const [, items, query] = irreproducible[1];
    const { proof, root } = forged(items);
    await expect(
      verifyQuerySelection('s1', query, response(proof, [], 0), { expectedRootHash: 'ab'.repeat(32) }),
    ).rejects.toThrow(/Root hash mismatch/);
    await expect(verifyQuerySelection('s1', query, response(proof, [], 0))).rejects.toMatchObject({
      code: 'QUERY_RESULT_NOT_VERIFIABLE',
      rootHash: root,
    });
    // A query the API does not apply is still refused as the query.
    await expect(
      verifyQuerySelection('s1', { search: { field: 'v', query: 'a' } } as QueryRequest, response(proof, [], 0)),
    ).rejects.toThrow(QueryNotVerifiableError);
  });
});

describe('a query is verified against the body that was sent', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it('a caller changing its query object while pages are in flight still verifies each page', async () => {
    const all = docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g');
    const sent: Array<Record<string, any>> = [];
    global.fetch = jest.fn(async (_url: string, init?: RequestInit) => {
      const q = JSON.parse(init!.body as string);
      sent.push(q);
      // Answer after the caller has moved on.
      await new Promise((resolve) => setTimeout(resolve, 0));
      const status = q.filters?.status;
      const matching = all.filter((doc) => status === undefined || doc.status === status);
      const off = q.offset ?? 0;
      const lim = q.limit ?? 100;
      const body = {
        success: true,
        data: { ...response(FULL, matching.slice(off, off + lim), matching.length, off, lim), height: 7 },
      };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    }) as unknown as typeof fetch;
    const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
    (d as any).lightClient = { getLatestChainHeight: async () => 7, getVerifiedRootHashAtHeight: async () => S.ROOT };

    const q: QueryRequest = { filters: { status: 'active' }, limit: 2, offset: 0 };
    const pages: Array<Promise<unknown>> = [];
    for (let i = 0; i < 3; i++) {
      pages.push(d.query('s1', q).then((r) => r.documents));
      q.offset! += 1;
      (q.filters as Record<string, unknown>).status = i === 1 ? 'inactive' : 'active';
    }
    await expect(Promise.all(pages)).resolves.toEqual([
      docsOf('b', 'd'),
      docsOf('d', 'f'),
      docsOf('e', 'g'),
    ]);
    expect(sent.map((b) => [b.filters.status, b.offset])).toEqual([
      ['active', 0],
      ['active', 1],
      ['inactive', 2],
    ]);
  });
});

describe('a query whose selection the API does not make is refused before sending', () => {
  const refusals: QueryRequest[] = [
    { filters: { status: 'active', n: 1 } },
    { filters: { n: { $gt: 1 } } },
    { search: { field: 'id', query: 'a' } },
    { sort: { field: 'n', order: 'DESC' as 'desc' } },
    { limit: 1.5 },
    { offset: -1 },
    { filters: { s: '\ud800' } },
    { where: { a: 1 } } as unknown as QueryRequest,
  ];

  it.each(refusals)('%j', async (query) => {
    expect(() => querySelection({ ...query, include_proof: true })).toThrow(QueryNotVerifiableError);
    const fetchMock = jest.fn();
    const realFetch = global.fetch;
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
      await expect(d.query('s1', query)).rejects.toMatchObject({ code: 'QUERY_NOT_VERIFIABLE' });
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      global.fetch = realFetch;
    }
  });

  it('a NaN limit is sent as null, and the API takes its default', () => {
    expect(querySelection({ limit: NaN, include_proof: true }).limit).toBe(100);
  });
});

describe('data.query', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });
  const reply = (body: unknown) =>
    ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

  function data(latest = 7, root = S.ROOT): WillowData {
    const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
    (d as any).lightClient = {
      getLatestChainHeight: async () => latest,
      getVerifiedRootHashAtHeight: async () => root,
    };
    return d;
  }

  function serve(body: Record<string, unknown>) {
    const sent: string[] = [];
    global.fetch = jest.fn(async (_url: string, init?: RequestInit) => {
      sent.push(init!.body as string);
      return reply({ success: true, data: body });
    }) as unknown as typeof fetch;
    return sent;
  }

  it('returns the verified result with its root and height', async () => {
    const sent = serve({ ...response(FULL, docsOf('b', 'd', 'f'), 3), height: 7, verification: { x: 1 } });
    const result = await data().query('s1', { filters: { status: 'active' } });
    expect(result).toEqual({
      ...response(FULL, docsOf('b', 'd', 'f'), 3),
      verifiedRootHash: S.ROOT,
      verifiedHeight: 7,
    });
    expect(JSON.parse(sent[0])).toEqual({ filters: { status: 'active' }, include_proof: true });
  });

  it('refuses a subset, and a collapsed data layer', async () => {
    serve({ ...response(FULL, docsOf('b'), 1), height: 7 });
    await expect(data().query('s1', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
    const lone: LayerProof = {
      merk: S.root.prove(['subgroves']),
      lower: [['subgroves', { merk: S.subgroves.prove(['s1']), lower: [['s1', {
        merk: S.s1.prove(['data']),
        lower: [['data', { merk: Uint8Array.from(op.hash(S.data.rootHash())) }]],
      }]] }]],
    };
    serve({ ...response(hex(groveProof(lone)), [], 0), height: 7 });
    await expect(data().query('s1', {})).rejects.toMatchObject({
      code: 'PROOF_VERIFICATION_FAILED',
      message: expect.stringMatching(/does not reveal the whole subtree/),
    });
  });

  it('refuses a proof far from the chain, or naming no height', async () => {
    const body = response(FULL, docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g'), 7);
    serve({ ...body, height: 7 });
    await expect(data(28).query('s1', {})).rejects.toMatchObject({ code: 'PROOF_HEIGHT_OUT_OF_RANGE' });
    await expect(data(27).query('s1', {})).resolves.toMatchObject({ verifiedHeight: 7 });
    serve({ ...body, height: 0 });
    await expect(data().query('s1', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
    serve(body);
    await expect(data().query('s1', {})).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
  });

  it('takes the bound from lightClient.maxProofLagBlocks', async () => {
    serve({ ...response(FULL, docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g'), 7), height: 7 });
    const d = new WillowData(
      'http://api.test',
      new WillowAuth('http://api.test'),
      new WillowIndexers('http://api.test'),
      undefined,
      undefined,
      { lightClient: { maxProofLagBlocks: 2 } },
    );
    (d as any).lightClient = { getLatestChainHeight: async () => 10, getVerifiedRootHashAtHeight: async () => S.ROOT };
    await expect(d.query('s1', {})).rejects.toMatchObject({ code: 'PROOF_HEIGHT_OUT_OF_RANGE' });
  });

  it('refuses a root the light client does not give for the height', async () => {
    serve({ ...response(FULL, docsOf('a', 'b', 'c', 'd', 'e', 'f', 'g'), 7), height: 7 });
    await expect(data(7, '00'.repeat(32)).query('s1', {})).rejects.toMatchObject({
      code: 'PROOF_VERIFICATION_FAILED',
    });
  });
});

