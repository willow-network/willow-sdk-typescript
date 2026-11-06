/**
 * A query's result is verified as its whole result: the proof must reveal
 * the subgrove's entire data tree, and the documents and `total` must be
 * exactly what the API's query selects from it, in its order.
 *
 * The API's selection (with a proof): every item in the data tree whose bytes
 * serde_json (with `arbitrary_precision`) reads as JSON, kept when every
 * exact-match filter matches (numbers by exact decimal value), sorted stably
 * by the one sort field in a total order by kind, then `offset` and `limit`
 * (default 100).
 */
import * as fs from 'fs';
import * as path from 'path';
import {
  verifyQuerySelection,
  verifyQueryProof,
  subgroveDataPath,
  QueryRefusedError,
  QueryNotVerifiableError,
  QueryResultNotVerifiableError,
} from '../src/proof';
import { QuerySelection, querySelection, selectDocuments } from '../src/proof/query-selection';
import {
  parseNodeJson,
  parseNodeJsonText,
  canonicalNumber,
  nodeJsonToJs,
  nodeExactDecimal,
  nodeNumbersEqual,
  nodeJsonEqual,
  nodeJsonTextLength,
  parseF64,
} from '../src/proof/node-json';
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

  it('numbers keep their text as serde_json does, and a filter matches them by exact decimal value', () => {
    expect(canonicalNumber('1E5')).toBe('1e+5');
    expect(canonicalNumber('1e-5')).toBe('1e-5');
    expect(canonicalNumber('-0')).toBe('0');
    expect(canonicalNumber('-0.0')).toBe('-0.0');
    expect(canonicalNumber('18446744073709551615')).toBe('18446744073709551615');
    expect(canonicalNumber('18446744073709551616')).toBe('18446744073709551616');
    const docs = ['{"n":1}', '{"n":1.0}', '{"n":1e0}', '{"n":-0}', '{"n":0.0}', '{"n":0}', '{"n":10E-1}', '{"n":"1"}'];
    expect(select(docs, { filters: { n: 1 } })).toHaveLength(4);
    expect(select(docs, { filters: { n: 0 } })).toHaveLength(3); // -0, 0.0, and 0
    expect(select(docs, { filters: { n: 100000 } })).toHaveLength(0);
    expect(select(docs, { filters: { n: '1' } })).toEqual([{ n: '1' }]);
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

  it('strings sort by code point; mixed kinds sort by kind', async () => {
    const astral = '{"s":"\\ud83d\\ude00"}'; // U+1F600
    const high = '{"s":"\\uffff"}';
    expect(select([astral, high], { sort: { field: 's', order: 'asc' } })).toEqual(
      select([high, astral]),
    );
    const asc = { sort: { field: 'v', order: 'asc' as const } };
    expect(select(['{"v":1}', '{"v":"x"}', '{"v":2}'], asc)).toEqual([{ v: 1 }, { v: 2 }, { v: 'x' }]);
    expect(select(['{"v":1}', '{}', '{"v":2}'], asc)).toEqual([{}, { v: 1 }, { v: 2 }]);
    expect(select(['{"v":true}', '{"v":false}', '{"v":true}', '{"v":null}'], asc)).toEqual([
      { v: null },
      { v: false },
      { v: true },
      { v: true },
    ]);
  });

  it('a sort number of more than 20 significant digits sorts by its correctly rounded double, in linear time', () => {
    const asc = { sort: { field: 'v', order: 'asc' as const } };
    const desc = { sort: { field: 'v', order: 'desc' as const } };
    const ids = (texts: string[], query: QueryRequest) =>
      select(texts, query).map((d) => (d as { id: string }).id);
    // 65,400 zeros between two ones: a document that fits one KV node. Counting
    // its digits by a backtracking regex took seconds.
    const long = `{"id":"long","v":1.${'0'.repeat(65_400)}1}`;
    const start = performance.now();
    expect(ids([long, '{"id":"two","v":2}', '{"id":"one","v":1}'], asc)).toEqual(['long', 'one', 'two']);
    expect(performance.now() - start).toBeLessThan(1000);
    expect(ids(['{"id":"big","v":123456789012345678901}', '{"id":"two","v":2}'], asc)).toEqual(['two', 'big']);
    expect(ids(['{"id":"neg","v":-1.23456789012345678901e5}', '{"id":"two","v":2}'], desc)).toEqual(['two', 'neg']);
    // 2^53 + 1 rounds to 2^53 (ties to even); the same digits and a 1 far past the 20th round up to 2^53 + 2.
    const texts = [
      '{"id":"up","v":9007199254740993.0000000000000000001}',
      '{"id":"even","v":9007199254740994}',
      '{"id":"tie","v":9007199254740993}',
    ];
    expect(ids(texts, asc)).toEqual(['tie', 'up', 'even']);
    expect(ids(texts, desc)).toEqual(['up', 'even', 'tie']);
  }, 30_000);

  it('parseF64 is the correctly rounded double, as Rust parses it', () => {
    const cases = [
      '2.4703282292062327e-324', // just under half the least subnormal: 0
      '2.4703282292062328e-324', // just over: the least subnormal
      '2.2250738585072011e-308',
      '1.7976931348623157e308',
      '1.7976931348623158e308', // rounds down to the largest double
      '1.7976931348623159e308', // past it: Infinity
      '9007199254740993',
      '9007199254740995',
      `9007199254740993${'0'.repeat(30)}1e-31`,
      `1${'0'.repeat(5000)}e-5000`,
      `0.${'0'.repeat(400)}1e+400`,
      '-0',
      '1e400',
      '-1e-400',
      '1e-0000000000000000000000000000400',
      '1e99999999999999999999',
      '-1e-99999999999999999999',
    ];
    for (const text of cases) expect(Object.is(parseF64(text), Number(text))).toBe(true);
    // Numbers of 21 to 45 significant digits at every magnitude, against the
    // engine's own (correctly rounded) parse.
    let seed = 1;
    const next = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
      return (seed >>> 8) % n;
    };
    for (let i = 0; i < 20_000; i++) {
      let digits = String(1 + next(9));
      const length = 21 + next(25);
      while (digits.length < length) digits += String(next(10));
      const point = next(length);
      const text = `${next(2) ? '-' : ''}${digits.slice(0, length - point)}${point ? `.${digits.slice(length - point)}` : ''}e${next(700) - 360}`;
      expect([text, parseF64(text)]).toEqual([text, Number(text)]);
    }
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
      'a private token in a sorted document',
      [
        { key: 'x', item: '{"v":1}' },
        { key: 'y', item: '{"v":{"$serde_json::private::RawValue":"2"}}' },
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
    // A query the API refuses is still refused as the query.
    await expect(
      verifyQuerySelection('s1', { search: { field: 'v', query: 'a' } } as QueryRequest, response(proof, [], 0)),
    ).rejects.toThrow(QueryRefusedError);
  });

  it('a sort over mixed kinds verifies at the verified root', async () => {
    const items = [
      { key: 'a', item: '{"v":"x"}' },
      { key: 'b', item: '{"v":2}' },
      { key: 'c', item: '{}' },
      { key: 'd', item: '{"v":true}' },
      { key: 'e', item: '{"v":[1]}' },
      { key: 'f', item: '{"v":1.0}' },
    ];
    const state = stateWith(items);
    const proof = hex(groveProof(pathProof(state.root, PATH, state.keys)));
    const ordered = ['c', 'd', 'f', 'b', 'a', 'e'].map((k) => JSON.parse(items.find((i) => i.key === k)!.item));
    global.fetch = jest.fn(async () => {
      const body = { success: true, data: { ...response(proof, ordered, 6), height: 7 } };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    }) as unknown as typeof fetch;
    await expect(dataAt(state.ROOT).d.query('s1', { sort: { field: 'v', order: 'asc' } })).resolves.toMatchObject({
      documents: ordered,
      total: 6,
      verifiedRootHash: state.ROOT,
    });
    await expect(dataAt(state.ROOT).d.query('s1', { sort: { field: 'v', order: 'desc' } })).rejects.toMatchObject({
      code: 'PROOF_VERIFICATION_FAILED',
    });
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

describe('a query the API refuses is refused before sending', () => {
  const fields = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`f${i}`, i]));
  const refusals: Array<[string, QueryRequest]> = [
    ['a filter operator', { filters: { n: { $gt: 1 } } }],
    ['$and', { filters: { $and: [{ n: 1 }] } }],
    ['$or', { filters: { $or: [] } }],
    ['$not', { filters: { $not: 1 } }],
    ['$nor', { filters: { $nor: [] } }],
    ['33 filter fields', { filters: fields(33) }],
    ['a filter field of 257 bytes', { filters: { [`a${'\u00e9'.repeat(128)}`]: 1 } }],
    ['a filter value of 4,097 bytes', { filters: { s: 'a'.repeat(4095) } }],
    ['a filter value of 4,098 bytes once escaped', { filters: { s: '"'.repeat(2048) } }],
    ['a filter value of 4,100 bytes of control characters', { filters: { s: '\u0001'.repeat(683) } }],
    ['an array filter value of 4,097 bytes', { filters: { a: Array(2046).fill(1).concat([111]) } }],
    ['filters as an array', { filters: [] as unknown as QueryRequest['filters'] }],
    ['filters as a string', { filters: 'x' as unknown as QueryRequest['filters'] }],
    ['search', { search: { field: 'id', query: 'a' } }],
    ['includes', { includes: ['x'] } as unknown as QueryRequest],
    ['a sort order other than asc or desc', { sort: { field: 'n', order: 'DESC' as 'desc' } }],
    ['a sort with another key', { sort: { field: 'n', order: 'asc', nulls: 'first' } as QueryRequest['sort'] }],
    ['a sort without an order', { sort: { field: 'n' } as QueryRequest['sort'] }],
    ['a sort field of 257 bytes', { sort: { field: 'a'.repeat(257), order: 'asc' } }],
    ['a fractional limit', { limit: 1.5 }],
    ['a negative offset', { offset: -1 }],
    ['a limit past u32', { limit: 2 ** 32 }],
    ['a lone surrogate', { filters: { s: '\ud800' } }],
    ['a key the API does not read', { where: { a: 1 } } as unknown as QueryRequest],
  ];

  it.each(refusals)('%s', async (_, query) => {
    expect(() => querySelection({ ...query, include_proof: true })).toThrow(QueryRefusedError);
    const fetchMock = jest.fn();
    const realFetch = global.fetch;
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
      await expect(d.query('s1', query)).rejects.toMatchObject({
        code: 'QUERY_REFUSED',
        message: expect.stringMatching(/^The API refuses this query: /),
      });
      await expect(d.queryUnverified('s1', query)).rejects.toThrow(QueryRefusedError);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      global.fetch = realFetch;
    }
  });

  const accepted: Array<[string, QueryRequest]> = [
    ['32 filter fields', { filters: fields(32) }],
    ['a filter field of 256 bytes', { filters: { [`${'\u00e9'.repeat(128)}`]: 1 } }],
    ['a filter value of 4,096 bytes', { filters: { s: 'a'.repeat(4094) } }],
    ['a filter value of 4,096 bytes once escaped', { filters: { s: '"'.repeat(2047) } }],
    ['an array filter value of 4,096 bytes', { filters: { a: Array(2046).fill(1).concat([11]) } }],
    ['a sort field of 256 bytes', { sort: { field: 'a'.repeat(256), order: 'desc' } }],
    ['null filters, search, and sort', { filters: null, search: null, sort: null } as unknown as QueryRequest],
    ['empty includes', { includes: [] } as unknown as QueryRequest],
    ['$comment, an ordinary field', { filters: { $comment: 'x' } }],
    ['a limit of u32::MAX', { limit: 2 ** 32 - 1, offset: 0 }],
  ];

  it.each(accepted)('%s is sent', async (_, query) => {
    expect(() => querySelection({ ...query, include_proof: true })).not.toThrow();
    const realFetch = global.fetch;
    const fetchMock = jest.fn(async () => {
      const body = { success: true, data: { documents: [], total: 0, offset: 0, limit: 100 } };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
      await d.queryUnverified('s1', query);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      global.fetch = realFetch;
    }
  });

  it("a filter value the SDK can't read as the API does is not verifiable, and is sent unverified", async () => {
    const query = { filters: { v: [{ '$serde_json::private::Number': '1' }] } };
    expect(() => querySelection({ ...query, include_proof: true })).toThrow(QueryNotVerifiableError);
    const realFetch = global.fetch;
    const fetchMock = jest.fn(async () => {
      const body = { success: true, data: { documents: [], total: 0, offset: 0, limit: 100 } };
      return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
    });
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
      await expect(d.query('s1', query)).rejects.toMatchObject({ code: 'QUERY_NOT_VERIFIABLE' });
      expect(fetchMock).not.toHaveBeenCalled();
      await d.queryUnverified('s1', query);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      global.fetch = realFetch;
    }
  });

  it('a NaN limit is sent as null, and the API takes its default', () => {
    expect(querySelection({ limit: NaN, include_proof: true }).limit).toBe(100);
  });

  it('a filter value is measured as the API writes it back', () => {
    const length = (text: string) => nodeJsonTextLength(parseNodeJsonText(text)!);
    expect(length('[1.50,-0,1E5,null,true,false]')).toBe('[1.50,0,1e+5,null,true,false]'.length);
    // `/` and non-ASCII are written as they are; `"`, `\\`, and control characters escaped.
    expect(length('"\\/\u00e9\ud83d\ude00"')).toBe(2 + 1 + 2 + 4);
    expect(length('"\\"\\\\\\b\\t\\n\\f\\r\\u0001\\u007f"')).toBe(2 + 2 * 7 + 6 + 1);
    expect(length('[{"a":1,"a":2},{}]')).toBe('[{"a":2},{}]'.length);
  });
});

describe("the API's selection, cross-checked with the node's query engine", () => {
  // The expected orders and match sets below are the node's, read from its
  // query engine (willow-indexing `query_engine.rs`: `sort_documents` with
  // `SortKey::total_cmp`, `apply_filters` with `json_values_equal`,
  // `numbers_equal`, and `exact_decimal`, and `get_field_value`): a stable
  // sort by kind (missing < null < false < true < numbers < strings < arrays
  // < objects), numbers by their f64 (none first), strings by code point;
  // every filter an exact match, numbers by exact decimal value.
  // Each document's `id` is its key; k22 is the one that is not an object, and k23 is not JSON.
  const TABLE: Array<[string, string]> = [
    ['k00', '{"v":2}'],
    ['k01', '{"v":"b"}'],
    ['k02', '{}'],
    ['k03', '{"v":null}'],
    ['k04', '{"v":true}'],
    ['k05', '{"v":false}'],
    ['k06', '{"v":[1]}'],
    ['k07', '{"v":{"a":1}}'],
    ['k08', '{"v":1.0}'],
    ['k09', '{"v":-1e400}'],
    ['k10', '{"v":"a"}'],
    ['k11', '{"v":"\\ud83d\\ude00"}'],
    ['k12', '{"v":"\\uffff"}'],
    ['k13', '{"v":1}'],
    ['k14', '{"v":1e400}'],
    ['k15', '{"v":[]}'],
    ['k16', '{"v":-0}'],
    ['k17', '{"v":0.0}'],
    ['k18', '{"v":10e-1}'],
    ['k19', '{"v":"A"}'],
    ['k20', '{"v":{}}'],
    ['k21', '{"v":null}'],
    ['k22', '5'],
    ['k23', '{"v":'],
    ['k24', '{"v":[1.0,{"a":1E0}],"m":{"k":"x"}}'],
    ['k25', '{"v":[1,{"a":1}],"m":{"k":"y"}}'],
    ['k26', '{"v":"b","m":{"k":"x"}}'],
    ['k27', '{"v.w":1,"m":["x"]}'],
  ];
  const entries = TABLE.map(([key, text]) => {
    const item = text.startsWith('{') && text.endsWith('}') ? `{"id":"${key}"${text.length > 2 ? ',' : ''}${text.slice(1)}` : text;
    return {
      key: enc(key),
      value: itemElement(enc(item)),
      element: { type: 'Item' as const, value: enc(item), flags: null },
      reference: false,
    };
  });
  const run = (selection: Partial<QuerySelection>) =>
    selectDocuments(entries, { filters: [], sort: null, offset: 0, limit: 100, ...selection }).documents.map((doc) => {
      const id = doc.t === 'obj' ? doc.v.get('id') : undefined;
      return id?.t === 'str' ? id.v : 'k22';
    });
  const where = (filters: Record<string, string>) =>
    run({ filters: Object.entries(filters).map(([field, text]) => ({ field, value: parseNodeJsonText(text)! })) });

  it('sorts ascending and descending in the total order, ties in key order', () => {
    expect(run({ sort: { field: 'v', descending: false } })).toEqual([
      'k02', 'k22', 'k27', // missing (k22 is not an object; k27's key is "v.w")
      'k03', 'k21', // null
      'k05', // false
      'k04', // true
      'k09', 'k14', // numbers with no finite f64
      'k16', 'k17', // 0
      'k08', 'k13', 'k18', // 1
      'k00', // 2
      'k19', 'k10', 'k01', 'k26', 'k12', 'k11', // "A" < "a" < "b" = "b" < U+FFFF < U+1F600
      'k06', 'k15', 'k24', 'k25', // arrays tie
      'k07', 'k20', // objects tie
    ]);
    expect(run({ sort: { field: 'v', descending: true } })).toEqual([
      'k07', 'k20',
      'k06', 'k15', 'k24', 'k25',
      'k11', 'k12', 'k01', 'k26', 'k10', 'k19',
      'k00',
      'k08', 'k13', 'k18',
      'k16', 'k17',
      'k09', 'k14',
      'k04',
      'k05',
      'k03', 'k21',
      'k02', 'k22', 'k27',
    ]);
    // A dotted sort field reaches into objects only.
    expect(run({ sort: { field: 'm.k', descending: true } }).slice(0, 3)).toEqual(['k25', 'k24', 'k26']);
  });

  it('matches every filter, numbers by exact decimal value, arrays and objects element by element', () => {
    expect(where({ v: '1' })).toEqual(['k08', 'k13', 'k18']);
    expect(where({ v: '1.000e0' })).toEqual(['k08', 'k13', 'k18']);
    expect(where({ v: '0' })).toEqual(['k16', 'k17']);
    expect(where({ v: '-0.0' })).toEqual(['k16', 'k17']);
    expect(where({ v: '1e400' })).toEqual(['k14']);
    expect(where({ v: '-1E+400' })).toEqual(['k09']);
    expect(where({ v: 'null' })).toEqual(['k03', 'k21']);
    expect(where({ v: 'false' })).toEqual(['k05']);
    expect(where({ v: '"b"' })).toEqual(['k01', 'k26']);
    expect(where({ v: '[]' })).toEqual(['k15']);
    expect(where({ v: '[1e0]' })).toEqual(['k06']);
    expect(where({ v: '[1,{"a":1.0}]' })).toEqual(['k24', 'k25']);
    expect(where({ v: '[1,{"a":1,"b":2}]' })).toEqual([]);
    expect(where({ v: '"b"', 'm.k': '"x"' })).toEqual(['k26']);
    expect(where({ 'm.k': '"x"' })).toEqual(['k24', 'k26']);
    expect(where({ 'v.w': '1' })).toEqual([]);
    expect(where({ 'm.0': '"x"' })).toEqual([]);
    expect(where({ v: '1', 'm.k': '"x"' })).toEqual([]);
  });

  it("compares numbers as the node's exact_decimal does, texts where an exponent passes an i128", () => {
    const max = '170141183460469231731687303715884105727'; // i128::MAX
    const cases: Array<[string, string, boolean]> = [
      ['1', '1.0', true],
      ['1', '1e+0', true],
      ['100', '1e+2', true],
      ['1.5', '15e-1', true],
      ['0', '-0.0', true],
      ['0', '0e+5', true],
      ['-1', '1', false],
      ['12345678901234567890', '12345678901234567891', false],
      ['9007199254740993', '9007199254740992', false],
      [`1e+${max}`, `10e+${BigInt(max) - 1n}`, true],
      [`10e+${max}`, `1e+${BigInt(max) + 1n}`, false], // + a trailing zero passes i128::MAX
      [`1e+${BigInt(max) + 1n}`, `1.0e+${BigInt(max) + 1n}`, false], // past i128: texts differ
      [`1e+${BigInt(max) + 1n}`, `1e+${BigInt(max) + 1n}`, true],
      [`1e-${BigInt(max) + 1n}`, `0.1e-${max}`, true], // i128::MIN
      [`1.0e-${BigInt(max) + 1n}`, `1e-${BigInt(max) + 1n}`, false], // - a fraction digit passes i128::MIN
      [`0e+${BigInt(max) + 1n}`, '0', false],
      [`0e+${max}`, '0', true],
      [`1e+${'0'.repeat(60)}5`, '1e+5', true],
    ];
    for (const [a, b, equal] of cases) {
      expect([a, b, nodeNumbersEqual(a, b), nodeNumbersEqual(b, a)]).toEqual([a, b, equal, equal]);
    }
    expect(nodeExactDecimal('-0.0')).toEqual({ negative: false, digits: '', exponent: 0n });
    expect(nodeExactDecimal('-12.3400e+2')).toEqual({ negative: true, digits: '1234', exponent: 0n });
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

