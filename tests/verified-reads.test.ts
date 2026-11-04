/**
 * Verified key reads and the checks around them: a proof's height must be
 * near the chain's latest, a key reported absent must be proven absent, a
 * proof at height H is checked against the header of H+1, proven bytes are
 * read as UTF-8 strictly, and options that verify nothing are refused.
 */
import { WillowData } from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';
import { verifyItemProof, subgroveDataPath } from '../src/proof';
import { LightClient } from '../src/light-client/client';
import { createTrustThreshold } from '../src/light-client/types';
import { hexToBytes } from '../src/grovedb';
import { VerifiableRpcOperations } from '../src/verifiable-rpc';
import { Merk, chainProof, enc, groveProof, hex, oneItemLayer, pathProof } from './helpers/grove-proof';

const DOC_A = { owner: 'alice', n: 1 };
const DOC_C = { owner: 'carol', n: 3 };
const data = new Merk([
  { key: 'a', item: JSON.stringify(DOC_A) },
  { key: 'c', item: JSON.stringify(DOC_C) },
]);
const s1 = new Merk([{ key: 'data', tree: data }]);
const subgroves = new Merk([{ key: 's1', tree: s1 }]);
const state = new Merk([{ key: 'subgroves', tree: subgroves }]);
const ROOT = hex(state.rootHash());
const PATH = subgroveDataPath('s1');
const proofOf = (reveal: string[]) => hex(groveProof(pathProof(state, PATH, reveal)));

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

const reply = (body: unknown) =>
  ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

/** The API: `/data` for `values`, `/proof` from `proofs` (absent: no proof). */
function serve(values: Record<string, unknown>, proofs: Record<string, string | undefined>, height: unknown = 7) {
  global.fetch = jest.fn(async (url: string) => {
    const [, route, , key] = new URL(url).pathname.split('/');
    if (route === 'data') {
      return key in values
        ? reply({ success: true, data: values[key] })
        : reply({ success: false, error: 'Data not found' });
    }
    if (route === 'proof') {
      const proof = proofs[key];
      return reply(proof ? { success: true, data: { proof, height } } : { success: false, error: 'no proof' });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
}

function client(latest = 7): WillowData {
  const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
  (d as any).lightClient = {
    getLatestChainHeight: async () => latest,
    getVerifiedRootHashAtHeight: async () => ROOT,
  };
  return d;
}

describe('getData and getVerifiedData', () => {
  it('return the value with the root and height it was verified against', async () => {
    serve({ a: DOC_A }, { a: proofOf(['a']) });
    await expect(client().getVerifiedData('s1', 'a')).resolves.toEqual({ data: DOC_A, rootHash: ROOT, height: 7 });
    await expect(client().getData('s1', 'a')).resolves.toEqual(DOC_A);
  });

  it('refuse a proof far from the chain, or naming no height', async () => {
    serve({ a: DOC_A }, { a: proofOf(['a']) });
    await expect(client(1_000).getData('s1', 'a')).rejects.toMatchObject({ code: 'PROOF_HEIGHT_OUT_OF_RANGE' });
    serve({ a: DOC_A }, { a: proofOf(['a']) }, null);
    await expect(client().getData('s1', 'a')).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
  });
});

describe('getMultiple leaves a key out only when it is proven absent', () => {
  it('a key between two proven neighbours is absent', async () => {
    serve({ a: DOC_A }, { a: proofOf(['a']), b: proofOf(['a', 'c']) });
    await expect(client().getMultiple('s1', ['a', 'b'])).resolves.toEqual({ a: DOC_A });
  });

  it('a key the proof does not prove absent, or with no proof, throws', async () => {
    // Revealing `a` alone leaves `c` a pruned subtree, where `b` could be.
    serve({ a: DOC_A }, { a: proofOf(['a']), b: proofOf(['a']) });
    await expect(client().getMultiple('s1', ['a', 'b'])).rejects.toMatchObject({
      code: 'PROOF_VERIFICATION_FAILED',
    });
    // A present key the API calls absent.
    serve({}, { c: proofOf(['c']) });
    await expect(client().getMultiple('s1', ['c'])).rejects.toMatchObject({ code: 'PROOF_VERIFICATION_FAILED' });
    serve({}, {});
    await expect(client().getMultiple('s1', ['b'])).rejects.toMatchObject({ code: 'MISSING_PROOF' });
  });

  it("an absence proof's root and height are checked like any other", async () => {
    serve({}, { b: proofOf(['a', 'c']) });
    await expect(client(1_000).getMultiple('s1', ['b'])).rejects.toMatchObject({
      code: 'PROOF_HEIGHT_OUT_OF_RANGE',
    });
  });
});

describe('proven bytes are read as UTF-8 strictly', () => {
  /** A proof of `s1`'s key `k` holding `payload`, and its root (hex). */
  function itemProof(payload: Uint8Array) {
    const leaf = oneItemLayer('k', payload);
    const { proof, root } = chainProof(PATH, leaf.ops, leaf.root, enc('k'));
    return { proof: hex(proof), root: hex(root) };
  }

  it('a byte-order mark is not JSON text', async () => {
    const bom = itemProof(Uint8Array.from([0xef, 0xbb, 0xbf, ...enc('{"a":1}')]));
    await expect(verifyItemProof(bom.proof, 'k', { a: 1 }, PATH)).rejects.toThrow(/does not match/);
    const plain = itemProof(enc('{"a":1}'));
    await expect(verifyItemProof(plain.proof, 'k', { a: 1 }, PATH)).resolves.toBe(plain.root);
  });

  it('a byte that is not UTF-8 is not read as U+FFFD', async () => {
    const bad = itemProof(Uint8Array.from([...enc('{"a":"'), 0xff, ...enc('"}')]));
    await expect(verifyItemProof(bad.proof, 'k', { a: '\ufffd' }, PATH)).rejects.toThrow(/does not match/);
    const good = itemProof(enc('{"a":"\ufffd"}'));
    await expect(verifyItemProof(good.proof, 'k', { a: '\ufffd' }, PATH)).resolves.toBe(good.root);
  });
});

describe('LightClient', () => {
  function lightClient(endpoints: string[], minValidatorsForConsensus = 1) {
    return new LightClient({
      chainId: 'test-chain',
      validatorEndpoints: endpoints,
      requestTimeoutSecs: 2,
      syncIntervalSecs: 30,
      autoSync: false,
      minValidatorsForConsensus,
      trustThreshold: createTrustThreshold(),
    });
  }

  const status = (height: number) =>
    reply({ result: { sync_info: { latest_block_height: String(height), latest_app_hash: 'AA'.repeat(32) } } });

  it('getLatestChainHeight: the highest height enough endpoints have reached', async () => {
    const heights: Record<string, number> = { 'http://v1': 100, 'http://v2': 104, 'http://v3': 9_999 };
    global.fetch = jest.fn(async (url: string) => status(heights[new URL(url).origin])) as unknown as typeof fetch;
    await expect(lightClient(['http://v1', 'http://v2', 'http://v3'], 2).getLatestChainHeight()).resolves.toBe(104);
    await expect(lightClient(['http://v1', 'http://v2', 'http://v3'], 1).getLatestChainHeight()).resolves.toBe(9_999);
    global.fetch = jest.fn(async () => {
      throw new Error('down');
    }) as unknown as typeof fetch;
    await expect(lightClient(['http://v1'], 1).getLatestChainHeight()).rejects.toThrow(/endpoints reported/);
  });

  it('verifyQueryProof checks a proof at height H against the header of H+1', async () => {
    const lc = lightClient(['http://v1']);
    const proof = hexToBytes(proofOf(['a', 'c']));
    const spy = jest
      .spyOn(lc, 'getHeaderByHeight')
      .mockImplementation(async (h: number) => ({ header: { height: h, appHash: hexToBytes(ROOT) } }) as any);
    const result = await lc.verifyQueryProof({ proof, pathQuery: {}, height: 41 });
    expect(spy).toHaveBeenCalledWith(42);
    expect(result).toMatchObject({ success: true, height: 41 });
  });
});

describe('VerifiableRpc', () => {
  it('refuses anchorStateRoot, which it does not implement, before fetching', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    await expect(
      new VerifiableRpcOperations('http://indexer.test').verify('s1', 'k', { anchorStateRoot: true }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
