/**
 * `getMultiple` and `getMultipleUnverified` return each key's value as an
 * own property of an object with no inherited keys: a key named
 * `__proto__` is a key like any other, and a key left out reads as absent.
 */
import { WillowData } from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';
import { subgroveDataPath } from '../src/proof';
import { Merk, groveProof, hex, pathProof } from './helpers/grove-proof';

const STORED = '{"role":"admin","balance":1000000}';
const data = new Merk([
  { key: '__proto__', item: STORED },
  { key: 'zz', item: '{"n":1}' },
]);
const state = new Merk([
  { key: 'subgroves', tree: new Merk([{ key: 's1', tree: new Merk([{ key: 'data', tree: data }]) }]) },
]);
const ROOT = hex(state.rootHash());
// Both keys revealed: `role` and `constructor` fall between them, so this proves them absent.
const PROOF = hex(groveProof(pathProof(state, subgroveDataPath('s1'), ['__proto__', 'zz'])));

const reply = (body: unknown) =>
  ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) }) as unknown as Response;

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

/** The API: `__proto__` holds STORED, every other key is absent; every proof is PROOF. */
function serve() {
  global.fetch = jest.fn(async (url: string) => {
    const [, route, , key] = new URL(url).pathname.split('/');
    if (route === 'data') {
      return key === '__proto__'
        ? reply({ success: true, data: JSON.parse(STORED) })
        : reply({ success: false, error: 'Data not found' });
    }
    if (route === 'proof') return reply({ success: true, data: { proof: PROOF, height: 7 } });
    throw new Error(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
}

function client(): WillowData {
  const d = new WillowData('http://api.test', new WillowAuth('http://api.test'), new WillowIndexers('http://api.test'));
  (d as any).lightClient = {
    getLatestChainHeight: async () => 7,
    getVerifiedRootHashAtHeight: async () => ROOT,
  };
  return d;
}

describe('a key named __proto__ is returned as a key, not as the prototype', () => {
  for (const method of ['getMultiple', 'getMultipleUnverified'] as const) {
    it(`${method}: a key proven absent reads as absent`, async () => {
      serve();
      const results = await client()[method]('s1', ['__proto__', 'role', 'constructor']);
      expect(Object.keys(results)).toEqual(['__proto__']);
      expect(Object.getOwnPropertyDescriptor(results, '__proto__')?.value).toEqual(JSON.parse(STORED));
      expect(results.role).toBeUndefined();
      expect(results.constructor).toBeUndefined();
      expect('role' in results).toBe(false);
      expect('toString' in results).toBe(false);
      expect(JSON.stringify(results)).toBe(`{"__proto__":${STORED}}`);
    });
  }
});
