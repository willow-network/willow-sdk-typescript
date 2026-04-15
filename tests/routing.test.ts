// Tests for WillowData.graphqlQuery / sqlQuery source routing.
//
// Mocking strategy: axios is mocked at the module level. We inspect the
// underlying `post` mock to verify which URL the routing layer actually
// contacted, so we can tell apart validator vs indexer requests by the
// request URL.

import {
  WillowData,
  ValidatorHasNoDataError,
  NoIndexersReachableError,
} from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';

// A mutable mock backing the axios module. `create()` returns the same
// instance as the top-level methods so that whether the code uses
// `axios.create().post(...)` (validator) or `axios.post(...)` (indexer),
// both land in the same spy.
jest.mock('axios', () => {
  const fn = {
    post: jest.fn(),
    get: jest.fn(),
    create: undefined as any,
  };
  fn.create = jest.fn(() => fn);
  return { __esModule: true, default: fn, _mock: fn };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const getAxios = () => require('axios')._mock;

const auth = new WillowAuth('http://validator:3031');

function makeData(indexerUrl?: string): WillowData {
  const indexers = new WillowIndexers('http://validator:3031', { indexerUrl });
  return new WillowData('http://validator:3031', auth, indexers);
}

// Stub the validator's /indexers response via the get() mock.
function stubDiscovery(entries: Array<{ did: string; subgroves: string[]; endpoint: string; perf?: number; status?: string }>) {
  getAxios().get.mockImplementation((path: string) => {
    if (path === '/indexers') {
      return Promise.resolve({
        data: {
          success: true,
          data: entries.map((e) => ({
            indexer_did: e.did,
            subgroves: e.subgroves,
            stake_amount: 100,
            endpoint: e.endpoint,
            query_endpoint: e.endpoint,
            status: e.status ?? 'active',
            performance_score: e.perf ?? 100,
            last_update: 0,
          })),
        },
      });
    }
    return Promise.reject(new Error(`Unexpected GET ${path}`));
  });
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe("source: 'validator'", () => {
  it('POSTs to the validator apiUrl and returns validator source', async () => {
    getAxios().post.mockResolvedValue({ data: { data: { hello: 'world' } } });

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ hello }', { source: 'validator' });

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(false);
    // Axios was given the relative path; verify the axios.create() baseURL
    // by checking the call URL.
    expect(getAxios().post).toHaveBeenCalledWith(
      '/graphql/sg-1',
      expect.objectContaining({ query: '{ hello }' }),
      expect.any(Object),
    );
  });

  it('throws ValidatorHasNoDataError on 404 (VerifyOnly subgrove)', async () => {
    getAxios().post.mockRejectedValue({
      response: { status: 404, data: { error: 'subgrove uses VerifyOnly retention' } },
      message: 'Request failed',
    });

    const data = makeData();
    await expect(
      data.sqlQuery('verifyonly-sg', 'SELECT 1', { source: 'validator' }),
    ).rejects.toBeInstanceOf(ValidatorHasNoDataError);
  });

  it('throws ValidatorHasNoDataError on 403 (private/forbidden)', async () => {
    getAxios().post.mockRejectedValue({
      response: { status: 403, data: { error: 'not available' } },
      message: 'Forbidden',
    });

    const data = makeData();
    await expect(
      data.graphqlQuery('private-sg', '{}', { source: 'validator' }),
    ).rejects.toBeInstanceOf(ValidatorHasNoDataError);
  });
});

describe("source: 'indexer' — discovered", () => {
  it('routes to the best-performing indexer that serves the subgrove', async () => {
    stubDiscovery([
      { did: 'indexer-slow', subgroves: ['sg-1'], endpoint: 'http://slow:3032', perf: 50 },
      { did: 'indexer-fast', subgroves: ['sg-1'], endpoint: 'http://fast:3032', perf: 99 },
    ]);
    getAxios().post.mockResolvedValue({ data: { data: { ok: true } } });

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }', { source: 'indexer' });

    expect(res.source).toBe('indexer');
    expect(res.indexerDid).toBe('indexer-fast');
    // URL of the indexer POST should start with the fast indexer's endpoint
    expect(getAxios().post).toHaveBeenCalledWith(
      expect.stringContaining('http://fast:3032/graphql/sg-1'),
      expect.any(Object),
      expect.any(Object),
    );
  });

  it('falls through to next indexer on network failure', async () => {
    stubDiscovery([
      { did: 'down', subgroves: ['sg-1'], endpoint: 'http://down:3032', perf: 100 },
      { did: 'up', subgroves: ['sg-1'], endpoint: 'http://up:3032', perf: 50 },
    ]);
    getAxios()
      .post.mockRejectedValueOnce({ message: 'ECONNREFUSED' })
      .mockResolvedValueOnce({ data: { data: { ok: true } } });

    const data = makeData();
    const res = await data.sqlQuery('sg-1', 'SELECT 1', { source: 'indexer' });

    expect(res.indexerDid).toBe('up');
    expect(getAxios().post).toHaveBeenCalledTimes(2);
  });

  it('throws NoIndexersReachableError when no indexer serves the subgrove', async () => {
    stubDiscovery([{ did: 'other', subgroves: ['other-sg'], endpoint: 'http://x:3032' }]);

    const data = makeData();
    await expect(
      data.graphqlQuery('unserved', '{}', { source: 'indexer' }),
    ).rejects.toBeInstanceOf(NoIndexersReachableError);
  });

  it('throws NoIndexersReachableError when all indexers fail', async () => {
    stubDiscovery([
      { did: 'a', subgroves: ['sg-1'], endpoint: 'http://a:3032' },
      { did: 'b', subgroves: ['sg-1'], endpoint: 'http://b:3032' },
    ]);
    getAxios().post.mockRejectedValue({ message: 'boom' });

    const data = makeData();
    await expect(
      data.graphqlQuery('sg-1', '{}', { source: 'indexer' }),
    ).rejects.toBeInstanceOf(NoIndexersReachableError);
  });
});

describe("source: 'indexer' — explicit indexerUrl override", () => {
  it('skips discovery and routes directly to the configured URL', async () => {
    getAxios().post.mockResolvedValue({ data: { data: { ok: true } } });

    const data = makeData('http://pinned-indexer:3032');
    const res = await data.graphqlQuery('sg-1', '{ ok }', { source: 'indexer' });

    expect(res.source).toBe('indexer');
    // Discovery endpoint must not have been called
    expect(getAxios().get).not.toHaveBeenCalled();
    expect(getAxios().post).toHaveBeenCalledWith(
      'http://pinned-indexer:3032/graphql/sg-1',
      expect.any(Object),
      expect.any(Object),
    );
  });
});

describe("source: 'auto'", () => {
  it('prefers an indexer when one serves the subgrove', async () => {
    stubDiscovery([{ did: 'idx', subgroves: ['sg-1'], endpoint: 'http://idx:3032' }]);
    getAxios().post.mockResolvedValue({ data: { data: { ok: true } } });

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }');

    expect(res.source).toBe('indexer');
    expect(res.fallback).toBe(false);
  });

  it('falls back to validator when no indexer serves the subgrove', async () => {
    stubDiscovery([]);
    getAxios().post.mockResolvedValue({ data: { data: { ok: true } } });

    const data = makeData();
    const res = await data.graphqlQuery('unserved', '{ ok }');

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(false); // no indexer to fall from
  });

  it('falls back to validator with fallback=true when indexer lookup fails', async () => {
    stubDiscovery([{ did: 'broken', subgroves: ['sg-1'], endpoint: 'http://broken:3032' }]);
    getAxios()
      .post.mockRejectedValueOnce({ message: 'indexer down' })
      // Validator fallback call succeeds
      .mockResolvedValueOnce({ data: { data: { ok: true } } });

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }');

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(true);
  });
});
