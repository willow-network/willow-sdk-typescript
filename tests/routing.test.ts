// Tests for WillowData.graphqlQuery / sqlQuery source routing.
//
// Mocking strategy: the global fetch used by the SDK's HttpClient is
// mocked. We inspect the requested URLs to tell apart validator vs
// indexer requests (the validator is `http://validator:3031`, indexers
// are absolute URLs from discovery).

import {
  WillowData,
  ValidatorHasNoDataError,
  NoIndexersReachableError,
} from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

const auth = new WillowAuth('http://validator:3031');

function makeData(indexerUrl?: string): WillowData {
  const indexers = new WillowIndexers('http://validator:3031', { indexerUrl });
  return new WillowData('http://validator:3031', auth, indexers);
}

interface StubEntry {
  did: string;
  subgroves: string[];
  endpoint: string;
  perf?: number;
  status?: string;
}

function discoveryBody(entries: StubEntry[]) {
  return {
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
  };
}

// Route fetch by URL: `/indexers` serves discovery, everything else is
// handled by `onPost` (the GraphQL/SQL POST under test).
function stubFetch(
  entries: StubEntry[],
  onPost: (url: string, init: RequestInit) => Promise<Response> | Response,
) {
  mockFetch.mockImplementation((url: string, init: RequestInit) => {
    if (url === 'http://validator:3031/indexers') {
      return Promise.resolve(jsonResponse(discoveryBody(entries)));
    }
    return Promise.resolve(onPost(url, init));
  });
}

/** URLs of all non-discovery requests, in call order. */
function postUrls(): string[] {
  return mockFetch.mock.calls
    .map((c) => c[0] as string)
    .filter((u) => u !== 'http://validator:3031/indexers');
}

beforeEach(() => {
  jest.clearAllMocks();
});

describe("source: 'validator'", () => {
  it('POSTs to the validator apiUrl and returns validator source', async () => {
    stubFetch([], () => jsonResponse({ data: { hello: 'world' } }));

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ hello }', { source: 'validator' });

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(false);
    expect(postUrls()).toEqual(['http://validator:3031/graphql/sg-1']);
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toMatchObject({ query: '{ hello }' });
  });

  it('throws ValidatorHasNoDataError on 404 (VerifyOnly subgrove)', async () => {
    stubFetch([], () =>
      jsonResponse({ error: 'subgrove uses VerifyOnly retention' }, 404),
    );

    const data = makeData();
    await expect(
      data.sqlQuery('verifyonly-sg', 'SELECT 1', { source: 'validator' }),
    ).rejects.toBeInstanceOf(ValidatorHasNoDataError);
  });

  it('throws ValidatorHasNoDataError on 403 (private/forbidden)', async () => {
    stubFetch([], () => jsonResponse({ error: 'not available' }, 403));

    const data = makeData();
    await expect(
      data.graphqlQuery('private-sg', '{}', { source: 'validator' }),
    ).rejects.toBeInstanceOf(ValidatorHasNoDataError);
  });
});

describe("source: 'indexer' — discovered", () => {
  it('routes to the best-performing indexer that serves the subgrove', async () => {
    stubFetch(
      [
        { did: 'indexer-slow', subgroves: ['sg-1'], endpoint: 'http://slow:3032', perf: 50 },
        { did: 'indexer-fast', subgroves: ['sg-1'], endpoint: 'http://fast:3032', perf: 99 },
      ],
      () => jsonResponse({ data: { ok: true } }),
    );

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }', { source: 'indexer' });

    expect(res.source).toBe('indexer');
    expect(res.indexerDid).toBe('indexer-fast');
    expect(postUrls()).toEqual(['http://fast:3032/graphql/sg-1']);
  });

  it('falls through to next indexer on network failure', async () => {
    stubFetch(
      [
        { did: 'down', subgroves: ['sg-1'], endpoint: 'http://down:3032', perf: 100 },
        { did: 'up', subgroves: ['sg-1'], endpoint: 'http://up:3032', perf: 50 },
      ],
      (url) => {
        if (url.startsWith('http://down:3032')) throw new Error('ECONNREFUSED');
        return jsonResponse({ data: { ok: true } });
      },
    );

    const data = makeData();
    const res = await data.sqlQuery('sg-1', 'SELECT 1', { source: 'indexer' });

    expect(res.indexerDid).toBe('up');
    expect(postUrls()).toHaveLength(2);
  });

  it('throws NoIndexersReachableError when no indexer serves the subgrove', async () => {
    stubFetch(
      [{ did: 'other', subgroves: ['other-sg'], endpoint: 'http://x:3032' }],
      () => jsonResponse({ data: {} }),
    );

    const data = makeData();
    await expect(
      data.graphqlQuery('unserved', '{}', { source: 'indexer' }),
    ).rejects.toBeInstanceOf(NoIndexersReachableError);
  });

  it('throws NoIndexersReachableError when all indexers fail', async () => {
    stubFetch(
      [
        { did: 'a', subgroves: ['sg-1'], endpoint: 'http://a:3032' },
        { did: 'b', subgroves: ['sg-1'], endpoint: 'http://b:3032' },
      ],
      () => {
        throw new Error('boom');
      },
    );

    const data = makeData();
    await expect(
      data.graphqlQuery('sg-1', '{}', { source: 'indexer' }),
    ).rejects.toBeInstanceOf(NoIndexersReachableError);
  });
});

describe("source: 'indexer' — explicit indexerUrl override", () => {
  it('skips discovery and routes directly to the configured URL', async () => {
    mockFetch.mockResolvedValue(jsonResponse({ data: { ok: true } }));

    const data = makeData('http://pinned-indexer:3032');
    const res = await data.graphqlQuery('sg-1', '{ ok }', { source: 'indexer' });

    expect(res.source).toBe('indexer');
    // Discovery endpoint must not have been called
    expect(mockFetch.mock.calls.map((c) => c[0])).toEqual([
      'http://pinned-indexer:3032/graphql/sg-1',
    ]);
  });
});

describe("source: 'auto'", () => {
  it('prefers an indexer when one serves the subgrove', async () => {
    stubFetch(
      [{ did: 'idx', subgroves: ['sg-1'], endpoint: 'http://idx:3032' }],
      () => jsonResponse({ data: { ok: true } }),
    );

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }');

    expect(res.source).toBe('indexer');
    expect(res.fallback).toBe(false);
  });

  it('falls back to validator when no indexer serves the subgrove', async () => {
    stubFetch([], () => jsonResponse({ data: { ok: true } }));

    const data = makeData();
    const res = await data.graphqlQuery('unserved', '{ ok }');

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(false); // no indexer to fall from
  });

  it('falls back to validator with fallback=true when indexer lookup fails', async () => {
    stubFetch(
      [{ did: 'broken', subgroves: ['sg-1'], endpoint: 'http://broken:3032' }],
      (url) => {
        if (url.startsWith('http://broken:3032')) throw new Error('indexer down');
        // Validator fallback call succeeds
        return jsonResponse({ data: { ok: true } });
      },
    );

    const data = makeData();
    const res = await data.graphqlQuery('sg-1', '{ ok }');

    expect(res.source).toBe('validator');
    expect(res.fallback).toBe(true);
  });
});
