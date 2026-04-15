import { WillowIndexers, effectiveQueryEndpoint, ApiIndexerInfo } from '../src/indexers';

// Mock axios so tests don't hit the network. Because WillowIndexers calls
// `axios.create(...)` in its constructor and stores the returned instance,
// we return a shared instance whose `get` we can poke from the test body.
jest.mock('axios', () => {
  const mockInstance = { get: jest.fn() };
  return {
    __esModule: true,
    default: { create: jest.fn(() => mockInstance) },
    _mockInstance: mockInstance,
  };
});

// eslint-disable-next-line @typescript-eslint/no-var-requires
const getMockAxios = () => require('axios')._mockInstance;

const active = (
  did: string,
  subgroves: string[],
  perf: number,
  opts: { query_endpoint?: string; status?: string } = {},
): ApiIndexerInfo => ({
  indexer_did: did,
  subgroves,
  stake_amount: 100,
  endpoint: `http://${did.replace(/[^a-z0-9]/gi, '')}.test:9090`,
  query_endpoint: opts.query_endpoint,
  status: opts.status ?? 'active',
  performance_score: perf,
  last_update: 0,
});

beforeEach(() => jest.clearAllMocks());

describe('effectiveQueryEndpoint', () => {
  it('returns query_endpoint when set', () => {
    const info = active('x', [], 100, { query_endpoint: 'http://q:3032' });
    expect(effectiveQueryEndpoint(info)).toBe('http://q:3032');
  });

  it('falls back to endpoint when query_endpoint is missing', () => {
    const info = active('x', [], 100);
    expect(effectiveQueryEndpoint(info)).toBe('http://x.test:9090');
  });
});

describe('WillowIndexers — discovery mode', () => {
  it('fetches /indexers and caches the response within TTL', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({
      data: { success: true, data: [active('a', ['sg-1'], 90)] },
    });

    const client = new WillowIndexers('http://validator:3031', { cacheTtlMs: 10_000 });
    const first = await client.list();
    const second = await client.list();

    expect(axios.get).toHaveBeenCalledTimes(1);
    expect(axios.get).toHaveBeenCalledWith('/indexers');
    expect(first).toEqual(second);
    expect(first[0].indexer_did).toBe('a');
  });

  it('re-fetches after the cache expires', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({
      data: { success: true, data: [active('a', ['sg-1'], 90)] },
    });

    const client = new WillowIndexers('http://validator:3031', { cacheTtlMs: 1 });
    await client.list();
    // Wait past the 1ms TTL
    await new Promise((resolve) => setTimeout(resolve, 5));
    await client.list();

    expect(axios.get).toHaveBeenCalledTimes(2);
  });

  it('forSubgrove filters active indexers serving the subgrove, sorted by performance', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({
      data: {
        success: true,
        data: [
          active('best', ['sg-shared'], 99),
          active('other-sg', ['sg-other'], 100),
          active('inactive', ['sg-shared'], 100, { status: 'inactive' }),
          active('worst', ['sg-shared'], 20),
        ],
      },
    });

    const client = new WillowIndexers('http://validator:3031');
    const picks = await client.forSubgrove('sg-shared');

    expect(picks.map((p) => p.indexer_did)).toEqual(['best', 'worst']);
  });

  it('evict removes a specific indexer from the cache', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({
      data: {
        success: true,
        data: [active('a', ['sg-1'], 90), active('b', ['sg-1'], 80)],
      },
    });

    const client = new WillowIndexers('http://validator:3031');
    await client.list();
    client.evict('a');

    // Subsequent forSubgrove should not include 'a' even though its TTL is
    // still valid — eviction simulates a 5xx from 'a'.
    const picks = await client.forSubgrove('sg-1');
    expect(picks.map((p) => p.indexer_did)).toEqual(['b']);
  });

  it('invalidate forces the next call to re-fetch', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({
      data: { success: true, data: [active('a', ['sg-1'], 90)] },
    });

    const client = new WillowIndexers('http://validator:3031');
    await client.list();
    client.invalidate();
    await client.list();

    expect(axios.get).toHaveBeenCalledTimes(2);
  });

  it('returns empty array when the validator has no indexers registered', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({ data: { success: true, data: [] } });

    const client = new WillowIndexers('http://validator:3031');
    expect(await client.list()).toEqual([]);
    expect(await client.forSubgrove('any')).toEqual([]);
  });

  it('defends against a missing `data` field in the response envelope', async () => {
    const axios = getMockAxios();
    // Simulate a malformed response (unlikely but we mustn't throw)
    axios.get.mockResolvedValue({ data: { success: false } });

    const client = new WillowIndexers('http://validator:3031');
    expect(await client.list()).toEqual([]);
  });
});

describe('WillowIndexers — explicit indexerUrl override', () => {
  it('skips discovery entirely when indexerUrl is set', async () => {
    const axios = getMockAxios();
    axios.get.mockResolvedValue({ data: { success: true, data: [] } });

    const client = new WillowIndexers('http://validator:3031', {
      indexerUrl: 'http://my-indexer.test:3032',
    });
    expect(client.hasExplicitOverride()).toBe(true);

    const all = await client.list();
    const sg = await client.forSubgrove('whatever');

    expect(axios.get).not.toHaveBeenCalled();
    expect(all).toHaveLength(1);
    expect(all[0].endpoint).toBe('http://my-indexer.test:3032');
    expect(all[0].query_endpoint).toBe('http://my-indexer.test:3032');
    expect(sg).toHaveLength(1);
  });
});
