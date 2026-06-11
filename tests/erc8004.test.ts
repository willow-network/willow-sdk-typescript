import { Erc8004Client } from '../src/erc8004';
import { WillowError } from '../src/types';

const API_URL = 'http://api.test';

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

beforeEach(() => jest.clearAllMocks());

describe('Erc8004Client — envelope parsing', () => {
  it('listAgents builds the query string and unwraps the data envelope', async () => {
    const data = {
      agents: [
        {
          did: 'did:willow:agent',
          eth_address: '0xabc',
          agent_uri: 'https://agent.test',
          chain_id: 1,
          agent_id: 7,
          validation_count: 3,
          registered_at: 100,
        },
      ],
      total: 1,
      offset: 10,
      limit: 5,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data }));

    const client = new Erc8004Client(API_URL);
    const result = await client.listAgents({ limit: 5, offset: 10 });

    expect(result).toEqual(data);
    expect(mockFetch.mock.calls[0][0]).toBe(`${API_URL}/agents?limit=5&offset=10`);
  });

  it('getAgentRegistration URL-encodes the DID', async () => {
    const registration = { type: 'agent', name: 'a', services: [] };
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data: registration }));

    const client = new Erc8004Client(API_URL);
    const result = await client.getAgentRegistration('did:willow:agent');

    expect(result).toEqual(registration);
    expect(mockFetch.mock.calls[0][0]).toBe(
      `${API_URL}/agent/${encodeURIComponent('did:willow:agent')}/registration.json`,
    );
  });

  it('getValidationStatus encodes limit and subgrove_id filters', async () => {
    const data = { did: 'did:willow:agent', validations: [], total: 0 };
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data }));

    const client = new Erc8004Client(API_URL);
    const result = await client.getValidationStatus('did:willow:agent', 20, 'sg/1');

    expect(result).toEqual(data);
    expect(mockFetch.mock.calls[0][0]).toBe(
      `${API_URL}/agent/${encodeURIComponent('did:willow:agent')}/validation-status` +
        `?limit=20&subgrove_id=${encodeURIComponent('sg/1')}`,
    );
  });

  it('getEthAddress unwraps the nested eth_address field', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ success: true, data: { eth_address: '0xabc' } }),
    );

    const client = new Erc8004Client(API_URL);
    expect(await client.getEthAddress('did:willow:agent')).toBe('0xabc');
  });
});

describe('Erc8004Client — error mapping', () => {
  it('maps a non-2xx response to a typed WillowError with the API error message', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'registry unavailable' }, 500));

    const client = new Erc8004Client(API_URL);
    const err = await client.listAgents().catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('AGENT_LIST_FAILED');
    expect(err.statusCode).toBe(500);
    expect(err.message).toBe('registry unavailable');
  });

  it('maps a 200 envelope with success:false to a typed WillowError', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: false, error: 'no attestation' }));

    const client = new Erc8004Client(API_URL);
    const err = await client.getReputationAttestation('did:willow:agent').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('REPUTATION_ATTESTATION_FAILED');
    expect(err.message).toBe('no attestation');
  });

  it('falls back to the module error message when the body has no error field', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({}, 503));

    const client = new Erc8004Client(API_URL);
    const err = await client.getReputationHistory('did:willow:agent').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('REPUTATION_HISTORY_FAILED');
    expect(err.statusCode).toBe(503);
    expect(err.message).toMatch(/Failed to fetch reputation history/);
  });

  it('propagates non-HTTP failures (network errors) unchanged', async () => {
    mockFetch.mockRejectedValueOnce(new Error('connection refused'));

    const client = new Erc8004Client(API_URL);
    const err = await client.listAgents().catch((e) => e);
    expect(err).not.toBeInstanceOf(WillowError);
    expect(err.message).toMatch(/connection refused/);
  });
});

describe('Erc8004Client — 404-as-null lookups', () => {
  it.each([
    ['getEthAddress', (c: Erc8004Client) => c.getEthAddress('did:willow:missing')],
    ['getDidForEth', (c: Erc8004Client) => c.getDidForEth('0xmissing')],
    ['getErc8004Details', (c: Erc8004Client) => c.getErc8004Details('did:willow:missing')],
  ])('%s resolves to null on 404', async (_name, call) => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'not found' }, 404));

    const client = new Erc8004Client(API_URL);
    expect(await call(client)).toBeNull();
  });

  it('still throws on non-404 failures', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, 500));

    const client = new Erc8004Client(API_URL);
    const err = await client.getEthAddress('did:willow:agent').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('ETH_ADDRESS_FETCH_FAILED');
    expect(err.statusCode).toBe(500);
  });

  it('getDidForEth returns the linked DID when present', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ success: true, data: { did: 'did:willow:linked' } }),
    );

    const client = new Erc8004Client(API_URL);
    expect(await client.getDidForEth('0xabc')).toBe('did:willow:linked');
  });
});
