import { ConsensusClient } from '../src/consensus/client';
import { NonceAllocator } from '../src/consensus/nonces';

describe('ConsensusClient.nextNonce — propagate fetch errors instead of fabricating nonce=1', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; });

  it('throws when the API returns 401 and no nonce is cached', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ error: 'unauthorized' }),
    }) as any;

    const client = new ConsensusClient({ apiUrl: 'http://stub', consensusRpcUrl: 'http://stub' });
    await expect(
      client.nextNonce('did:willow:unseen'),
    ).rejects.toThrow(/HTTP 401|Failed to fetch nonce/);
  });

  it('throws when the fetch itself rejects and no nonce is cached', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as any;

    const client = new ConsensusClient({ apiUrl: 'http://stub', consensusRpcUrl: 'http://stub' });
    await expect(
      client.nextNonce('did:willow:unseen'),
    ).rejects.toThrow(/network down|Failed to fetch nonce/);
  });

  it('falls back to the last state seen if one was read before (transient API hiccup)', async () => {
    let apiCalls = 0;
    global.fetch = jest.fn().mockImplementation((url: string) => {
      if (url === 'http://rpc') return Promise.reject(new Error('rpc down'));
      apiCalls += 1;
      if (apiCalls === 1) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ success: true, data: { nonce: 5 } }) });
      }
      return Promise.resolve({ ok: false, status: 503, json: async () => ({ error: 'upstream down' }) });
    }) as any;

    const client = new ConsensusClient({
      apiUrl: 'http://stub',
      consensusRpcUrl: 'http://rpc',
      nonceAllocator: new NonceAllocator(),
    });
    expect(await client.nextNonce('did:willow:seen')).toBe(6);
    // 6 is still handed out, so the next is 7.
    expect(await client.nextNonce('did:willow:seen')).toBe(7);
  });
});
