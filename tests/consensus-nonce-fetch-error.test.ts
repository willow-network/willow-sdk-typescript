import { ConsensusClient } from '../src/consensus/client';

describe('ConsensusClient.getNextNonce — propagate fetch errors instead of fabricating nonce=1', () => {
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
      (client as any).getNextNonce('did:willow:unseen'),
    ).rejects.toThrow(/HTTP 401|Failed to fetch nonce/);
  });

  it('throws when the fetch itself rejects and no nonce is cached', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('network down')) as any;

    const client = new ConsensusClient({ apiUrl: 'http://stub', consensusRpcUrl: 'http://stub' });
    await expect(
      (client as any).getNextNonce('did:willow:unseen'),
    ).rejects.toThrow(/network down|Failed to fetch nonce/);
  });

  it('still falls back to cache if a nonce was previously fetched (transient API hiccup)', async () => {
    let calls = 0;
    global.fetch = jest.fn().mockImplementation(() => {
      calls += 1;
      if (calls === 1) {
        return Promise.resolve({ ok: true, status: 200, json: async () => ({ success: true, data: { nonce: 5 } }) });
      }
      return Promise.resolve({ ok: false, status: 503, json: async () => ({ error: 'upstream down' }) });
    }) as any;

    const client = new ConsensusClient({ apiUrl: 'http://stub', consensusRpcUrl: 'http://stub' });
    expect(await (client as any).getNextNonce('did:willow:seen')).toBe(6);
    expect(await (client as any).getNextNonce('did:willow:seen')).toBe(7);
  });
});
