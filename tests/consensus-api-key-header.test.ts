import { ConsensusClient } from '../src/consensus/client';

describe('ConsensusClient — X-API-Key header forwarded on every fetch', () => {
  const originalFetch = global.fetch;
  afterEach(() => { global.fetch = originalFetch; });

  function lastHeaders(spy: jest.Mock): Record<string, string> {
    const init = spy.mock.calls.at(-1)?.[1];
    return (init?.headers ?? {}) as Record<string, string>;
  }

  it('omits X-API-Key when apiKey is not configured', async () => {
    const spy = jest.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ success: true, data: { nonce: 0 } }),
    });
    global.fetch = spy as any;
    const client = new ConsensusClient({
      apiUrl: 'http://stub',
      consensusRpcUrl: 'http://stub:26657',
    });
    await (client as any).getAccountNonce('did:willow:x');
    expect(lastHeaders(spy)['X-API-Key']).toBeUndefined();
  });

  it('sends X-API-Key on /account/<did>/nonce when configured', async () => {
    const spy = jest.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ success: true, data: { nonce: 5 } }),
    });
    global.fetch = spy as any;
    const client = new ConsensusClient({
      apiUrl: 'http://stub',
      consensusRpcUrl: 'http://stub:26657',
      apiKey: 'wk_test_abc',
    });
    await (client as any).getAccountNonce('did:willow:x');
    expect(lastHeaders(spy)['X-API-Key']).toBe('wk_test_abc');
  });

  it('sends X-API-Key on POST /tx/submit when configured', async () => {
    const spy = jest.fn().mockResolvedValue({
      ok: true, status: 200,
      json: async () => ({ success: true, data: { tx_hash: 'ABC', code: 0, log: 'ok' } }),
    });
    global.fetch = spy as any;
    const client = new ConsensusClient({
      apiUrl: 'http://stub',
      consensusRpcUrl: 'http://stub:26657',
      apiKey: 'wk_test_abc',
    });
    await (client as any).broadcastTransaction({ Test: {} });
    expect(spy.mock.calls.at(-1)?.[0]).toBe('http://stub/tx/submit');
    expect(lastHeaders(spy)['X-API-Key']).toBe('wk_test_abc');
  });

  it('sends X-API-Key on CometBFT JSON-RPC rpcRequest when configured', async () => {
    const spy = jest.fn().mockResolvedValue({
      ok: true, status: 200, json: async () => ({ result: { x: 1 } }),
    });
    global.fetch = spy as any;
    const client = new ConsensusClient({
      apiUrl: 'http://stub',
      consensusRpcUrl: 'http://stub:26657',
      apiKey: 'wk_test_abc',
    });
    await (client as any).rpcRequest('status', {});
    expect(spy.mock.calls.at(-1)?.[0]).toBe('http://stub:26657');
    expect(lastHeaders(spy)['X-API-Key']).toBe('wk_test_abc');
  });
});
