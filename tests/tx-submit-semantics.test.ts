/**
 * Semantics of submitTxToApi and how the three callers react.
 *
 * The contract: a transport/HTTP-level failure (non-2xx, or an unparseable
 * body — e.g. an HTML 502/504 from a proxy) THROWS TxTransportError so the
 * consensus retry loop retries it and direct callers surface an error; a
 * chain-level rejection (well-formed JSON envelope reporting failure, or a
 * CheckTx code !== 0) returns BroadcastResult{ success: false } with no retry,
 * since it is deterministic.
 */

import { submitTxToApi, TxTransportError } from '../src/internal/tx';
import { ConsensusClient } from '../src/consensus/client';
import { ConsensusError } from '../src/consensus/types';

const API_URL = 'http://api.test';

function response(opts: {
  ok: boolean;
  status: number;
  body?: unknown;
  text?: string;
}): Response {
  const text = opts.text ?? (opts.body === undefined ? '' : JSON.stringify(opts.body));
  return {
    ok: opts.ok,
    status: opts.status,
    text: async () => text,
  } as unknown as Response;
}

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

beforeEach(() => jest.clearAllMocks());

describe('submitTxToApi — transport vs chain-level failures', () => {
  it('returns success on an accepted tx (code 0)', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: true, status: 200, body: { success: true, data: { tx_hash: 'AB', code: 0, log: 'ok' } } }),
    );
    const result = await submitTxToApi(API_URL, { Test: {} });
    expect(result.success).toBe(true);
    expect(result.txHash).toBe('AB');
  });

  it('returns success:false (no throw) on a chain-level rejection (code !== 0)', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: true, status: 200, body: { success: true, data: { tx_hash: 'AB', code: 5, log: 'bad nonce' } } }),
    );
    const result = await submitTxToApi(API_URL, { Test: {} });
    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(5);
    expect(result.rawLog).toBe('bad nonce');
  });

  it('returns success:false on a well-formed failure envelope (success:false)', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: true, status: 200, body: { success: false, error: 'rejected by mempool' } }),
    );
    const result = await submitTxToApi(API_URL, { Test: {} });
    expect(result.success).toBe(false);
    expect(result.errorMessage).toMatch(/rejected by mempool/);
  });

  it('THROWS TxTransportError on a non-2xx (proxy/5xx) so the caller can retry', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: false, status: 503, body: { error: 'upstream down' } }),
    );
    const err = await submitTxToApi(API_URL, { Test: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(TxTransportError);
    expect(err.message).toMatch(/HTTP 503/);
    expect(err.message).toMatch(/upstream down/);
  });

  it('THROWS TxTransportError on a non-JSON body (HTML 502/504 gateway page)', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: false, status: 502, text: '<html>502 Bad Gateway</html>' }),
    );
    const err = await submitTxToApi(API_URL, { Test: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(TxTransportError);
    expect(err.message).toMatch(/non-JSON response body/);
  });

  it('THROWS TxTransportError on an unparseable 2xx body', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: true, status: 200, text: 'not json' }),
    );
    const err = await submitTxToApi(API_URL, { Test: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(TxTransportError);
  });
});

describe('ConsensusClient.broadcastTransaction — retry policy', () => {
  function makeClient() {
    return new ConsensusClient({
      apiUrl: API_URL,
      consensusRpcUrl: 'http://rpc.test',
      maxRetries: 2,
      requestTimeoutSecs: 1,
    });
  }

  it('retries transport failures and succeeds when a later attempt returns JSON', async () => {
    mockFetch
      .mockResolvedValueOnce(response({ ok: false, status: 502, text: '<html>bad gateway</html>' }))
      .mockResolvedValueOnce(
        response({ ok: true, status: 200, body: { success: true, data: { tx_hash: 'OK', code: 0, log: 'ok' } } }),
      );

    const result = await (makeClient() as any).broadcastTransaction({ Test: {} });
    expect(result.success).toBe(true);
    expect(result.txHash).toBe('OK');
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it('raises ConsensusError after exhausting retries on persistent transport failures', async () => {
    mockFetch.mockResolvedValue(response({ ok: false, status: 504, text: 'gateway timeout' }));

    const err = await (makeClient() as any).broadcastTransaction({ Test: {} }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsensusError);
    expect(err.code).toBe('TX_SUBMIT_FAILED');
    // maxRetries=2 -> 3 attempts total.
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it('does NOT retry a chain-level rejection (deterministic): one attempt, success:false', async () => {
    mockFetch.mockResolvedValue(
      response({ ok: true, status: 200, body: { success: true, data: { tx_hash: 'AB', code: 7, log: 'insufficient balance' } } }),
    );

    const result = await (makeClient() as any).broadcastTransaction({ Test: {} });
    expect(result.success).toBe(false);
    expect(result.errorCode).toBe(7);
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });
});
