/**
 * Semantics of submitTxToApi and how the three callers react.
 *
 * The contract: a transport/HTTP-level failure (a non-2xx other than a 4xx,
 * or an unparseable body — e.g. an HTML 502/504 from a proxy) THROWS
 * TxTransportError so the consensus retry loop retries it and direct callers
 * surface an error; a chain-level rejection (well-formed JSON envelope
 * reporting failure, or a CheckTx code !== 0), and a 4xx (the API refused the
 * request before CheckTx), return BroadcastResult{ success: false } with no
 * retry, since they are deterministic.
 */

import { submitTxToApi, TxTransportError } from '../src/internal/tx';
import { ConsensusClient } from '../src/consensus/client';
import { NonceAllocator } from '../src/consensus/nonces';
import { ConsensusError, TransactionSubmitError } from '../src/consensus/types';
import { WillowClient } from '../src/client';

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

describe('a 4xx from /tx/submit is a refusal: the request never reached CheckTx', () => {
  const DID = 'did:willow:writer';
  const SEED = '03'.repeat(32);
  const SIGNER = { privateKey: SEED, publicKeyId: `${DID}#key-1` };
  /** A body the API's JSON reader refuses: a 422 with a text body, as axum answers. */
  const unreadable = () =>
    response({
      ok: false,
      status: 422,
      text: 'Failed to deserialize the JSON body into the target type: StoreData: missing field `nonce`',
    });
  const accepted = () =>
    response({ ok: true, status: 200, body: { success: true, data: { tx_hash: 'AB12', code: 0, log: '' } } });
  const nonceOf = (body: string) => (Object.values(JSON.parse(body))[0] as { nonce: number }).nonce;

  /** The API at nonce base 4; `/tx/submit` answers `answer()`. Returns the bodies posted. */
  function stubChain(answer: () => Response): string[] {
    const sent: string[] = [];
    mockFetch.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url.includes('/nonce')) {
        const body = { success: true, data: { nonce: 4 } };
        return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
      }
      sent.push(init!.body as string);
      return answer();
    });
    return sent;
  }

  afterEach(() => mockFetch.mockReset());

  it('submitTxToApi returns it as success:false, without throwing', async () => {
    mockFetch.mockResolvedValueOnce(unreadable());
    const result = await submitTxToApi(API_URL, { Test: {} });
    expect(result).toMatchObject({ success: false, errorMessage: expect.stringMatching(/^HTTP 422: Failed to deserialize/) });
    expect(result.pending).toBeUndefined();
    const others: Array<[number, unknown]> = [
      [400, { success: false, error: 'Failed to bincode-serialize transaction: sequence too long' }],
      [401, undefined],
      [413, undefined],
      [429, undefined],
    ];
    for (const [status, body] of others) {
      mockFetch.mockResolvedValueOnce(response({ ok: false, status, body }));
      await expect(submitTxToApi(API_URL, { Test: {} })).resolves.toMatchObject({
        success: false,
        errorMessage: expect.stringMatching(new RegExp(`^HTTP ${status}`)),
      });
    }
  });

  it('one that says the transaction is already in the cache stays pending', async () => {
    mockFetch.mockResolvedValueOnce(
      response({ ok: false, status: 400, body: { success: false, error: 'Internal error tx already exists in cache' } }),
    );
    await expect(submitTxToApi(API_URL, { Test: {} })).resolves.toMatchObject({ success: false, pending: true });
  });

  it('ConsensusClient posts it once and gives its nonce back', async () => {
    let answer = unreadable;
    const sent = stubChain(() => answer());
    const c = new ConsensusClient({ apiUrl: API_URL, nonceAllocator: new NonceAllocator() });
    const result = await c.storeData('sg', 'k', { a: 1 }, DID, SIGNER);
    expect(result).toMatchObject({
      success: false,
      errorMessage: expect.stringMatching(/^HTTP 422/),
      submission: { did: DID, nonce: 5 },
    });
    expect(result.pending).toBeUndefined();
    expect(sent).toHaveLength(1);
    // Its nonce is free again: the next write takes it.
    answer = accepted;
    await expect(c.storeData('sg', 'k', { a: 1 }, DID, SIGNER)).resolves.toMatchObject({ success: true });
    expect(sent.map(nonceOf)).toEqual([5, 5]);
  });

  it("WillowClient's writes throw it as a refusal, a TransactionSubmitError carrying the result", async () => {
    const sent = stubChain(unreadable);
    const client = new WillowClient({ apiUrl: API_URL, nonceAllocator: new NonceAllocator() });
    client.auth.setIdentity(DID, SEED, `${DID}#key-1`, 'Ed25519');
    const err = await client.store('sg', 'k', { a: 1 }).catch((e) => e);
    expect(err).toBeInstanceOf(TransactionSubmitError);
    expect(err).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, nonce: 5, result: { success: false } });
    expect(err.message).toMatch(/^store failed: HTTP 422/);
    expect(sent).toHaveLength(1);
  });
});
