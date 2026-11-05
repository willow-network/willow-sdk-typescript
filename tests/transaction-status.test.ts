/**
 * A transaction's status, read from CometBFT. Its JSON-RPC `tx` method reads
 * the hash as the base64 of its bytes (as CometBFT's own clients send it), so
 * the hex hash the API returns from `/tx/submit` matches no transaction there.
 */
import { ConsensusClient } from '../src/consensus/client';
import { TransactionStatus } from '../src/consensus/types';

/** A transaction hash as the API returns it: uppercase hex. */
const HASH = 'D8F1EC6479D48635B8A9A027D87DD08E33247ACE581C6358B1651C88A9324420';
const HASH_BASE64 = Buffer.from(HASH, 'hex').toString('base64');

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

/**
 * CometBFT's RPC holding the transaction `HASH`, its result `code`: `tx`
 * finds it only by the base64 of its hash. Returns the requests sent.
 */
function cometbft(code: number): unknown[] {
  const requests: unknown[] = [];
  global.fetch = jest.fn(async (_url: string, init?: RequestInit) => {
    const request = JSON.parse(init!.body as string);
    requests.push(request);
    const body =
      request.params.hash === HASH_BASE64
        ? { jsonrpc: '2.0', id: 1, result: { hash: HASH, height: '12', index: 0, tx_result: { code, log: '' } } }
        : { jsonrpc: '2.0', id: 1, error: { code: -32603, message: 'Internal error', data: 'tx not found' } };
    return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
  }) as unknown as typeof fetch;
  return requests;
}

const client = () =>
  new ConsensusClient({ consensusRpcUrl: 'http://rpc.test', apiUrl: 'http://api.test', maxRetries: 0 });

describe('a transaction is looked up by the base64 of its hash', () => {
  it('getTransactionStatus sends the hash as base64', async () => {
    const requests = cometbft(0);
    await expect(client().getTransactionStatus(HASH)).resolves.toBe(TransactionStatus.SUCCESS);
    expect(requests).toEqual([{ jsonrpc: '2.0', id: 1, method: 'tx', params: { hash: HASH_BASE64, prove: false } }]);
    // Lowercase, and with a 0x prefix, it names the same transaction.
    await expect(client().getTransactionStatus(HASH.toLowerCase())).resolves.toBe(TransactionStatus.SUCCESS);
    await expect(client().getTransactionStatus(`0x${HASH}`)).resolves.toBe(TransactionStatus.SUCCESS);
  });

  it('waitForTransaction resolves SUCCESS, or FAILED for a transaction refused in its block', async () => {
    cometbft(0);
    await expect(client().waitForTransaction(HASH, 2, 0.01)).resolves.toBe(TransactionStatus.SUCCESS);
    cometbft(7);
    await expect(client().waitForTransaction(HASH, 2, 0.01)).resolves.toBe(TransactionStatus.FAILED);
  });

  it('a hash that is not 32 bytes of hex is refused before anything is sent', async () => {
    const requests = cometbft(0);
    for (const hash of ['', 'AB', 'ZZ'.repeat(32), `${HASH}00`, HASH_BASE64]) {
      await expect(client().getTransactionStatus(hash)).rejects.toMatchObject({ code: 'INVALID_TX_HASH' });
    }
    expect(requests).toHaveLength(0);
  });
});
