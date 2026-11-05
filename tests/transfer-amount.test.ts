/**
 * A Transfer's amount is a u128 on the chain: the SDK sends and signs it as
 * its exact decimal digits. A JS number writes 10^21 as `1e+21`, which the
 * chain's u128 decoder refuses, and can't carry an amount above 2^53 exactly.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { verifyEd25519 } from '../src/auth';
import { ConsensusClient } from '../src/consensus/client';
import { NonceAllocator } from '../src/consensus/nonces';
import { createSignMessage, createTransactionWrapper, TransferTx } from '../src/consensus/types';
import { toJson } from '../src/internal/json';

const FROM = 'did:willow:alice';
const TO = 'did:willow:bob';
const SEED = '03'.repeat(32);
const SIGNER = { privateKey: SEED, publicKeyId: `${FROM}#key-1` };
const PUBLIC_KEY = bytesToHex(ed25519.getPublicKey(hexToBytes(SEED)));

/** 1000 WILL in wei, 10^21. */
const THOUSAND_WILL = '1000000000000000000000';
/** 2^64 + 1. */
const PAST_U64 = '18446744073709551617';

function json(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) } as unknown as Response;
}

/** The API at nonce base 4: every submission is accepted. Returns the bodies sent. */
function stubChain(): string[] {
  const sent: string[] = [];
  global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/nonce')) return json({ success: true, data: { nonce: 4 } });
    if (url.endsWith('/tx/submit')) {
      sent.push(init!.body as string);
      return json({ success: true, data: { tx_hash: 'AB12', code: 0, log: '' } });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
  return sent;
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

const client = () => new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator(), maxRetries: 0 });

/** The message the node rebuilds for a Transfer body (its amount read as digits). */
function nodeMessage(body: string): string {
  const amount = /"amount":([0-9]+),/.exec(body)![1];
  const tx = JSON.parse(body).Transfer;
  return `Transfer\nFrom: ${tx.from_did}\nTo: ${tx.to_did}\nAmount: ${amount}\nMemo: ${tx.memo}\nNonce: ${tx.nonce}`;
}

describe('a Transfer amount is sent and signed as its exact digits', () => {
  it('1000 WILL (10^21 wei), as a bigint or a decimal string', async () => {
    const sent = stubChain();
    const c = client();
    await c.transfer(FROM, TO, 10n ** 21n, SIGNER, 'rent');
    await c.transfer(FROM, TO, THOUSAND_WILL, SIGNER, 'rent');
    expect(sent).toHaveLength(2);
    for (const body of sent) {
      // A JSON number of the digits, which the chain's `u128_flexible` reads exactly.
      expect(body).toContain(`"amount":${THOUSAND_WILL},`);
      expect(nodeMessage(body)).toContain(`\nAmount: ${THOUSAND_WILL}\n`);
      const signature = bytesToHex(Uint8Array.from(JSON.parse(body).Transfer.signature));
      expect(verifyEd25519(nodeMessage(body), signature, PUBLIC_KEY)).toBe(true);
    }
  });

  it('2^64 + 1 wei', async () => {
    const sent = stubChain();
    await client().transfer(FROM, TO, 2n ** 64n + 1n, SIGNER);
    expect(sent[0]).toContain(`"amount":${PAST_U64},`);
    const signature = bytesToHex(Uint8Array.from(JSON.parse(sent[0]).Transfer.signature));
    expect(nodeMessage(sent[0])).toBe(`Transfer\nFrom: ${FROM}\nTo: ${TO}\nAmount: ${PAST_U64}\nMemo: \nNonce: 5`);
    expect(verifyEd25519(nodeMessage(sent[0]), signature, PUBLIC_KEY)).toBe(true);
  });

  it('the message and the body agree for every form of the amount', () => {
    for (const [amount, digits] of [
      [10n ** 21n, THOUSAND_WILL],
      [THOUSAND_WILL, THOUSAND_WILL],
      [2n ** 64n + 1n, PAST_U64],
      [PAST_U64, PAST_U64],
      [(1n << 128n) - 1n, ((1n << 128n) - 1n).toString()],
      [1000, '1000'],
      ['0042', '42'],
    ] as Array<[TransferTx['amount'], string]>) {
      const tx: TransferTx = { fromDid: FROM, toDid: TO, amount, nonce: 3 };
      expect(createSignMessage('Transfer', tx)).toBe(
        `Transfer\nFrom: ${FROM}\nTo: ${TO}\nAmount: ${digits}\nMemo: \nNonce: 3`,
      );
      expect(toJson(createTransactionWrapper('Transfer', tx))).toContain(`"amount":${digits},`);
    }
  });

  it('an amount that is not a u128 is refused before a nonce is taken', async () => {
    const sent = stubChain();
    const c = client();
    const notU128 = [1e21, 2 ** 53 + 2, -1, 1.5, NaN, '1e21', '-1', '0x10', ' 1', (1n << 128n).toString(), 1n << 128n, -1n];
    for (const amount of notU128) {
      await expect(c.transfer(FROM, TO, amount as TransferTx['amount'], SIGNER)).rejects.toMatchObject({
        code: 'INVALID_SIGNED_FIELD',
      });
    }
    expect(global.fetch).not.toHaveBeenCalled();
    // No nonce was taken: the next transfer takes base + 1.
    await c.transfer(FROM, TO, 5, SIGNER);
    expect(JSON.parse(sent[0]).Transfer.nonce).toBe(5);
    expect(sent[0]).toContain('"amount":5,');
  });
});
