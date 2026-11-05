/**
 * Choosing nonces in a client: every write path that picks a nonce takes the
 * lowest one in `base + 1 … base + 24` that isn't used, seen to land, or handed
 * out within the last 120 s, so writes in flight together get distinct ones.
 */
import {
  NonceAllocator,
  NONCE_WINDOW,
  NONCE_HOLD_MS,
  parseAccountNonceState,
  refusalKeepsNonce,
} from '../src/consensus/nonces';
import { ConsensusClient } from '../src/consensus/client';
import { WillowClient } from '../src/client';
import { WillowAuth } from '../src/auth';
import { PrivacyOperations, EncryptedKeyGrant } from '../src/privacy';
import { WillowError } from '../src/types';
import { createDidFromPublicKey } from '../src/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const DID = 'did:willow:writer';
const SEED = '03'.repeat(32);
const SIGNER = { privateKey: SEED, publicKeyId: `${DID}#key-1` };

const chain = (base: number, used = 0) => ({ base, used });

/** A clock tests move by hand. */
function fakeClock(start = 1_000_000) {
  const clock = { t: start, now: () => clock.t };
  return clock;
}

function json(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

/** An ABCI answer for `/store/account_nonce_state`: base (BE u64), then the 3-byte bitmap. */
function nonceState(base: number, used = 0) {
  const bytes = new Uint8Array(11);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(base));
  bytes[8] = used & 0xff;
  bytes[9] = (used >> 8) & 0xff;
  bytes[10] = (used >> 16) & 0xff;
  return json({ result: { response: { code: 0, value: Buffer.from(bytes).toString('base64') } } });
}

/**
 * A chain behind fetch: the RPC answers the nonce state, the API the base,
 * and /tx/submit answers with `checkTx(nonce)` (a log, or '' to accept).
 */
function stubChain(opts: { base: number; used?: number; checkTx?: (nonce: number) => string }) {
  const sent: number[] = [];
  global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
    if (url === 'http://rpc.test') return nonceState(opts.base, opts.used ?? 0);
    if (url.includes('/nonce')) return json({ success: true, data: { nonce: opts.base } });
    if (url.endsWith('/tx/submit')) {
      const body = JSON.parse(init!.body as string);
      const tx = Object.values(body)[0] as { nonce: number };
      sent.push(tx.nonce);
      const log = opts.checkTx?.(tx.nonce) ?? '';
      return json({ success: true, data: { tx_hash: `T${tx.nonce}`, code: log ? 1 : 0, log } });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
  return sent;
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

describe('NonceAllocator', () => {
  it('hands out distinct nonces to writes in flight, lowest first', () => {
    const a = new NonceAllocator();
    expect([1, 2, 3].map(() => a.take(DID, chain(2_092)))).toEqual([2_093, 2_094, 2_095]);
  });

  it('skips nonces the chain reports used and drops the ones seen to land', () => {
    const a = new NonceAllocator();
    // base + 1 and base + 3 used.
    expect(a.take(DID, chain(10, 0b101))).toBe(12);
    expect(a.take(DID, chain(10, 0b101))).toBe(14);
    // 12 landed and the base moved past it; 14 is still in flight.
    expect(a.take(DID, chain(13))).toBe(15);
    expect(a.take(DID, chain(13))).toBe(16);
  });

  it('keeps the nonces it has seen land: an older answer hands out none of them', () => {
    const a = new NonceAllocator();
    expect(a.take(DID, chain(5))).toBe(6);
    expect(a.take(DID, chain(6, 0b10))).toBe(7); // 6 and 8 landed
    expect(a.take(DID, chain(5))).toBe(9); // a slower answer from before both
  });

  it('gives a refused nonce back, unless the refusal says it is taken', () => {
    const a = new NonceAllocator();
    expect(a.take(DID, chain(5))).toBe(6);
    expect(a.take(DID, chain(5))).toBe(7);
    a.settle(DID, 6, { success: false, rawLog: 'Signature mismatch' });
    expect(a.take(DID, chain(5))).toBe(6);

    for (const log of [
      'Nonce 6 of did:willow:writer is held by a pending transaction; sign this one with another nonce',
      'Invalid nonce: 6 already used (replay)',
      'Invalid nonce: 6 <= base nonce 9',
      'Subgrove not found (nonce 6 spent)',
    ]) {
      expect(refusalKeepsNonce(log)).toBe(true);
      const b = new NonceAllocator();
      expect(b.take(DID, chain(5))).toBe(6);
      b.settle(DID, 6, { success: false, rawLog: log });
      expect(b.take(DID, chain(5))).toBe(7);
    }
    expect(refusalKeepsNonce('Invalid nonce: 40 is too far ahead (base=5, max=29)')).toBe(false);
  });

  it('never takes a nonce above base + 24: a full window is an error', () => {
    const a = new NonceAllocator();
    for (let n = 1; n <= NONCE_WINDOW; n++) expect(a.take(DID, chain(0))).toBe(n);
    expect(() => a.take(DID, chain(0))).toThrow(/Nonce window full/);
    try {
      a.take(DID, chain(0));
    } catch (e) {
      expect((e as WillowError).code).toBe('NONCE_WINDOW_FULL');
    }
    // Used nonces count against the window too.
    const b = new NonceAllocator();
    expect(() => b.take(DID, chain(0, 0xffffff))).toThrow(/Nonce window full/);
    // Once the base moves, the window opens again.
    expect(a.take(DID, chain(1))).toBe(25);
  });

  it('frees a nonce handed out 120 s ago that has not landed', () => {
    const clock = fakeClock();
    const a = new NonceAllocator({ now: clock.now });
    expect(a.take(DID, chain(5))).toBe(6);
    clock.t += NONCE_HOLD_MS - 1;
    expect(a.take(DID, chain(5))).toBe(7);
    clock.t += 1; // 6 was handed out 120 s ago; 7 just under
    expect(a.take(DID, chain(5))).toBe(6);
    expect(a.take(DID, chain(5))).toBe(8);
  });

  it('runs an accepted write’s hold from its acceptance', () => {
    const clock = fakeClock();
    const a = new NonceAllocator({ now: clock.now });
    expect(a.take(DID, chain(5))).toBe(6);
    clock.t += NONCE_HOLD_MS / 2;
    a.settle(DID, 6, { success: true, txHash: 'AB' });
    clock.t += NONCE_HOLD_MS / 2;
    expect(a.take(DID, chain(5))).toBe(7);
  });

  it('keeps accounts apart, and one allocator per API URL in the process', () => {
    const a = new NonceAllocator();
    expect(a.take('did:willow:a', chain(5))).toBe(6);
    expect(a.take('did:willow:b', chain(5))).toBe(6);
    expect(NonceAllocator.shared('http://x.test/')).toBe(NonceAllocator.shared('http://x.test'));
    expect(NonceAllocator.shared('http://x.test')).not.toBe(NonceAllocator.shared('http://y.test'));
  });

  it('reads the chain’s nonce state', () => {
    expect(parseAccountNonceState(new Uint8Array())).toEqual(chain(0));
    const eleven = new Uint8Array([0, 0, 0, 0, 0, 0, 0x08, 0x2c, 0b101, 0, 0b1000_0000]);
    expect(parseAccountNonceState(eleven)).toEqual(chain(2_092, 0b101 | (1 << 23)));
    expect(parseAccountNonceState(eleven.slice(0, 8))).toEqual(chain(2_092));
    expect(() => parseAccountNonceState(new Uint8Array([1, 2, 3]))).toThrow();
    expect(() => parseAccountNonceState(new Uint8Array(8).fill(0xff))).toThrow();
  });
});

describe('ConsensusClient picks nonces with the allocator', () => {
  function client(nonceAllocator = new NonceAllocator(), maxRetries = 3) {
    return new ConsensusClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator,
      maxRetries,
      retryDelaySecs: 0,
    });
  }

  it('concurrent writes get distinct nonces, skipping the ones the chain reports used', async () => {
    const sent = stubChain({ base: 40, used: 0b10 }); // 42 used
    const c = client();
    const results = await Promise.all(
      [0, 1, 2, 3].map((i) => c.storeData('sg-1', `k${i}`, { i }, DID, SIGNER)),
    );
    expect(results.every((r) => r.success)).toBe(true);
    expect([...sent].sort((x, y) => x - y)).toEqual([41, 43, 44, 45]);
  });

  it('reads the base from the API without an RPC URL', async () => {
    const sent = stubChain({ base: 7 });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    await c.storeData('sg-1', 'a', {}, DID, SIGNER);
    await c.storeData('sg-1', 'b', {}, DID, SIGNER);
    expect(sent).toEqual([8, 9]);
  });

  it('gives a nonce refused at CheckTx back, and holds one the refusal says is taken', async () => {
    let refuse = 'Signature mismatch';
    const sent = stubChain({ base: 9, checkTx: (n) => (n === 10 ? refuse : '') });
    const c = client();
    expect((await c.storeData('sg-1', 'a', {}, DID, SIGNER)).success).toBe(false);
    expect((await c.storeData('sg-1', 'a', {}, DID, SIGNER)).success).toBe(false);
    refuse = 'Nonce 10 of did:willow:writer is held by a pending transaction; sign this one with another nonce';
    expect((await c.storeData('sg-1', 'a', {}, DID, SIGNER)).success).toBe(false);
    expect((await c.storeData('sg-1', 'a', {}, DID, SIGNER)).success).toBe(true);
    expect(sent).toEqual([10, 10, 10, 11]);
  });

  it('gives back the nonce of a write refused before it is sent', async () => {
    const sent = stubChain({ base: 3 });
    const c = client();
    await expect(c.storeData('sg-1', 'bad\nkey', {}, DID, SIGNER)).rejects.toThrow();
    await c.storeData('sg-1', 'good', {}, DID, SIGNER);
    expect(sent).toEqual([4]);
  });

  it('keeps the nonce of a write whose submission failed in transport, until its hold runs out', async () => {
    const clock = fakeClock();
    const sent: number[] = [];
    let down = true;
    global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
      if (url === 'http://rpc.test') return nonceState(3);
      const tx = Object.values(JSON.parse(init!.body as string))[0] as { nonce: number };
      sent.push(tx.nonce);
      if (down) return { ok: false, status: 504, text: async () => '<html>timeout</html>' } as Response;
      return json({ success: true, data: { tx_hash: 'AB', code: 0, log: '' } });
    }) as unknown as typeof fetch;
    const c = client(new NonceAllocator({ now: clock.now }), 1);
    await expect(c.storeData('sg-1', 'a', {}, DID, SIGNER)).rejects.toThrow(/TX_SUBMIT_FAILED|failed after/);
    down = false;
    await c.storeData('sg-1', 'b', {}, DID, SIGNER);
    clock.t += NONCE_HOLD_MS;
    await c.storeData('sg-1', 'c', {}, DID, SIGNER);
    // The failed write was sent twice under 4 (its retry kept its nonce); 5
    // went next; 4 was free again 120 s later.
    expect(sent).toEqual([4, 4, 5, 4]);
  });

  it('refuses a write when every nonce in the window is in flight', async () => {
    stubChain({ base: 0 });
    const c = client();
    for (let i = 0; i < NONCE_WINDOW; i++) await c.storeData('sg-1', `k${i}`, {}, DID, SIGNER);
    await expect(c.storeData('sg-1', 'one-more', {}, DID, SIGNER)).rejects.toMatchObject({
      code: 'NONCE_WINDOW_FULL',
    });
  });

  it('holds nonce 1 for a DID whose registration is pending', async () => {
    const doc = createDidFromPublicKey(bytesToHex(ed25519.getPublicKey(hexToBytes(SEED))));
    const sent = stubChain({ base: 0 });
    const c = client();
    await c.registerDid(doc, { ...SIGNER, publicKeyId: doc.publicKeys[0].id });
    await c.storeData('sg-1', 'a', {}, doc.id, SIGNER);
    expect(sent).toEqual([1, 2]);
  });

  it('is shared by a WillowClient’s writes and its data module', async () => {
    const sent = stubChain({ base: 0 });
    const willow = new WillowClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator: new NonceAllocator(),
    });
    willow.auth.setIdentity(DID, SEED, `${DID}#key-1`, 'Ed25519');
    const schema = { version: 1, fields: {}, indexes: [], required_fields: [] };
    await Promise.all([
      willow.store('sg-1', 'a', { a: 1 }),
      willow.data.registerSubgrove({
        dataset_id: 'sg-2',
        name: 'n',
        schema,
        owner_did: DID,
        writers: [],
        readers: [],
      }),
    ]);
    expect([...sent].sort()).toEqual([1, 2]);
  });
});

describe('PrivacyOperations picks nonces with the allocator', () => {
  const grant: EncryptedKeyGrant = {
    grantee_did: 'did:willow:reader',
    key_epoch: 1,
    grantee_public_key_id: 'did:willow:reader#key-1',
    ephemeral_public_key: [1, 2, 3],
    encrypted_key: [4, 5, 6],
    granted_by: DID,
    granted_at: 1,
  };

  function privacy(allocator: NonceAllocator) {
    const auth = new WillowAuth('http://api.test');
    auth.setIdentity(DID, SEED, `${DID}#key-1`, 'Ed25519');
    return new PrivacyOperations('http://api.test', auth, SEED, `${DID}#key-1`, undefined, allocator);
  }

  it('gives concurrent grants distinct nonces, and a refused one back', async () => {
    const sent = stubChain({ base: 20, checkTx: (n) => (n === 21 && sent.length === 1 ? 'Grantee not found' : '') });
    const p = privacy(new NonceAllocator());
    await expect(p.grantSubgroveKey('sg-1', grant)).rejects.toThrow(/Grantee not found/);
    await Promise.all([p.grantSubgroveKey('sg-1', grant), p.grantSubgroveKey('sg-1', grant)]);
    expect(sent[0]).toBe(21);
    expect(sent.slice(1).sort()).toEqual([21, 22]);
  });

  it('shares an allocator with a ConsensusClient for the same API URL', async () => {
    const sent = stubChain({ base: 0 });
    const shared = new NonceAllocator();
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: shared });
    await c.storeData('sg-1', 'a', {}, DID, SIGNER);
    await privacy(shared).grantSubgroveKey('sg-1', grant);
    expect(sent).toEqual([1, 2]);
  });
});
