/**
 * A write keeps its nonce while it is in flight, and one that did not go
 * through can be retried under the same nonce: the nonce state merge keeps
 * used bits when the base advances, file writes take and settle their nonces
 * like every other write, each send attempt renews the hold, and a failed
 * submission carries its DID, nonce, and signed body to post again.
 */
import { NonceAllocator } from '../src/consensus/nonces';
import { ConsensusClient } from '../src/consensus/client';
import { TransactionSubmitError, createSignMessage } from '../src/consensus/types';
import { WillowClient } from '../src/client';
import { FileOperations } from '../src/files';
import { WillowAuth } from '../src/auth';
import { PrivacyOperations, EncryptedKeyGrant } from '../src/privacy';
import { toJson } from '../src/internal/json';
import { createDidFromPublicKey } from '../src/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const DID = 'did:willow:writer';
const SEED = '03'.repeat(32);
const KEY_ID = `${DID}#key-1`;
const SIGNER = { privateKey: SEED, publicKeyId: KEY_ID };

function json(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

const accepted = (hash = 'AB12') => json({ success: true, data: { tx_hash: hash, code: 0, log: '' } });
const refused = (log: string) => json({ success: true, data: { tx_hash: 'AB12', code: 1, log } });
const inCache = () =>
  json({ success: false, error: 'CometBFT RPC error -32603: Internal error tx already exists in cache' }, 502);

/** The nonce a sent body carries. */
const nonceOf = (body: string) => (Object.values(JSON.parse(body))[0] as { nonce: number }).nonce;

/**
 * A chain behind fetch: the API answers the base, and /tx/submit answers with
 * `submit(body, attempt)`.
 */
function stubChain(base: number, submit: (body: string, attempt: number) => Response | Promise<Response>) {
  const sent: string[] = [];
  global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/nonce')) return json({ success: true, data: { nonce: base } });
    if (url.endsWith('/tx/submit')) {
      const body = init!.body as string;
      sent.push(body);
      return submit(body, sent.length);
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as unknown as typeof fetch;
  return sent;
}

const realFetch = global.fetch;
afterEach(() => {
  global.fetch = realFetch;
});

describe('nonce state merge', () => {
  it('a base-only read that advances the base keeps the used bits seen above it', () => {
    const a = new NonceAllocator();
    // An RPC read: base 5, nonce 7 used.
    expect(a.take(DID, { base: 5, used: 0b10 })).toBe(6);
    // 6 lands; an API read reports base 6 and no bitmap. 7 is still used.
    expect(a.take(DID, { base: 6, used: 0 })).toBe(8);
  });

  it("an older read's used bits above the newer base are kept", () => {
    const a = new NonceAllocator();
    expect(a.take(DID, { base: 6, used: 0 })).toBe(7);
    // An older read (base 5) marks nonce 10 used (bit 4).
    expect(a.take(DID, { base: 5, used: 1 << 4 })).toBe(8);
    expect(a.take(DID)).toBe(9);
    expect(a.take(DID)).toBe(11);
  });

  it('a base that advances past the window drops the old bits', () => {
    const a = new NonceAllocator();
    expect(a.take(DID, { base: 1, used: 0xffffff ^ 1 })).toBe(2);
    // 32 past: `>>> 32` would keep every bit; none of the old window remains.
    expect(a.take(DID, { base: 33, used: 0 })).toBe(34);
    expect(a.take(DID, { base: 25, used: 0 })).toBe(35);
  });
});

describe('file writes take and settle their nonces', () => {
  const SIGNING = { ownerDid: DID, privateKey: SEED, publicKeyId: KEY_ID, signFunction: () => 'ab'.repeat(64) };

  function consensus(allocator = new NonceAllocator()) {
    return new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: allocator, maxRetries: 0 });
  }

  it('takes the lowest free nonce when signing leaves it out', async () => {
    const sent = stubChain(4, () => accepted());
    const c = consensus();
    const files = new FileOperations('http://api.test', () => ({}), c);
    await files.delete('sg', 'f1', SIGNING);
    await files.delete('sg', 'f2', SIGNING);
    expect(sent.map(nonceOf)).toEqual([5, 6]);
    // The consensus client's next write takes the next free one.
    await c.storeData('sg', 'k', {}, DID, SIGNER);
    expect(sent.map(nonceOf)).toEqual([5, 6, 7]);
  });

  it('a refused manifest gives its nonce back and carries its submission', async () => {
    const sent = stubChain(4, (_, attempt) => (attempt === 1 ? refused('insufficient balance') : accepted()));
    const c = consensus();
    const files = new FileOperations('http://api.test', () => ({}), c);
    const err = await files
      .upload('sg', 'f1', 'a.txt', new TextEncoder().encode('hi'), 'http://node.test', SIGNING)
      .catch((e) => e);
    expect(err).toBeInstanceOf(TransactionSubmitError);
    expect(err).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, nonce: 5 });
    expect(err.result).toMatchObject({ success: false, rawLog: 'insufficient balance' });
    expect(toJson(err.transaction)).toBe(sent[0]);
    // Nonce 5 is free again.
    await c.storeData('sg', 'k', {}, DID, SIGNER);
    expect(nonceOf(sent[1])).toBe(5);
  });

  it('a refusal that says the nonce is taken keeps it', async () => {
    const sent = stubChain(4, (_, attempt) =>
      attempt === 1 ? refused('Nonce 5 of did:willow:writer is held by a pending transaction') : accepted(),
    );
    const c = consensus();
    const files = new FileOperations('http://api.test', () => ({}), c);
    await expect(files.delete('sg', 'f1', SIGNING)).rejects.toMatchObject({ nonce: 5 });
    await c.storeData('sg', 'k', {}, DID, SIGNER);
    expect(nonceOf(sent[1])).toBe(6);
  });

  it('a nonce the caller took with nextNonce is settled too', async () => {
    const sent = stubChain(4, (_, attempt) => (attempt === 1 ? refused('insufficient balance') : accepted()));
    const c = consensus();
    const files = new FileOperations('http://api.test', () => ({}), c);
    const nonce = await c.nextNonce(DID);
    await expect(files.delete('sg', 'f1', { ...SIGNING, nonce })).rejects.toMatchObject({ nonce: 5 });
    expect(await c.nextNonce(DID)).toBe(5);
    expect(sent).toHaveLength(1);
  });

  it('a unregistration takes the node DID’s nonce', async () => {
    const sent = stubChain(9, () => accepted());
    const files = new FileOperations('http://api.test', () => ({}), consensus());
    await files.unregisterStorageNode('did:willow:node', SIGNING);
    expect(JSON.parse(sent[0]).UnregisterStorageNode).toMatchObject({ node_did: 'did:willow:node', nonce: 10 });
  });

  it('without a nonce or a nonce source, refuses before sending anything', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const files = new FileOperations('http://api.test', () => ({}));
    await expect(files.delete('sg', 'f1', SIGNING)).rejects.toMatchObject({ code: 'NONCE_REQUIRED' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("refuses a field the chain refuses before taking a nonce", async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const files = new FileOperations('http://api.test', () => ({}), consensus());
    await expect(files.delete('sg', 'line\nbreak', SIGNING)).rejects.toMatchObject({
      code: 'LINE_BREAK_IN_SIGNED_FIELD',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("WillowClient.files shares the client's allocator", async () => {
    const sent = stubChain(4, () => accepted());
    const client = new WillowClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');
    await Promise.all([
      client.files.delete('sg', 'f1', SIGNING),
      client.consensus.storeData('sg', 'k', {}, DID, SIGNER),
    ]);
    expect(sent.map(nonceOf).sort()).toEqual([5, 6]);
  });
});

describe('a write in flight keeps its nonce', () => {
  it('each send attempt renews the hold', async () => {
    let t = 1_000_000;
    const allocator = new NonceAllocator({ now: () => t });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: allocator, maxRetries: 1 });
    let other: number | undefined;
    const sent = stubChain(4, async (_, attempt) => {
      if (attempt === 1) {
        // The first attempt times out just inside the 120 s hold.
        t += 119_000;
        throw new Error('timeout');
      }
      // The retry is still in flight 130 s after the nonce was taken: another
      // write must not take it.
      t += 11_000;
      other = allocator.take(DID, { base: 4, used: 0 });
      return accepted();
    });
    const result = await c.storeData('sg', 'k', {}, DID, SIGNER);
    expect(result.success).toBe(true);
    expect(sent.map(nonceOf)).toEqual([5, 5]);
    expect(other).toBe(6);
  });
});

describe('a failed submission carries what was sent, to post again', () => {
  it('TX_SUBMIT_FAILED carries the DID, nonce, and signed body, and keeps the nonce held', async () => {
    const sent = stubChain(4, () => {
      throw new Error('connection reset');
    });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator(), maxRetries: 1 });
    const err = await c.storeData('sg', 'k', { a: 1 }, DID, SIGNER).catch((e) => e);
    expect(err).toBeInstanceOf(TransactionSubmitError);
    expect(err).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, nonce: 5 });
    expect(sent).toEqual([toJson(err.transaction), toJson(err.transaction)]);
    // It may yet land, so the next write takes 6.
    expect(await c.nextNonce(DID)).toBe(6);
  });

  it('resubmit posts the same signed body; a repeat the mempool holds is pending, not accepted', async () => {
    let fail = true;
    const sent = stubChain(4, () => {
      if (fail) throw new Error('timeout');
      return inCache();
    });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator(), maxRetries: 0 });
    const err = await c.storeData('sg', 'k', { a: 1 }, DID, SIGNER).catch((e) => e);
    fail = false;
    const result = await c.resubmit(err);
    expect(result).toMatchObject({ success: false, pending: true });
    expect(result.errorMessage).toMatch(/unconfirmed/);
    expect(result.txHash).toBeUndefined();
    expect(sent).toHaveLength(2);
    expect(sent[1]).toBe(sent[0]);
    // Its outcome is unknown, so its nonce stays held.
    expect(await c.nextNonce(DID)).toBe(6);
  });

  it('isNonceUsed reads whether the chain has used a nonce', async () => {
    stubChain(4, () => accepted());
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    expect(await c.isNonceUsed(DID, 4)).toBe(true);
    expect(await c.isNonceUsed(DID, 5)).toBe(false);
  });

  it('resubmit settles the nonce with the answer', async () => {
    let fail = true;
    const sent = stubChain(4, () => {
      if (fail) throw new Error('timeout');
      return refused('Insufficient balance');
    });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator(), maxRetries: 0 });
    const err = await c.storeData('sg', 'k', {}, DID, SIGNER).catch((e) => e);
    fail = false;
    expect((await c.resubmit(err)).success).toBe(false);
    // Refused at CheckTx without spending: nonce 5 is free again.
    expect(await c.nextNonce(DID)).toBe(5);
    expect(sent).toHaveLength(2);
  });

  it("a write's own retry that meets the mempool's copy reports it pending and keeps the nonce", async () => {
    const sent = stubChain(4, (_, attempt) => {
      if (attempt === 1) throw new Error('timeout');
      return inCache();
    });
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator(), maxRetries: 1 });
    expect(await c.storeData('sg', 'k', {}, DID, SIGNER)).toMatchObject({ success: false, pending: true });
    expect(sent[1]).toBe(sent[0]);
    expect(await c.nextNonce(DID)).toBe(6);
  });

  it('BROADCAST_FAILED from PrivacyOperations carries its submission', async () => {
    const grant: EncryptedKeyGrant = {
      grantee_did: 'did:willow:reader',
      key_epoch: 1,
      grantee_public_key_id: 'did:willow:reader#key-1',
      ephemeral_public_key: [1, 2, 3],
      encrypted_key: [4, 5, 6],
      granted_by: DID,
      granted_at: 1_700_000_000,
    };
    const auth = new WillowAuth('http://api.test');
    auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');
    const allocator = new NonceAllocator();
    const privacy = new PrivacyOperations('http://api.test', auth, SEED, KEY_ID, undefined, allocator);

    let sent = stubChain(4, () => {
      throw new Error('connection refused');
    });
    let err = await privacy.grantSubgroveKey('private-1', grant).catch((e) => e);
    expect(err).toBeInstanceOf(TransactionSubmitError);
    expect(err).toMatchObject({ code: 'BROADCAST_FAILED', did: DID, nonce: 5 });
    expect(toJson(err.transaction)).toBe(sent[0]);

    sent = stubChain(4, () => refused('not the subgrove owner'));
    err = await privacy.grantSubgroveKey('private-1', grant).catch((e) => e);
    expect(err).toMatchObject({ code: 'BROADCAST_FAILED', did: DID, nonce: 6 });
    expect(err.result).toMatchObject({ success: false, rawLog: 'not the subgrove owner' });

    // The consensus client of the same allocator posts it again.
    sent = stubChain(4, () => inCache());
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: allocator });
    expect(await c.resubmit(err)).toMatchObject({ success: false, pending: true });
    expect(sent[0]).toBe(toJson(err.transaction));

    // A grant whose answer is the mempool's copy is unconfirmed, not refused.
    sent = stubChain(4, () => inCache());
    err = await privacy.grantSubgroveKey('private-1', grant).catch((e) => e);
    expect(err).toMatchObject({ code: 'BROADCAST_FAILED', result: { pending: true } });
    expect(err.message).toMatch(/unconfirmed/);
  });
});

describe('a write that did not go through carries what was sent', () => {
  it("ConsensusClient's pending or refused result carries its submission", async () => {
    let sent = stubChain(4, () => inCache());
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    const pending = await c.storeData('sg', 'k', { a: 1 }, DID, SIGNER);
    expect(pending).toMatchObject({ success: false, pending: true, submission: { did: DID, nonce: 5 } });
    expect(toJson(pending.submission!.transaction)).toBe(sent[0]);

    // It can be posted again under its nonce.
    sent = stubChain(4, () => accepted());
    expect(await c.resubmit(pending.submission!)).toMatchObject({ success: true, txHash: 'AB12' });
    expect(sent[0]).toBe(toJson(pending.submission!.transaction));

    sent = stubChain(4, () => refused('Insufficient balance'));
    const refusal = await c.storeData('sg', 'k2', {}, DID, SIGNER);
    expect(refusal).toMatchObject({ success: false, submission: { did: DID } });
    expect(refusal.pending).toBeUndefined();

    stubChain(4, () => accepted());
    expect((await c.storeData('sg', 'k3', {}, DID, SIGNER)).submission).toBeUndefined();
  });

  it('a pending registerDid carries nonce 1', async () => {
    const doc = createDidFromPublicKey(bytesToHex(ed25519.getPublicKey(hexToBytes(SEED))), 'Ed25519');
    const sent = stubChain(0, () => inCache());
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    const result = await c.registerDid(doc, { privateKey: SEED, publicKeyId: `${doc.id}#key-1` });
    expect(result).toMatchObject({ pending: true, submission: { did: doc.id, nonce: 1 } });
    expect(toJson(result.submission!.transaction)).toBe(sent[0]);
  });

  it("WillowClient's and WillowData's writes throw it as a TransactionSubmitError", async () => {
    const sent = stubChain(4, () => inCache());
    const client = new WillowClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');

    const store = await client.store('sg', 'k', { a: 1 }).catch((e) => e);
    expect(store).toBeInstanceOf(TransactionSubmitError);
    expect(store).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, nonce: 5, result: { pending: true } });
    expect(store.message).toMatch(/^store failed: unconfirmed/);
    expect(toJson(store.transaction)).toBe(sent[0]);

    const request = {
      dataset_id: 'sg-1',
      name: 'sg-1',
      schema: { version: 1, fields: {} },
      owner_did: DID,
      writers: [],
      readers: [],
    };
    for (const register of [() => client.registerSubgrove(request), () => client.data.registerSubgrove(request)]) {
      const err = await register().catch((e) => e);
      expect(err).toBeInstanceOf(TransactionSubmitError);
      expect(err).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, result: { pending: true } });
      expect(err.message).toMatch(/^registerSubgrove failed/);
      expect(sent).toContain(toJson(err.transaction));
    }

    // A refusal carries it too, with the chain's answer.
    stubChain(4, () => refused('Insufficient balance'));
    const refusal = await client.store('sg', 'k', {}).catch((e) => e);
    expect(refusal).toMatchObject({ code: 'TX_SUBMIT_FAILED', result: { rawLog: 'Insufficient balance' } });
    expect(refusal.message).toBe('store failed: Insufficient balance');
  });

  it('WillowClient.deregisterSubgrove throws it too', async () => {
    let sent = stubChain(4, () => inCache());
    const client = new WillowClient({ apiUrl: 'http://api.test', nonceAllocator: new NonceAllocator() });
    client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');

    const pending = await client.deregisterSubgrove('sg').catch((e) => e);
    expect(pending).toBeInstanceOf(TransactionSubmitError);
    expect(pending).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: DID, nonce: 5, result: { pending: true } });
    expect(pending.message).toMatch(/^deregisterSubgrove failed: unconfirmed/);
    expect(toJson(pending.transaction)).toBe(sent[0]);

    stubChain(4, () => refused('Only the owner can deregister'));
    const refusal = await client.deregisterSubgrove('sg').catch((e) => e);
    expect(refusal).toBeInstanceOf(TransactionSubmitError);
    expect(refusal).toMatchObject({ code: 'TX_SUBMIT_FAILED', result: { rawLog: 'Only the owner can deregister' } });
    expect(refusal.message).toBe('deregisterSubgrove failed: Only the owner can deregister');

    sent = stubChain(4, () => accepted());
    await expect(client.deregisterSubgrove('sg')).resolves.toMatchObject({ success: true, txHash: 'AB12' });
    expect(sent).toHaveLength(1);
  });
});

describe('a StoreData value must be a JSON object', () => {
  it('anything else is refused before a nonce is taken or anything is sent', async () => {
    const sent = stubChain(4, () => accepted());
    const allocator = new NonceAllocator();
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: allocator });
    const client = new WillowClient({ apiUrl: 'http://api.test', nonceAllocator: allocator });
    client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');
    // `undefined` would be signed as 0 bytes; a lone surrogate is escaped to text the node can't read.
    const notObjects: unknown[] = [undefined, null, [1, 2], 'text', 42, true, new Date(0), { s: '\ud800' }];
    for (const value of notObjects) {
      await expect(c.storeData('sg', 'k', value, DID, SIGNER)).rejects.toMatchObject({ code: 'INVALID_SIGNED_FIELD' });
      await expect(client.store('sg', 'k', value)).rejects.toMatchObject({ code: 'INVALID_SIGNED_FIELD' });
    }
    expect(global.fetch).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);

    // No nonce was taken: an object takes base + 1.
    await c.storeData('sg', 'k', { a: [1, null] }, DID, SIGNER);
    expect(sent.map(nonceOf)).toEqual([5]);
  });
});

describe('Transfer, DeregisterSubgrove, and SubmitAnchor text fields are checked like the others', () => {
  const BAD = 'x\ud800';
  const ANCHOR = {
    did: DID,
    anchorId: 'anchor-1',
    sequenceRange: [1, 1] as [number, number],
    receiptHashes: ['ab'.repeat(32)],
    timestamp: 't-1',
    previousAnchorHash: '',
    isGenesis: true,
  };

  it('a lone surrogate is refused before a nonce is taken or anything is sent', async () => {
    const sent = stubChain(4, () => accepted());
    const allocator = new NonceAllocator();
    const c = new ConsensusClient({ apiUrl: 'http://api.test', nonceAllocator: allocator });
    const client = new WillowClient({ apiUrl: 'http://api.test', nonceAllocator: allocator });
    client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');
    const writes: Array<() => Promise<unknown>> = [
      () => c.transfer(DID, `did:willow:bob${BAD}`, 1n, SIGNER),
      () => c.transfer(DID, 'did:willow:bob', 1n, SIGNER, `memo ${BAD}`),
      () => c.deregisterSubgrove(`sg${BAD}`, DID, SIGNER),
      () => client.deregisterSubgrove(`sg${BAD}`),
      () => c.submitAnchor({ ...ANCHOR, anchorId: BAD }, SIGNER),
      () => c.submitAnchor({ ...ANCHOR, timestamp: BAD }, SIGNER),
      () => c.submitAnchor({ ...ANCHOR, previousAnchorHash: BAD }, SIGNER),
      () => c.submitAnchor({ ...ANCHOR, receiptHashes: ['ab'.repeat(32), BAD] }, SIGNER),
      () => c.submitAnchor({ ...ANCHOR, merkleRoot: BAD }, SIGNER),
    ];
    for (const write of writes) {
      await expect(write()).rejects.toMatchObject({
        code: 'INVALID_SIGNED_FIELD',
        message: expect.stringMatching(/surrogate/),
      });
    }
    expect(global.fetch).not.toHaveBeenCalled();
    expect(sent).toHaveLength(0);

    // A surrogate pair is one character, and fine; no nonce was taken: the next write takes base + 1.
    await c.transfer(DID, 'did:willow:bob', 1n, SIGNER, 'memo 😀');
    expect(sent.map(nonceOf)).toEqual([5]);
  });

  it('createSignMessage refuses them too', () => {
    const transfer = { fromDid: DID, toDid: 'did:willow:bob', amount: 1, nonce: 1 };
    const anchor = {
      ...ANCHOR,
      merkleRoot: 'ab'.repeat(32),
      count: 1,
      anchorHash: 'cd'.repeat(32),
      nonce: 1,
    };
    const refused: Array<[string, Record<string, unknown>]> = [
      ['Transfer', { ...transfer, fromDid: BAD }],
      ['Transfer', { ...transfer, toDid: BAD }],
      ['Transfer', { ...transfer, memo: BAD }],
      ['DeregisterSubgrove', { subgroveId: 'sg', ownerDid: BAD, nonce: 1 }],
      ['DeregisterSubgrove', { subgroveId: BAD, ownerDid: DID, nonce: 1 }],
      ['SubmitAnchor', { ...anchor, did: BAD }],
      ['SubmitAnchor', { ...anchor, anchorHash: BAD }],
    ];
    for (const [kind, tx] of refused) {
      expect(() => createSignMessage(kind, tx as any)).toThrow(
        expect.objectContaining({ code: 'INVALID_SIGNED_FIELD' }),
      );
    }
    expect(createSignMessage('Transfer', transfer)).toBe(
      `Transfer\nFrom: ${DID}\nTo: did:willow:bob\nAmount: 1\nMemo: \nNonce: 1`,
    );
    expect(createSignMessage('DeregisterSubgrove', { subgroveId: 'sg', ownerDid: DID, nonce: 2 })).toBe(
      `DeregisterSubgrove:sg:${DID}:2`,
    );
    expect(createSignMessage('SubmitAnchor', anchor)).toBe(`SubmitAnchor\n${'cd'.repeat(32)}\n1`);
  });
});
