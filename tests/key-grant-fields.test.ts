import { signEd25519, verifyEd25519, getEd25519PublicKey, WillowAuth } from '../src/auth';
import { NonceAllocator } from '../src/consensus/nonces';
import {
  createSignMessage,
  createTransactionWrapper,
  EncryptedKeyGrant,
  GrantSubgroveKeyTx,
  grantSubgroveKeySignMessage,
  RevokeSubgroveKeyTx,
  revokeSubgroveKeySignMessage,
  RotateSubgroveKeyTx,
  rotateSubgroveKeySignMessage,
} from '../src/consensus/types';
import { PrivacyOperations } from '../src/privacy';
import { WillowError } from '../src/types';

/**
 * The chain's CheckTx refuses a RevokeSubgroveKey whose subgrove id is empty
 * or holds a ':', or whose `revokee_did` or `sender_did` is not a Willow
 * DID; and a GrantSubgroveKey or RotateSubgroveKey whose subgrove id is
 * empty or holds a ':', or one of whose grants has a `grantee_did` that is
 * not one. A Willow DID is `did:willow:` followed by one or more ASCII
 * letters, digits, `_`, or `-`, at most 128 bytes in all.
 */

const OWNER = 'did:willow:owner';
const PRIVATE_KEY = '11'.repeat(32);
const KEY_ID = `${OWNER}#key-1`;

const GOOD_DIDS = [
  'did:willow:a',
  'did:willow:A-b_9',
  'did:willow:0',
  `did:willow:${'x'.repeat(117)}`, // 128 bytes
];

const BAD_DIDS = [
  '',
  'did:willow:',
  'did:willow',
  'did:key:abc',
  'DID:willow:a',
  ' did:willow:a',
  'did:willow:a ',
  'did:willow:a.b',
  'did:willow:a:b',
  'did:willow:a#key-1',
  'did:willow:ä',
  'did:willow:a\n',
  `did:willow:${'x'.repeat(118)}`, // 129 bytes
];

const grant: EncryptedKeyGrant = {
  grantee_did: 'did:willow:reader',
  key_epoch: 1,
  grantee_public_key_id: 'did:willow:reader#key-1',
  ephemeral_public_key: Array(32).fill(1),
  encrypted_key: [4, 5, 6],
  granted_by: OWNER,
  granted_at: 1700000000,
};

const revoke: RevokeSubgroveKeyTx = {
  subgroveId: 'private-data',
  revokeeDid: 'did:willow:reader',
  senderDid: OWNER,
  publicKeyId: KEY_ID,
  nonce: 10,
};

const grantTx: GrantSubgroveKeyTx = {
  subgroveId: 'private-data',
  encryptedKeyGrant: grant,
  senderDid: OWNER,
  publicKeyId: KEY_ID,
  nonce: 5,
};

const rotateTx: RotateSubgroveKeyTx = {
  subgroveId: 'private-data',
  newEpoch: 2,
  newGrants: [grant, { ...grant, grantee_did: 'did:willow:other' }],
  senderDid: OWNER,
  publicKeyId: KEY_ID,
  nonce: 6,
};

function refuses(f: () => unknown, code: string, pattern?: RegExp) {
  let caught: unknown;
  try {
    f();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(WillowError);
  expect((caught as WillowError).code).toBe(code);
  if (pattern) expect((caught as WillowError).message).toMatch(pattern);
}

describe('RevokeSubgroveKey', () => {
  it('signs the revoke message', () => {
    const message = 'RevokeSubgroveKey:private-data:did:willow:reader:did:willow:owner:10';
    expect(revokeSubgroveKeySignMessage(revoke)).toBe(message);
    expect(createSignMessage('RevokeSubgroveKey', revoke)).toBe(message);
  });

  it.each(['', 'a:b', ':', 'private-data:'])('refuses the subgrove id %j', (subgroveId) => {
    refuses(() => revokeSubgroveKeySignMessage({ ...revoke, subgroveId }), 'INVALID_SUBGROVE_ID');
    refuses(
      () => createTransactionWrapper('RevokeSubgroveKey', { ...revoke, subgroveId, signature: '00' }),
      'INVALID_SUBGROVE_ID',
    );
  });

  it('takes a subgrove id the chain takes', () => {
    for (const subgroveId of ['a', 'my.subgrove', 'a b', 'ü']) {
      expect(revokeSubgroveKeySignMessage({ ...revoke, subgroveId })).toBe(
        `RevokeSubgroveKey:${subgroveId}:did:willow:reader:did:willow:owner:10`,
      );
    }
  });

  it.each(BAD_DIDS)('refuses the revokee or sender %j', (did) => {
    refuses(() => revokeSubgroveKeySignMessage({ ...revoke, revokeeDid: did }), 'INVALID_DID', /revokeeDid/);
    refuses(() => revokeSubgroveKeySignMessage({ ...revoke, senderDid: did }), 'INVALID_DID', /senderDid/);
    refuses(
      () => createTransactionWrapper('RevokeSubgroveKey', { ...revoke, revokeeDid: did, signature: '00' }),
      'INVALID_DID',
    );
  });

  it.each(GOOD_DIDS)('takes the revokee or sender %j', (did) => {
    expect(revokeSubgroveKeySignMessage({ ...revoke, revokeeDid: did, senderDid: did })).toBe(
      `RevokeSubgroveKey:private-data:${did}:${did}:10`,
    );
  });

  it('refuses to sign without a nonce, or with an unsafe one', () => {
    for (const nonce of [undefined, -1, 1.5, 2 ** 53]) {
      expect(() => revokeSubgroveKeySignMessage({ ...revoke, nonce })).toThrow(WillowError);
    }
  });
});

describe('GrantSubgroveKey and RotateSubgroveKey', () => {
  it.each(BAD_DIDS.filter((d) => !d.includes('\n')))('refuse the grantee %j', (did) => {
    const bad = { ...grant, grantee_did: did };
    refuses(
      () => grantSubgroveKeySignMessage({ ...grantTx, encryptedKeyGrant: bad }),
      'INVALID_DID',
      /encryptedKeyGrant\.grantee_did/,
    );
    refuses(
      () => createTransactionWrapper('GrantSubgroveKey', { ...grantTx, encryptedKeyGrant: bad, signature: '00' }),
      'INVALID_DID',
    );
    const newGrants = [grant, bad];
    refuses(
      () => rotateSubgroveKeySignMessage({ ...rotateTx, newGrants }),
      'INVALID_DID',
      /newGrants\[1\]\.grantee_did/,
    );
    refuses(
      () => createTransactionWrapper('RotateSubgroveKey', { ...rotateTx, newGrants, signature: '00' }),
      'INVALID_DID',
    );
  });

  it('refuse a line break in the grantee as a line break', () => {
    refuses(
      () => grantSubgroveKeySignMessage({ ...grantTx, encryptedKeyGrant: { ...grant, grantee_did: 'did:willow:a\n' } }),
      'LINE_BREAK_IN_SIGNED_FIELD',
    );
  });

  it.each(GOOD_DIDS)('take the grantee %j', (did) => {
    const g = { ...grant, grantee_did: did };
    expect(grantSubgroveKeySignMessage({ ...grantTx, encryptedKeyGrant: g }).split('\n')[3]).toBe(
      `Grantee: ${did}`,
    );
    expect(rotateSubgroveKeySignMessage({ ...rotateTx, newGrants: [g] }).split('\n')[5]).toBe(
      `Grantee: ${did}`,
    );
  });

  it.each(['', 'a:b'])('refuse the subgrove id %j', (subgroveId) => {
    refuses(() => grantSubgroveKeySignMessage({ ...grantTx, subgroveId }), 'INVALID_SUBGROVE_ID');
    refuses(() => rotateSubgroveKeySignMessage({ ...rotateTx, subgroveId }), 'INVALID_SUBGROVE_ID');
    refuses(
      () => createTransactionWrapper('GrantSubgroveKey', { ...grantTx, subgroveId, signature: '00' }),
      'INVALID_SUBGROVE_ID',
    );
    refuses(
      () => createTransactionWrapper('RotateSubgroveKey', { ...rotateTx, subgroveId, signature: '00' }),
      'INVALID_SUBGROVE_ID',
    );
  });
});

describe('PrivacyOperations refuses these before taking a nonce', () => {
  const originalFetch = global.fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn(async (url: string) => {
      const body = url.includes('/nonce')
        ? { success: true, data: { nonce: 9 } }
        : { success: true, data: { tx_hash: 'AB12', code: 0, log: '' } };
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      } as unknown as Response;
    });
    global.fetch = fetchMock as unknown as typeof fetch;
  });
  afterEach(() => {
    global.fetch = originalFetch;
  });

  function privacy() {
    const auth = new WillowAuth('http://api.test');
    auth.setIdentity(OWNER, PRIVATE_KEY, KEY_ID, 'Ed25519');
    return new PrivacyOperations('http://api.test', auth, PRIVATE_KEY, KEY_ID, undefined, new NonceAllocator());
  }

  it('revokeSubgroveKey', async () => {
    const p = privacy();
    await expect(p.revokeSubgroveKey('private-data', 'reader')).rejects.toMatchObject({ code: 'INVALID_DID' });
    await expect(p.revokeSubgroveKey('a:b', 'did:willow:reader')).rejects.toMatchObject({
      code: 'INVALID_SUBGROVE_ID',
    });
    expect(fetchMock).not.toHaveBeenCalled();

    // A revoke the chain takes is signed over its own fields.
    await p.revokeSubgroveKey('private-data', 'did:willow:reader');
    const [, init] = fetchMock.mock.calls.find(([url]) => url.endsWith('/tx/submit'))!;
    const w = JSON.parse(init.body).RevokeSubgroveKey;
    expect(w.nonce).toBe(10);
    const message = revokeSubgroveKeySignMessage({
      subgroveId: w.subgrove_id,
      revokeeDid: w.revokee_did,
      senderDid: w.sender_did,
      nonce: w.nonce,
    });
    const signature = Buffer.from(w.signature as number[]).toString('hex');
    expect(verifyEd25519(message, signature, getEd25519PublicKey(PRIVATE_KEY))).toBe(true);
    expect(signature).toBe(signEd25519(message, PRIVATE_KEY));
  });

  it('revokeSubgroveKey with an identity that is not a Willow DID', async () => {
    const auth = new WillowAuth('http://api.test');
    auth.setIdentity('did:key:z6Mk', PRIVATE_KEY, 'did:key:z6Mk#key-1', 'Ed25519');
    const p = new PrivacyOperations('http://api.test', auth, PRIVATE_KEY, 'did:key:z6Mk#key-1', undefined, new NonceAllocator());
    await expect(p.revokeSubgroveKey('private-data', 'did:willow:reader')).rejects.toMatchObject({
      code: 'INVALID_DID',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('grantSubgroveKey', async () => {
    await expect(
      privacy().grantSubgroveKey('private-data', { ...grant, grantee_did: 'reader' }),
    ).rejects.toMatchObject({ code: 'INVALID_DID' });
    await expect(privacy().grantSubgroveKey('a:b', grant)).rejects.toMatchObject({
      code: 'INVALID_SUBGROVE_ID',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rotateSubgroveKey', async () => {
    await expect(
      privacy().rotateSubgroveKey('private-data', 2, [grant, { ...grant, grantee_did: 'did:willow:' }]),
    ).rejects.toMatchObject({ code: 'INVALID_DID' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
