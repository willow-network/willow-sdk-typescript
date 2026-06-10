import { PrivacyOperations, EncryptedKeyGrant, CommitmentFrequency } from '../src/privacy';
import { WillowAuth, signEd25519 } from '../src/auth';
import { WillowError } from '../src/types';
import { hexToBytes } from '../src/internal/bytes';

/** The wire signature is the byte-array form of the hex signEd25519 output. */
function sigArray(message: string): number[] {
  return Array.from(hexToBytes(signEd25519(message, PRIVATE_KEY)));
}

const API_URL = 'http://api.test';
const DID = 'did:willow:owner';
const PRIVATE_KEY = '11'.repeat(32);
const KEY_ID = `${DID}#key-1`;

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function nonceResponse(nonce: number) {
  return jsonResponse({ success: true, data: { nonce } });
}

function txAccepted(txHash = 'FEED') {
  return jsonResponse({ success: true, data: { tx_hash: txHash, code: 0, log: 'ok' } });
}

function txRejected(log: string) {
  return jsonResponse({ success: true, data: { tx_hash: 'FEED', code: 5, log } });
}

function makePrivacy(withIdentity = true) {
  const auth = new WillowAuth(API_URL);
  if (withIdentity) auth.setIdentity(DID, PRIVATE_KEY, KEY_ID);
  return new PrivacyOperations(API_URL, auth, PRIVATE_KEY, KEY_ID);
}

const grant: EncryptedKeyGrant = {
  grantee_did: 'did:willow:reader',
  key_epoch: 1,
  grantee_public_key_id: 'did:willow:reader#key-1',
  ephemeral_public_key: [1, 2, 3],
  encrypted_key: [4, 5, 6],
  granted_by: DID,
  granted_at: 1700000000,
};

beforeEach(() => jest.clearAllMocks());

describe('PrivacyOperations — write operations broadcast through /tx/submit', () => {
  it('grantSubgroveKey fetches the nonce, signs, and POSTs the wrapped tx', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(4))
      .mockResolvedValueOnce(txAccepted('AB12'));

    const privacy = makePrivacy();
    const result = await privacy.grantSubgroveKey('private-data', grant);

    expect(result.success).toBe(true);
    expect(result.txHash).toBe('AB12');

    expect(mockFetch.mock.calls[0][0]).toBe(
      `${API_URL}/account/${encodeURIComponent(DID)}/nonce`,
    );

    const [url, init] = mockFetch.mock.calls[1];
    expect(url).toBe(`${API_URL}/tx/submit`);
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers['X-DID']).toBe(DID);
    expect(init.headers['X-Signature']).toBeTruthy();

    const body = JSON.parse(init.body);
    expect(Object.keys(body)).toEqual(['GrantSubgroveKey']);
    const tx = body.GrantSubgroveKey;
    // snake_case keys — must match the Rust GrantSubgroveKeyTx field names.
    expect(Object.keys(tx).sort()).toEqual(
      ['encrypted_key_grant', 'nonce', 'public_key_id', 'sender_did', 'signature', 'subgrove_id'].sort(),
    );
    expect(tx.subgrove_id).toBe('private-data');
    // EncryptedKeyGrant byte fields stay number[] (Rust Vec<u8>, no serde_bytes).
    expect(tx.encrypted_key_grant).toEqual(grant);
    expect(Array.isArray(tx.encrypted_key_grant.ephemeral_public_key)).toBe(true);
    expect(Array.isArray(tx.encrypted_key_grant.encrypted_key)).toBe(true);
    expect(tx.sender_did).toBe(DID);
    expect(tx.public_key_id).toBe(KEY_ID);
    expect(tx.nonce).toBe(5); // fetched nonce + 1
    // signature is an array of numbers (Rust Vec<u8>), never a hex string.
    expect(Array.isArray(tx.signature)).toBe(true);
    expect(tx.signature.every((b: number) => Number.isInteger(b) && b >= 0 && b <= 255)).toBe(true);
    expect(tx.signature).toEqual(
      sigArray(`GrantSubgroveKey:private-data:${grant.grantee_did}:${DID}:5`),
    );
  });

  it('revokeSubgroveKey wraps a RevokeSubgroveKey tx with the canonical message', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(9))
      .mockResolvedValueOnce(txAccepted());

    const privacy = makePrivacy();
    await privacy.revokeSubgroveKey('private-data', 'did:willow:reader');

    const tx = JSON.parse(mockFetch.mock.calls[1][1].body).RevokeSubgroveKey;
    expect(tx.subgrove_id).toBe('private-data');
    expect(tx.revokee_did).toBe('did:willow:reader');
    expect(tx.sender_did).toBe(DID);
    expect(tx.nonce).toBe(10);
    expect(Array.isArray(tx.signature)).toBe(true);
    expect(tx.signature).toEqual(
      sigArray(`RevokeSubgroveKey:private-data:did:willow:reader:${DID}:10`),
    );
  });

  it('rotateSubgroveKey wraps a RotateSubgroveKey tx with the new epoch and grants', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(0))
      .mockResolvedValueOnce(txAccepted());

    const privacy = makePrivacy();
    await privacy.rotateSubgroveKey('private-data', 2, [grant]);

    const tx = JSON.parse(mockFetch.mock.calls[1][1].body).RotateSubgroveKey;
    expect(tx.subgrove_id).toBe('private-data');
    expect(tx.new_epoch).toBe(2);
    expect(tx.new_grants).toEqual([grant]);
    expect(tx.sender_did).toBe(DID);
    expect(Array.isArray(tx.signature)).toBe(true);
    expect(tx.signature).toEqual(sigArray(`RotateSubgroveKey:private-data:2:${DID}:1`));
  });

  it('maps a consensus rejection (code !== 0) to BROADCAST_FAILED', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(4))
      .mockResolvedValueOnce(txRejected('not the subgrove owner'));

    const privacy = makePrivacy();
    const err = await privacy
      .grantSubgroveKey('private-data', grant)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('BROADCAST_FAILED');
    expect(err.message).toMatch(/not the subgrove owner/);
  });

  it('maps a network failure during broadcast to BROADCAST_FAILED', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(4))
      .mockRejectedValueOnce(new Error('connection refused'));

    const privacy = makePrivacy();
    const err = await privacy
      .grantSubgroveKey('private-data', grant)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('BROADCAST_FAILED');
    expect(err.message).toMatch(/connection refused/);
  });

  it('propagates nonce fetch failures instead of broadcasting with a guess', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: false, error: 'down' }));

    const privacy = makePrivacy();
    const err = await privacy
      .grantSubgroveKey('private-data', grant)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('NONCE_FETCH_FAILED');
    expect(mockFetch).toHaveBeenCalledTimes(1); // never reached /tx/submit
  });

  it('requires an identity before broadcasting', async () => {
    const privacy = makePrivacy(false);
    const err = await privacy
      .grantSubgroveKey('private-data', grant)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('NO_IDENTITY');
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe('PrivacyOperations — read operations', () => {
  it('getMyKeyGrant signs the real key-grants path and unwraps the grant', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data: grant }));

    const privacy = makePrivacy();
    const result = await privacy.getMyKeyGrant('private-data');

    expect(result).toEqual(grant);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(
      `${API_URL}/key-grants/private-data/${encodeURIComponent(DID)}`,
    );
    expect(init.headers['X-DID']).toBe(DID);
    expect(init.headers['X-Signature']).toBeTruthy();
  });

  it('getMyKeyGrant maps an unsuccessful envelope to KEY_GRANT_NOT_FOUND', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: false, error: 'no grant' }));

    const privacy = makePrivacy();
    const err = await privacy.getMyKeyGrant('private-data').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('KEY_GRANT_NOT_FOUND');
    expect(err.statusCode).toBe(404);
    expect(err.message).toMatch(/no grant/);
  });

  it('listKeyGrantees returns the grantee DIDs', async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ success: true, data: ['did:willow:a', 'did:willow:b'] }),
    );

    const privacy = makePrivacy();
    expect(await privacy.listKeyGrantees('private-data')).toEqual([
      'did:willow:a',
      'did:willow:b',
    ]);
    expect(mockFetch.mock.calls[0][0]).toBe(`${API_URL}/key-grants/private-data`);
  });

  it('getKeyGrantProof maps an unsuccessful envelope to KEY_GRANT_PROOF_FAILED', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ success: false, error: 'no proof' }));

    const privacy = makePrivacy();
    const err = await privacy
      .getKeyGrantProof('private-data', 'did:willow:reader')
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('KEY_GRANT_PROOF_FAILED');
  });
});

describe('PrivacyOperations — non-2xx HTTP failures map to typed WillowError codes', () => {
  it('getMyKeyGrant maps a 404 to KEY_GRANT_NOT_FOUND (not an untyped HttpError)', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'not found' }, 404));

    const privacy = makePrivacy();
    const err = await privacy.getMyKeyGrant('private-data').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('KEY_GRANT_NOT_FOUND');
    expect(err.statusCode).toBe(404);
    expect(err.message).toMatch(/not found/);
  });

  it('getMyKeyGrant keeps the documented code but surfaces the real status on a 500', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, 500));

    const privacy = makePrivacy();
    const err = await privacy.getMyKeyGrant('private-data').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('KEY_GRANT_NOT_FOUND');
    expect(err.statusCode).toBe(500);
  });

  it('getKeyGrantProof maps a 404 to KEY_GRANT_PROOF_FAILED', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'no proof' }, 404));

    const privacy = makePrivacy();
    const err = await privacy
      .getKeyGrantProof('private-data', 'did:willow:reader')
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('KEY_GRANT_PROOF_FAILED');
    expect(err.statusCode).toBe(404);
  });

  it('listKeyGrantees maps a 500 to LIST_GRANTEES_FAILED', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'denied' }, 500));

    const privacy = makePrivacy();
    const err = await privacy.listKeyGrantees('private-data').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('LIST_GRANTEES_FAILED');
  });

  it('getNextNonce (via grant) maps a non-2xx nonce fetch to NONCE_FETCH_FAILED', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'down' }, 503));

    const privacy = makePrivacy();
    const err = await privacy.grantSubgroveKey('private-data', grant).catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('NONCE_FETCH_FAILED');
    expect(mockFetch).toHaveBeenCalledTimes(1); // never reached /tx/submit
  });
});

describe('CommitmentFrequency constructors', () => {
  it('produce the serde representations the chain expects', () => {
    expect(CommitmentFrequency.everyUpdate()).toBe('EveryUpdate');
    expect(CommitmentFrequency.everyNBlocks(10)).toEqual({ EveryNBlocks: 10 });
    expect(CommitmentFrequency.everyNSeconds(60)).toEqual({ EveryNSeconds: 60 });
    expect(CommitmentFrequency.never()).toBe('Never');
  });
});
