import { PrivacyOperations, EncryptedKeyGrant, CommitmentFrequency } from '../src/privacy';
import { WillowAuth, signEd25519 } from '../src/auth';
import { WillowError } from '../src/types';

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
    expect(tx.subgrove_id).toBe('private-data');
    expect(tx.encrypted_key_grant).toEqual(grant);
    expect(tx.sender_did).toBe(DID);
    expect(tx.public_key_id).toBe(KEY_ID);
    expect(tx.nonce).toBe(5); // fetched nonce + 1
    expect(tx.signature).toBe(
      signEd25519(
        `GrantSubgroveKey:private-data:${grant.grantee_did}:${DID}:5`,
        PRIVATE_KEY,
      ),
    );
  });

  it('revokeSubgroveKey wraps a RevokeSubgroveKey tx with the canonical message', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(9))
      .mockResolvedValueOnce(txAccepted());

    const privacy = makePrivacy();
    await privacy.revokeSubgroveKey('private-data', 'did:willow:reader');

    const tx = JSON.parse(mockFetch.mock.calls[1][1].body).RevokeSubgroveKey;
    expect(tx.revokee_did).toBe('did:willow:reader');
    expect(tx.nonce).toBe(10);
    expect(tx.signature).toBe(
      signEd25519(
        `RevokeSubgroveKey:private-data:did:willow:reader:${DID}:10`,
        PRIVATE_KEY,
      ),
    );
  });

  it('rotateSubgroveKey wraps a RotateSubgroveKey tx with the new epoch and grants', async () => {
    mockFetch
      .mockResolvedValueOnce(nonceResponse(0))
      .mockResolvedValueOnce(txAccepted());

    const privacy = makePrivacy();
    await privacy.rotateSubgroveKey('private-data', 2, [grant]);

    const tx = JSON.parse(mockFetch.mock.calls[1][1].body).RotateSubgroveKey;
    expect(tx.new_epoch).toBe(2);
    expect(tx.new_grants).toEqual([grant]);
    expect(tx.signature).toBe(
      signEd25519(`RotateSubgroveKey:private-data:2:${DID}:1`, PRIVATE_KEY),
    );
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

describe('CommitmentFrequency constructors', () => {
  it('produce the serde representations the chain expects', () => {
    expect(CommitmentFrequency.everyUpdate()).toBe('EveryUpdate');
    expect(CommitmentFrequency.everyNBlocks(10)).toEqual({ EveryNBlocks: 10 });
    expect(CommitmentFrequency.everyNSeconds(60)).toEqual({ EveryNSeconds: 60 });
    expect(CommitmentFrequency.never()).toBe('Never');
  });
});
