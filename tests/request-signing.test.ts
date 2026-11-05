import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ethers } from 'ethers';
import {
  WillowAuth,
  legacyRequestMessage,
  newRequestNonce,
  signSecp256k1,
  signedRequestMessage,
  verifyEd25519,
  verifySecp256k1,
} from '../src/auth';
import { WillowClient } from '../src/client';
import { PrivacyOperations } from '../src/privacy';
import { createDidFromPublicKey, createDidFromWallet } from '../src/utils';
import { WillowError } from '../src/types';
import { bytesToBase64, bytesToHex, hexToBytes, utf8ToBytes } from '../src/internal/bytes';

// The api-server's test vector (crates/api-server/src/read_auth_tests.rs,
// the_signed_message_is_eight_lines), byte for byte.
const VECTOR_MESSAGE =
  'willow-request-v2\ndid:willow:a\ndid:willow:a#key-1\nPOST\n/query/sg?x=1\n1700000000\n' +
  'abcdefghijklmnop\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';

// Signatures over VECTOR_MESSAGE by the key whose seed is 32 bytes of 0x03,
// computed with an independent implementation of the server's verification.
const SEED = '03'.repeat(32);
const ED25519_PUBLIC_KEY = 'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1';
const ED25519_SIGNATURE =
  'c117313c0d01641340e398d9a7a9ff024a1c6672bca16bbcb99e6fe2738f82e7' +
  '7870bd2c30dc62d6c50cea32a3b21086730d9c25297831dd83bc797c5b394d0d';
const SECP256K1_PUBLIC_KEY = '02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337';
const SECP256K1_KECCAK = 'd88e0d6795532372abf6cc33c33a8903b5b0fb108c1dc0b0ccc63fe061bd9e93';
const SECP256K1_COMPACT =
  'bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238' +
  '30787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d';
const SECP256K1_DER =
  '3045022100bfbad8ec000c66ed30349070db245db0c45249293c545e35dc997d6427d32238' +
  '022030787244d5b3bb7e8a1b39bdba0c62261e02344a515f5e8e89f678e17d4b976d';

const DID = 'did:willow:a';
const KEY_ID = 'did:willow:a#key-1';
const FIXED = { timestamp: 1700000000, nonce: 'abcdefghijklmnop' };

function vectorAuth(algorithm: 'Ed25519' | 'secp256k1', apiUrl = 'http://api.test'): WillowAuth {
  const auth = new WillowAuth(apiUrl);
  auth.setIdentity(DID, SEED, KEY_ID, algorithm);
  return auth;
}

describe('request signing: known answers', () => {
  it('builds the eight-line message byte for byte', () => {
    const fromString = signedRequestMessage(
      DID, KEY_ID, 'POST', '/query/sg?x=1', '1700000000', 'abcdefghijklmnop', '{}',
    );
    expect(fromString).toBe(VECTOR_MESSAGE);
    const fromBytes = signedRequestMessage(
      DID, KEY_ID, 'POST', '/query/sg?x=1', '1700000000', 'abcdefghijklmnop', utf8ToBytes('{}'),
    );
    expect(fromBytes).toBe(VECTOR_MESSAGE);
  });

  it('hashes no body as the SHA-256 of no bytes', () => {
    const message = signedRequestMessage(DID, KEY_ID, 'GET', '/data/sg/k', '1', 'n'.repeat(16));
    expect(message.split('\n')[7]).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('signs the vector with Ed25519 and makes exactly the five headers', () => {
    const headers = vectorAuth('Ed25519').signRequestWithNonce('POST', '/query/sg?x=1', '{}', FIXED);
    expect(headers).toEqual({
      'X-DID': DID,
      'X-Public-Key-ID': KEY_ID,
      'X-Signature': ED25519_SIGNATURE,
      'X-Timestamp': '1700000000',
      'X-Nonce': 'abcdefghijklmnop',
    });
    expect(bytesToHex(ed25519.getPublicKey(hexToBytes(SEED)))).toBe(ED25519_PUBLIC_KEY);
    expect(verifyEd25519(VECTOR_MESSAGE, ED25519_SIGNATURE, ED25519_PUBLIC_KEY)).toBe(true);
  });

  it('signs the vector with secp256k1 over Keccak-256, 0x-prefixed compact r||s', () => {
    const headers = vectorAuth('secp256k1').signRequestWithNonce('POST', '/query/sg?x=1', '{}', FIXED);
    // 0x-prefixed: the server reads an unprefixed secp256k1 signature as base64 first.
    expect(headers['X-Signature']).toBe(`0x${SECP256K1_COMPACT}`);
    expect(headers['X-Nonce']).toBe('abcdefghijklmnop');
    expect(signSecp256k1(VECTOR_MESSAGE, `0x${SEED}`)).toBe(`0x${SECP256K1_COMPACT}`);
    expect(ethers.keccak256(ethers.toUtf8Bytes(VECTOR_MESSAGE))).toBe(`0x${SECP256K1_KECCAK}`);
    expect(bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), true))).toBe(SECP256K1_PUBLIC_KEY);
  });

  it("accepts the secp256k1 known answer in the SDK's verify, compact or DER", () => {
    const uncompressed = bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), false));
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${SECP256K1_COMPACT}`, SECP256K1_PUBLIC_KEY)).toBe(true);
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${SECP256K1_DER}`, SECP256K1_PUBLIC_KEY)).toBe(true);
    // Without a prefix the server reads base64 first, as this does.
    const base64 = bytesToBase64(hexToBytes(SECP256K1_COMPACT));
    expect(verifySecp256k1(VECTOR_MESSAGE, base64, SECP256K1_PUBLIC_KEY)).toBe(true);
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${SECP256K1_COMPACT}`, uncompressed)).toBe(true);
    // The 64-byte x || y form without the 04 tag, which older documents carry.
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${SECP256K1_COMPACT}`, uncompressed.slice(2))).toBe(true);
    expect(verifySecp256k1(`${VECTOR_MESSAGE}x`, `0x${SECP256K1_COMPACT}`, SECP256K1_PUBLIC_KEY)).toBe(false);
  });

  it('decodes an unprefixed signature base64 first, like the server', () => {
    // 128 hex characters are valid base64, which the server tries first, so
    // the unprefixed compact signature decodes to the wrong bytes.
    expect(verifySecp256k1(VECTOR_MESSAGE, SECP256K1_COMPACT, SECP256K1_PUBLIC_KEY)).toBe(false);
    // 142 hex characters are not padded base64, so the server falls back to hex.
    expect(verifySecp256k1(VECTOR_MESSAGE, SECP256K1_DER, SECP256K1_PUBLIC_KEY)).toBe(true);
  });

  it('refuses a high-S or recoverable secp256k1 signature, like the server', () => {
    const r = BigInt(`0x${SECP256K1_COMPACT.slice(0, 64)}`);
    const s = BigInt(`0x${SECP256K1_COMPACT.slice(64)}`);
    const highS = new secp256k1.Signature(r, secp256k1.CURVE.n - s).toCompactHex();
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${highS}`, SECP256K1_PUBLIC_KEY)).toBe(false);
    expect(verifySecp256k1(VECTOR_MESSAGE, `0x${SECP256K1_COMPACT}1b`, SECP256K1_PUBLIC_KEY)).toBe(false);
  });
});

describe('request signing: the older form', () => {
  it('drops the query string from the path', () => {
    expect(legacyRequestMessage('GET', '/data/sg/k?include_proof=true', '1700000000')).toBe(
      'GET:/data/sg/k:1700000000',
    );
    expect(legacyRequestMessage('GET', '/data/sg/k', '1700000000')).toBe('GET:/data/sg/k:1700000000');
  });

  it('signs METHOD:PATH:TIMESTAMP with Ed25519 and no nonce', () => {
    const headers = vectorAuth('Ed25519').signRequest('GET', '/data/sg/k?include_proof=true');
    expect(headers['X-Nonce']).toBeUndefined();
    expect(Object.keys(headers).sort()).toEqual(['X-DID', 'X-Public-Key-ID', 'X-Signature', 'X-Timestamp']);
    const message = `GET:/data/sg/k:${headers['X-Timestamp']}`;
    expect(verifyEd25519(message, headers['X-Signature'], ED25519_PUBLIC_KEY)).toBe(true);
  });

  it('signs METHOD:PATH:TIMESTAMP with secp256k1, 0x-prefixed over Keccak-256', () => {
    const headers = vectorAuth('secp256k1').signRequest('POST', '/tx/submit');
    expect(headers['X-Signature']).toMatch(/^0x[0-9a-f]{128}$/);
    const message = `POST:/tx/submit:${headers['X-Timestamp']}`;
    expect(verifySecp256k1(message, headers['X-Signature'], SECP256K1_PUBLIC_KEY)).toBe(true);
  });
});

describe('request signing: nonces', () => {
  it('makes 32 hex characters the server accepts, never twice', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const nonce = newRequestNonce();
      expect(nonce).toMatch(/^[0-9a-f]{32}$/);
      expect(nonce).toMatch(/^[A-Za-z0-9_-]{16,128}$/);
      expect(seen.has(nonce)).toBe(false);
      seen.add(nonce);
    }
  });

  it('draws a fresh nonce and the current time for each signature', () => {
    const auth = vectorAuth('Ed25519');
    const a = auth.signRequestWithNonce('GET', '/data/sg/k');
    const b = auth.signRequestWithNonce('GET', '/data/sg/k');
    expect(a['X-Nonce']).not.toBe(b['X-Nonce']);
    expect(Math.abs(Number(a['X-Timestamp']) - Date.now() / 1000)).toBeLessThan(5);
  });
});

// ---------------------------------------------------------------------------
// Through the client: what a server would verify, rebuilt from what it got.
// ---------------------------------------------------------------------------

interface Received {
  method: string;
  url: URL;
  target: string;
  headers: Record<string, string>;
  body?: string;
}

const mockFetch = jest.fn();

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

function received(): Received[] {
  return mockFetch.mock.calls.map(([input, init]) => {
    const url = new URL(String(input));
    return {
      method: (init?.method as string) ?? 'GET',
      url,
      // What the request line carries, which is what the API reads.
      target: url.pathname + url.search,
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: init?.body as string | undefined,
    };
  });
}

/** Verify a nonce-signed request the way the API does. */
function verifiesAsNonceSigned(req: Received, target = req.target): boolean {
  const h = req.headers;
  if (!h['X-Nonce']) return false;
  const message = signedRequestMessage(
    h['X-DID'], h['X-Public-Key-ID'], req.method, target, h['X-Timestamp'], h['X-Nonce'], req.body,
  );
  return verifyEd25519(message, h['X-Signature'], ED25519_PUBLIC_KEY);
}

/** Verify an older-form request the way the API does: over the path alone. */
function verifiesAsOlderForm(req: Received, path = req.url.pathname): boolean {
  const h = req.headers;
  if (h['X-Nonce'] !== undefined) return false;
  const message = `${req.method}:${path}:${h['X-Timestamp']}`;
  return verifyEd25519(message, h['X-Signature'], ED25519_PUBLIC_KEY);
}

function vectorClient(config: Partial<ConstructorParameters<typeof WillowClient>[0]> = {}) {
  const client = new WillowClient({ apiUrl: 'http://api.test', ...config });
  client.auth.setIdentity(DID, SEED, KEY_ID, 'Ed25519');
  return client;
}

describe('request signing: through the client', () => {
  const realFetch = global.fetch;
  beforeAll(() => {
    global.fetch = mockFetch as unknown as typeof fetch;
  });
  afterAll(() => {
    global.fetch = realFetch;
  });
  beforeEach(() => {
    mockFetch.mockReset();
    mockFetch.mockImplementation(async () =>
      jsonResponse({ success: true, data: { documents: [], proof: 'aa', total: 0 } }),
    );
  });

  it('nonce-signs a GET and a POST read over the request as received', async () => {
    const client = vectorClient();
    await client.data.getDataUnverified('sg', 'k');
    await client.data.queryUnverified('sg', { filters: { owner: 'x' } } as any);

    const [get, post] = received();
    expect(get.method).toBe('GET');
    expect(get.target).toBe('/data/sg/k');
    expect(get.body).toBeUndefined();
    expect(verifiesAsNonceSigned(get)).toBe(true);

    expect(post.method).toBe('POST');
    expect(post.target).toBe('/query/sg');
    expect(JSON.parse(post.body!)).toEqual({ filters: { owner: 'x' }, include_proof: false });
    expect(verifiesAsNonceSigned(post)).toBe(true);
    // A different body would not verify: the signature covers it.
    expect(verifiesAsNonceSigned({ ...post, body: '{}' })).toBe(false);
  });

  it('nonce-signs proofs, SQL, and GraphQL reads sent to the API', async () => {
    const client = vectorClient();
    await client.getProof('sg', 'k');
    await client.sqlQuery('sg', 'SELECT * FROM items', { source: 'validator' });
    await client.graphqlQuery('sg', '{ items { id } }', { source: 'validator' });

    const reqs = received();
    expect(reqs.map((r) => `${r.method} ${r.target}`)).toEqual([
      'GET /proof/sg/k',
      'POST /sql/sg',
      'POST /graphql/sg',
    ]);
    for (const req of reqs) expect(verifiesAsNonceSigned(req)).toBe(true);
  });

  it('signs the path as sent, percent-encoded', async () => {
    const client = vectorClient();
    await client.data.getDataUnverified('sg', 'a b');
    const [req] = received();
    expect(req.target).toBe('/data/sg/a%20b');
    expect(verifiesAsNonceSigned(req)).toBe(true);
    expect(verifiesAsNonceSigned(req, '/data/sg/a b')).toBe(false);
  });

  it('leaves out the path of an API base URL behind a proxy', async () => {
    const client = vectorClient({ apiUrl: 'https://proxy.example/willow/' });
    await client.data.getDataUnverified('sg', 'k');
    const [req] = received();
    expect(req.url.href).toBe('https://proxy.example/willow/data/sg/k');
    expect(verifiesAsNonceSigned(req, '/data/sg/k')).toBe(true);
  });

  it('signs each request with its own nonce', async () => {
    const client = vectorClient();
    await client.data.getDataUnverified('sg', 'k');
    await client.data.getDataUnverified('sg', 'k');
    const [a, b] = received();
    expect(verifiesAsNonceSigned(a)).toBe(true);
    expect(verifiesAsNonceSigned(b)).toBe(true);
    expect(a.headers['X-Nonce']).not.toBe(b.headers['X-Nonce']);
  });

  it('keeps transaction submission on the older form, over the path alone', async () => {
    mockFetch.mockImplementation(async () =>
      jsonResponse({ success: true, data: { tx_hash: 'AB12', code: 0, log: '' } }),
    );
    const client = vectorClient();
    await client.files.delete('sg', 'k', {
      ...client.auth.transactionSigner(),
      ownerDid: client.auth.getDid()!,
      nonce: 1,
    });
    const [req] = received();
    expect(`${req.method} ${req.target}`).toBe('POST /tx/submit');
    expect(verifiesAsOlderForm(req)).toBe(true);
  });

  it('sends no request for a data write, which the API serves only as a transaction', async () => {
    const client = vectorClient();
    for (const write of [
      () => client.data.storeData('sg', { k: 1 }),
      () => client.data.updateData('sg', 'k', { v: 2 }),
      () => client.data.deleteData('sg', 'k'),
    ]) {
      await expect(write()).rejects.toMatchObject({ code: 'UNSUPPORTED_OPERATION' });
    }
    expect(received()).toHaveLength(0);
  });

  it('sends X-API-Key with signed reads', async () => {
    const client = vectorClient({ apiKey: 'wk_test' });
    await client.data.getDataUnverified('sg', 'k');
    const [req] = received();
    expect(req.headers['X-API-Key']).toBe('wk_test');
    expect(verifiesAsNonceSigned(req)).toBe(true);
  });

  it('sends no request signature headers without an identity', async () => {
    const client = new WillowClient({ apiUrl: 'http://api.test' });
    await client.data.getDataUnverified('sg', 'k');
    const [req] = received();
    for (const name of ['X-DID', 'X-Public-Key-ID', 'X-Signature', 'X-Timestamp', 'X-Nonce']) {
      expect(req.headers[name]).toBeUndefined();
    }
  });

  it('never sends a nonce to an indexer', async () => {
    const client = vectorClient({ indexerUrl: 'http://indexer.test' });
    await client.sqlQuery('sg', 'SELECT 1', { source: 'indexer' });
    const [req] = received();
    expect(req.url.origin).toBe('http://indexer.test');
    expect(req.headers['X-Nonce']).toBeUndefined();
  });

  it('signs key-grant proof reads, in the older form over the encoded path', async () => {
    mockFetch.mockImplementation(async () =>
      jsonResponse({ success: true, data: { proof: 'aa', subgrove_id: 'sg', grantee_did: DID } }),
    );
    const auth = vectorAuth('Ed25519');
    const privacy = new PrivacyOperations('http://api.test', auth, SEED, KEY_ID);
    await privacy.getKeyGrantProof('sg', DID);
    await privacy.getMyKeyGrant('sg');
    const reqs = received();
    expect(reqs.map((r) => r.target)).toEqual([
      '/proof/key-grant/sg/did%3Awillow%3Aa',
      '/key-grants/sg/did%3Awillow%3Aa',
    ]);
    for (const req of reqs) expect(verifiesAsOlderForm(req)).toBe(true);
  });

  it('asks for an indexer URL instead of sending verifiable RPC reads to the API', async () => {
    const client = vectorClient();
    await expect(client.verifiableRpc.get('sg', 'k')).rejects.toMatchObject({
      code: 'INDEXER_URL_REQUIRED',
    });
    await expect(client.eth.getState(`0x${'11'.repeat(20)}`, [], 1)).rejects.toBeInstanceOf(
      WillowError,
    );
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("reads the key id from the API's snake_case DID document in init()", async () => {
    mockFetch.mockImplementation(async () =>
      jsonResponse({
        success: true,
        data: {
          id: DID,
          public_keys: [{ id: KEY_ID, type: 'EcdsaSecp256k1VerificationKey2019' }],
          authentication: [KEY_ID],
        },
      }),
    );
    const client = new WillowClient({ apiUrl: 'http://api.test', did: DID, privateKey: SEED });
    await client.init();
    expect(client.auth.getPublicKeyId()).toBe(KEY_ID);
    const headers = client.auth.signRequestWithNonce('POST', '/query/sg?x=1', '{}', FIXED);
    expect(headers['X-Signature']).toBe(`0x${SECP256K1_COMPACT}`);
  });
});

describe('DID documents publish secp256k1 keys compressed', () => {
  const uncompressed = bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), false));

  it('from a wallet', () => {
    const wallet = new ethers.Wallet(`0x${SEED}`);
    // signingKey.publicKey is the 65-byte uncompressed form.
    const doc = createDidFromWallet({ address: wallet.address, publicKey: wallet.signingKey.publicKey });
    expect(doc.publicKeys[0].publicKeyHex).toBe(SECP256K1_PUBLIC_KEY);
  });

  it('from a public key in any encoding, with the same id', () => {
    const ids = new Set<string>();
    for (const key of [SECP256K1_PUBLIC_KEY, uncompressed, `0x${uncompressed}`, uncompressed.slice(2)]) {
      const doc = createDidFromPublicKey(key, 'secp256k1');
      expect(doc.publicKeys[0].publicKeyHex).toBe(SECP256K1_PUBLIC_KEY);
      ids.add(doc.id);
    }
    expect(ids.size).toBe(1);
  });

  it('leaves Ed25519 keys as given', () => {
    expect(createDidFromPublicKey(ED25519_PUBLIC_KEY).publicKeys[0].publicKeyHex).toBe(ED25519_PUBLIC_KEY);
  });
});
