import { WillowClient } from '../src/client';
import { generateEd25519KeyPair, verifyEd25519 } from '../src/auth';
import { createDidFromPublicKey } from '../src/utils';
import { bytesToHex } from '../src/internal/bytes';

// Mock fetch — every SDK HTTP call (auth, data, root hash) goes through it.
global.fetch = jest.fn();

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  } as Response;
}

describe('WillowClient', () => {
  let client: WillowClient;
  const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

  // Test keys
  const { privateKey: testPrivateKey, publicKey: testPublicKey } = generateEd25519KeyPair();
  // A Willow DID as the chain takes one (no ':' after the method).
  const testDid = 'did:willow:test-123';
  const testPublicKeyId = `${testDid}#key-1`;

  function lastRequest(): { url: string; init: RequestInit } {
    const call = mockFetch.mock.calls.at(-1)!;
    return { url: call[0] as string, init: call[1] as RequestInit };
  }

  beforeEach(() => {
    client = new WillowClient({ apiUrl: 'http://localhost:3031' });
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should initialize with config', () => {
      const customClient = new WillowClient({ apiUrl: 'http://custom.api' });
      expect(customClient).toBeDefined();
    });

    it('should expose auth and data modules', () => {
      expect(client.auth).toBeDefined();
      expect(client.data).toBeDefined();
    });
  });

  describe('registerDid', () => {
    it('sends a RegisterDid transaction signed by the new DID, not a REST call', async () => {
      const didDoc = { ...createDidFromPublicKey(testPublicKey), created: 1, updated: 2 };
      const keyId = didDoc.publicKeys[0].id;
      client.auth.setIdentity(didDoc.id, testPrivateKey, keyId);
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ success: true, data: { tx_hash: 'AB12', code: 0, log: '' } }),
      );

      const result = await client.registerDid(didDoc);
      expect(result.success).toBe(true);
      expect(result.txHash).toBe('AB12');

      // One request: a registration is the DID's first transaction, at nonce 1.
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const { url, init } = lastRequest();
      expect(url).toBe('http://localhost:3031/tx/submit');
      expect(init.method).toBe('POST');
      const tx = JSON.parse(init.body as string).RegisterDid;
      expect(tx.nonce).toBe(1);
      expect(tx.public_key_id).toBe(keyId);
      expect(tx.did_document).toEqual({
        id: didDoc.id,
        public_keys: [
          {
            id: keyId,
            type: 'Ed25519VerificationKey2018',
            controller: didDoc.id,
            public_key_base58: null,
            public_key_hex: testPublicKey,
          },
        ],
        authentication: [keyId],
        service: [],
        created: 1,
        updated: 2,
        proof: null,
      });
      // Signed over the document's JSON text as the chain writes it.
      expect(
        verifyEd25519(
          JSON.stringify(tx.did_document),
          bytesToHex(Uint8Array.from(tx.signature)),
          testPublicKey,
        ),
      ).toBe(true);
    });

    it('refuses to register a DID other than the identity', async () => {
      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);
      const didDoc = createDidFromPublicKey(testPublicKey);
      await expect(client.registerDid(didDoc)).rejects.toMatchObject({
        code: 'IDENTITY_MISMATCH',
      });
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('auth.registerDid names the transaction path instead of calling a missing route', async () => {
      await expect(
        client.auth.registerDid(createDidFromPublicKey(testPublicKey)),
      ).rejects.toMatchObject({ code: 'UNSUPPORTED_OPERATION' });
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe('identity management', () => {
    it('should set identity for per-request signing', () => {
      expect(client.auth.hasIdentity()).toBe(false);

      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);

      expect(client.auth.hasIdentity()).toBe(true);
      expect(client.auth.getDid()).toBe(testDid);
    });

    it('should generate auth headers when identity is set', () => {
      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);

      const headers = client.auth.getAuthHeaders('GET', '/data/dataset1/key1');

      expect(headers['X-DID']).toBe(testDid);
      expect(headers['X-Public-Key-ID']).toBe(testPublicKeyId);
      expect(headers['X-Signature']).toBeDefined();
      expect(headers['X-Timestamp']).toBeDefined();
    });

    it('should return empty headers when no identity is set', () => {
      const headers = client.auth.getAuthHeaders('GET', '/data/dataset1/key1');
      expect(headers).toEqual({});
    });

    it('should throw when signing without identity', () => {
      expect(() => client.auth.signRequest('GET', '/data/dataset1/key1'))
        .toThrow('Identity not set');
    });
  });

  describe('data operations', () => {
    beforeEach(() => {
      // Set up authenticated client using per-request signing
      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);
    });

    // The API serves no data writes; each is a transaction. These name the
    // supported path and send nothing.
    it.each([
      ['data.storeData', (c: WillowClient) => c.data.storeData('dataset1', { key1: 1 })],
      [
        'data.batchStore',
        (c: WillowClient) => c.data.batchStore('dataset1', [{ key: 'key1', value: 1 }]),
      ],
      ['data.updateData', (c: WillowClient) => c.data.updateData('dataset1', 'key1', {})],
      ['data.deleteData', (c: WillowClient) => c.data.deleteData('dataset1', 'key1')],
      ['update', (c: WillowClient) => c.update('dataset1', 'key1', {})],
      ['delete', (c: WillowClient) => c.delete('dataset1', 'key1')],
      [
        'collection().batchStore',
        (c: WillowClient) => c.collection('dataset1').batchStore([{ key: 'k', value: 1 }]),
      ],
    ])('%s throws UNSUPPORTED_OPERATION without a request', async (_name, call) => {
      const err = await call(client).catch((e: unknown) => e);
      expect(err).toMatchObject({ code: 'UNSUPPORTED_OPERATION' });
      expect((err as Error).message).toMatch(/transaction/);
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('data.storeData names the per-key path', async () => {
      await expect(client.data.storeData('dataset1', { key1: 1 })).rejects.toThrow(
        /WillowClient\.store\(subgroveId, key, value\)/,
      );
    });
  });

  describe('registration operations', () => {
    beforeEach(() => {
      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);
    });

    it('should register a dataset with auth headers', async () => {
      const datasetRequest = {
        dataset_id: 'test-dataset',
        name: 'Test Dataset',
        schema: {
          version: 1,
          fields: { name: { type: 'string' as const } },
          indexes: [],
          required_fields: ['name'],
        },
        owner_did: testDid,
        writers: [testDid],
        readers: [testDid],
      };

      mockFetch
        // The devnet's CometBFT RPC answers the account's nonce state: base 4,
        // none used above it.
        .mockResolvedValueOnce(
          jsonResponse({ result: { response: { code: 0, value: 'AAAAAAAAAAQAAAA=' } } }),
        )
        .mockResolvedValueOnce(
          jsonResponse({ success: true, data: { tx_hash: 'CD34', code: 0, log: '' } }),
        );

      const result = await client.data.registerDataset(datasetRequest);
      expect(result.success).toBe(true);
      expect(result.txHash).toBe('CD34');
      const query = JSON.parse(mockFetch.mock.calls[0][1]!.body as string);
      expect(mockFetch.mock.calls[0][0]).toBe('http://localhost:26657');
      expect(query.method).toBe('abci_query');
      expect(query.params.path).toBe(`/store/account_nonce_state/${testDid}`);

      // Sent as a RegisterSubgrove transaction; the API has no REST route.
      const { url, init } = lastRequest();
      expect(url).toBe('http://localhost:3031/tx/submit');
      const tx = JSON.parse(init.body as string).RegisterSubgrove;
      expect(tx.subgrove_id).toBe('test-dataset');
      expect(tx.owner_did).toBe(testDid);
      expect(tx.nonce).toBe(5);
      expect(tx.mode).toEqual({
        DataStorage: {
          name: 'Test Dataset',
          writers: [testDid],
          free_readers: [testDid],
          read_pricing: null,
        },
      });
    });
  });

  describe('root hash operations', () => {
    it('should get verified root hash from blockchain', async () => {
      const rootHash = '0x1234567890abcdef';
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ success: true, data: { root_hash: rootHash } }),
      );

      const result = await client.getRootHash();
      expect(result).toBe(rootHash);
      expect(mockFetch.mock.calls.at(-1)?.[0]).toBe(
        'http://localhost:3031/state/root-hash/verified',
      );
    });

    it('should get local root hash from node state', async () => {
      const rootHash = '0xabcdef1234567890';
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ success: true, data: { root_hash: rootHash } }),
      );

      const result = await client.getRootHashLocal();
      expect(result).toBe(rootHash);
      expect(mockFetch.mock.calls.at(-1)?.[0]).toBe(
        'http://localhost:3031/state/root-hash',
      );
    });

    it('should handle error when getting verified root hash', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      } as Response);

      await expect(client.getRootHash()).rejects.toThrow(
        'Failed to get verified root hash: Internal Server Error'
      );
    });

    it('should handle error when getting local root hash', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      } as Response);

      await expect(client.getRootHashLocal()).rejects.toThrow(
        'Failed to get local root hash: Internal Server Error'
      );
    });

    it('should handle missing root hash in response', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data: {} }));

      await expect(client.getRootHash()).rejects.toThrow(
        'No root hash in response'
      );
    });

    it('should handle unsuccessful response', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ success: false, error: 'Some error' }));

      await expect(client.getRootHash()).rejects.toThrow(
        'No root hash in response'
      );
    });
  });
});
