import { WillowClient } from '../src/client';
import { generateEd25519KeyPair, getEd25519PublicKey } from '../src/auth';

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
  const testDid = 'did:willow:test:123';
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
    it('should register a DID document', async () => {
      const didDoc = {
        id: testDid,
        publicKeys: [{
          id: testPublicKeyId,
          type: 'Ed25519VerificationKey2020',
          publicKeyHex: testPublicKey,
        }],
        created: Date.now(),
        updated: Date.now(),
      };

      mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data: didDoc }));

      const result = await client.registerDid(didDoc);
      expect(result).toEqual(didDoc);

      const { url, init } = lastRequest();
      expect(url).toBe('http://localhost:3031/did');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body as string)).toEqual(didDoc);
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

    describe('store', () => {
      it('should store data with auth headers', async () => {
        mockFetch.mockResolvedValueOnce(jsonResponse({ success: true }));

        await client.data.storeData('dataset1', {
          key1: { value: 'test' },
        });

        const { url, init } = lastRequest();
        expect(url).toBe('http://localhost:3031/data/dataset1');
        expect(init.method).toBe('POST');
        expect(JSON.parse(init.body as string)).toEqual({ key1: { value: 'test' } });
        expect(init.headers).toMatchObject({
          'X-DID': testDid,
          'X-Public-Key-ID': testPublicKeyId,
          'X-Signature': expect.any(String),
          'X-Timestamp': expect.any(String),
        });
      });
    });

    describe('update', () => {
      it('should update data with auth headers', async () => {
        mockFetch.mockResolvedValueOnce(jsonResponse({ success: true }));

        await client.data.updateData('dataset1', 'key1', { value: 'updated' });

        const { url, init } = lastRequest();
        expect(url).toBe('http://localhost:3031/data/dataset1/key1');
        expect(init.method).toBe('PUT');
        expect(JSON.parse(init.body as string)).toEqual({ value: 'updated' });
        expect(init.headers).toMatchObject({
          'X-DID': testDid,
          'X-Public-Key-ID': testPublicKeyId,
          'X-Signature': expect.any(String),
          'X-Timestamp': expect.any(String),
        });
      });
    });

    describe('delete', () => {
      it('should delete data with auth headers', async () => {
        mockFetch.mockResolvedValueOnce(jsonResponse({ success: true }));

        await client.data.deleteData('dataset1', 'key1');

        const { url, init } = lastRequest();
        expect(url).toBe('http://localhost:3031/data/dataset1/key1');
        expect(init.method).toBe('DELETE');
        expect(init.headers).toMatchObject({
          'X-DID': testDid,
          'X-Public-Key-ID': testPublicKeyId,
          'X-Signature': expect.any(String),
          'X-Timestamp': expect.any(String),
        });
      });
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

      mockFetch.mockResolvedValueOnce(jsonResponse({ success: true, data: datasetRequest }));

      const result = await client.data.registerDataset(datasetRequest);
      expect(result).toEqual(datasetRequest);
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
