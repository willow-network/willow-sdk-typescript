import { WillowClient } from '../src/client';
import { generateEd25519KeyPair, getEd25519PublicKey } from '../src/auth';

// Mock fetch (used by getRootHash / getRootHashLocal)
global.fetch = jest.fn();

// Mock axios (used by auth and data operations)
jest.mock('axios', () => {
  const mockAxiosInstance = {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
  };
  return {
    __esModule: true,
    default: {
      create: jest.fn(() => mockAxiosInstance),
    },
    _mockInstance: mockAxiosInstance,
  };
});

// Get the mock axios instance
function getMockAxios() {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return require('axios')._mockInstance;
}

describe('WillowClient', () => {
  let client: WillowClient;
  const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

  // Test keys
  const { privateKey: testPrivateKey, publicKey: testPublicKey } = generateEd25519KeyPair();
  const testDid = 'did:willow:test:123';
  const testPublicKeyId = `${testDid}#key-1`;

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

      const mockAxios = getMockAxios();
      mockAxios.post.mockResolvedValueOnce({
        data: { success: true, data: didDoc },
      });

      const result = await client.registerDid(didDoc);
      expect(result).toEqual(didDoc);
      expect(mockAxios.post).toHaveBeenCalledWith(
        '/did',
        didDoc,
      );
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
        const mockAxios = getMockAxios();
        mockAxios.post.mockResolvedValueOnce({
          data: { success: true },
        });

        await client.data.storeData('dataset1', {
          key1: { value: 'test' },
        });

        expect(mockAxios.post).toHaveBeenCalledWith(
          '/data/dataset1',
          { key1: { value: 'test' } },
          expect.objectContaining({
            headers: expect.objectContaining({
              'X-DID': testDid,
              'X-Public-Key-ID': testPublicKeyId,
              'X-Signature': expect.any(String),
              'X-Timestamp': expect.any(String),
            }),
          })
        );
      });
    });

    describe('update', () => {
      it('should update data with auth headers', async () => {
        const mockAxios = getMockAxios();
        mockAxios.put.mockResolvedValueOnce({
          data: { success: true },
        });

        await client.data.updateData('dataset1', 'key1', { value: 'updated' });

        expect(mockAxios.put).toHaveBeenCalledWith(
          '/data/dataset1/key1',
          { value: 'updated' },
          expect.objectContaining({
            headers: expect.objectContaining({
              'X-DID': testDid,
              'X-Public-Key-ID': testPublicKeyId,
              'X-Signature': expect.any(String),
              'X-Timestamp': expect.any(String),
            }),
          })
        );
      });
    });

    describe('delete', () => {
      it('should delete data with auth headers', async () => {
        const mockAxios = getMockAxios();
        mockAxios.delete.mockResolvedValueOnce({
          data: { success: true },
        });

        await client.data.deleteData('dataset1', 'key1');

        expect(mockAxios.delete).toHaveBeenCalledWith(
          '/data/dataset1/key1',
          expect.objectContaining({
            headers: expect.objectContaining({
              'X-DID': testDid,
              'X-Public-Key-ID': testPublicKeyId,
              'X-Signature': expect.any(String),
              'X-Timestamp': expect.any(String),
            }),
          })
        );
      });
    });
  });

  describe('registration operations', () => {
    beforeEach(() => {
      client.auth.setIdentity(testDid, testPrivateKey, testPublicKeyId);
    });

    it('should register a subgrove with auth headers', async () => {
      const appRequest = {

        name: 'Test App',
        description: 'Test description',

        owner_did: testDid,
        admins: [],
      };

      const mockAxios = getMockAxios();
      mockAxios.post.mockResolvedValueOnce({
        data: { success: true, data: appRequest },
      });

      const result = await client.data.registerDataset(appRequest);
      expect(result).toEqual(appRequest);
      expect(mockAxios.post).toHaveBeenCalledWith(
        '/register/subgrove',
        appRequest,
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-DID': testDid,
          }),
        })
      );
    });

    it('should register a dataset with auth headers', async () => {
      const datasetRequest = {
        dataset_id: 'test-dataset',

        name: 'Test Dataset',
        dataset_path: ['collections'],
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

      const mockAxios = getMockAxios();
      mockAxios.post.mockResolvedValueOnce({
        data: { success: true, data: datasetRequest },
      });

      const result = await client.data.registerDataset(datasetRequest);
      expect(result).toEqual(datasetRequest);
    });
  });

  describe('root hash operations', () => {
    it('should get verified root hash from blockchain', async () => {
      const rootHash = '0x1234567890abcdef';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: { root_hash: rootHash }
        }),
      } as Response);

      const result = await client.getRootHash();
      expect(result).toBe(rootHash);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3031/state/root-hash/verified',
      );
    });

    it('should get local root hash from node state', async () => {
      const rootHash = '0xabcdef1234567890';
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: { root_hash: rootHash }
        }),
      } as Response);

      const result = await client.getRootHashLocal();
      expect(result).toBe(rootHash);
      expect(mockFetch).toHaveBeenCalledWith(
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
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: {} }),
      } as Response);

      await expect(client.getRootHash()).rejects.toThrow(
        'No root hash in response'
      );
    });

    it('should handle unsuccessful response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: false, error: 'Some error' }),
      } as Response);

      await expect(client.getRootHash()).rejects.toThrow(
        'No root hash in response'
      );
    });
  });
});
