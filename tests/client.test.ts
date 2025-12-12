import { WillowClient } from '../src/client';
import { WillowError } from '../src/errors';

// Mock fetch
global.fetch = jest.fn();

describe('WillowClient', () => {
  let client: WillowClient;
  const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

  beforeEach(() => {
    client = new WillowClient({ apiUrl: 'http://localhost:3031' });
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    it('should initialize with default config', () => {
      const defaultClient = new WillowClient();
      expect(defaultClient).toBeDefined();
    });

    it('should accept custom API URL', () => {
      const customClient = new WillowClient({ apiUrl: 'http://custom.api' });
      expect(customClient).toBeDefined();
    });
  });

  describe('registerDid', () => {
    it('should register a DID document', async () => {
      const didDoc = {
        id: 'did:willow:test:123',
        public_keys: [{
          id: 'did:willow:test:123#key-1',
          key_type: 'Ed25519VerificationKey2020',
          public_key_hex: 'abcdef123456',
        }],
        created: Date.now(),
        updated: Date.now(),
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({ success: true, data: didDoc }),
      } as Response);

      const result = await client.registerDid(didDoc);
      expect(result).toEqual(didDoc);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3031/did',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(didDoc),
        })
      );
    });

    it('should handle registration errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({ success: false, error: 'Invalid DID format' }),
      } as Response);

      await expect(client.registerDid({} as any)).rejects.toThrow(WillowError);
    });
  });

  describe('authenticate', () => {
    const did = 'did:willow:test:123';
    const privateKeyHex = 'a'.repeat(64);
    const publicKeyId = `${did}#key-1`;

    it('should complete authentication flow', async () => {
      // Mock challenge response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: {
            challenge: 'test-challenge',
            timestamp: Date.now(),
          },
        }),
      } as Response);

      // Mock verify response
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          success: true,
          data: {
            did,
            token: 'session-token',
            expires_at: Date.now() + 3600000,
          },
        }),
      } as Response);

      const session = await client.authenticate(did, privateKeyHex, publicKeyId);
      expect(session.token).toBe('session-token');
      expect(session.did).toBe(did);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it('should handle authentication failures', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ success: false, error: 'Invalid signature' }),
      } as Response);

      await expect(client.authenticate(did, privateKeyHex, publicKeyId))
        .rejects.toThrow(WillowError);
    });
  });

  describe('data operations', () => {
    beforeEach(() => {
      // Set up authenticated client
      client['session'] = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() + 3600000,
      };
    });

    describe('store', () => {
      it('should store data successfully', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        } as Response);

        await client.data.store('app1', 'dataset1', {
          key1: { value: 'test' },
        });

        expect(mockFetch).toHaveBeenCalledWith(
          'http://localhost:3031/data/app1/dataset1?did=did:willow:test:123&session=test-token',
          expect.objectContaining({
            method: 'POST',
            body: JSON.stringify({ key1: { value: 'test' } }),
          })
        );
      });

      it('should require authentication', async () => {
        client['session'] = null;
        await expect(client.data.store('app1', 'dataset1', {}))
          .rejects.toThrow('Not authenticated');
      });
    });

    describe('get', () => {
      it('should retrieve data', async () => {
        const testData = { value: 'test' };
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true, data: testData }),
        } as Response);

        const result = await client.data.get('app1', 'dataset1', 'key1');
        expect(result).toEqual(testData);
      });

      it('should handle not found', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: false,
          status: 404,
          json: async () => ({ success: false, error: 'Not found' }),
        } as Response);

        await expect(client.data.get('app1', 'dataset1', 'key1'))
          .rejects.toThrow(WillowError);
      });
    });

    describe('update', () => {
      it('should update data', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        } as Response);

        await client.data.update('app1', 'dataset1', 'key1', { value: 'updated' });

        expect(mockFetch).toHaveBeenCalledWith(
          'http://localhost:3031/data/app1/dataset1/key1?did=did:willow:test:123&session=test-token',
          expect.objectContaining({
            method: 'PUT',
            body: JSON.stringify({ value: 'updated' }),
          })
        );
      });
    });

    describe('delete', () => {
      it('should delete data', async () => {
        mockFetch.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        } as Response);

        await client.data.delete('app1', 'dataset1', 'key1');

        expect(mockFetch).toHaveBeenCalledWith(
          'http://localhost:3031/data/app1/dataset1/key1?did=did:willow:test:123&session=test-token',
          expect.objectContaining({
            method: 'DELETE',
          })
        );
      });
    });
  });

  describe('registration operations', () => {
    beforeEach(() => {
      client['session'] = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() + 3600000,
      };
    });

    it('should register an app', async () => {
      const appRequest = {
        app_id: 'test-app',
        name: 'Test App',
        description: 'Test description',
        app_type: 'test',
        owner_did: 'did:willow:test:123',
        admins: [],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: appRequest }),
      } as Response);

      const result = await client.registration.registerApp(appRequest);
      expect(result).toEqual(appRequest);
    });

    it('should register a dataset', async () => {
      const datasetRequest = {
        dataset_id: 'test-dataset',
        app_id: 'test-app',
        name: 'Test Dataset',
        dataset_path: ['collections'],
        schema: {
          version: 1,
          fields: { name: { type: 'string' } },
          indexes: [],
          required_fields: ['name'],
        },
        owner_did: 'did:willow:test:123',
        writers: ['did:willow:test:123'],
        readers: ['did:willow:test:123'],
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: datasetRequest }),
      } as Response);

      const result = await client.registration.registerDataset(datasetRequest);
      expect(result).toEqual(datasetRequest);
    });
  });

  describe('proof operations', () => {
    it('should get proof without authentication', async () => {
      const proofData = {
        proof: 'abc123def456',
        value: { test: 'data' },
      };

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true, data: proofData }),
      } as Response);

      const result = await client.proof.get('app1', 'dataset1', 'key1');
      expect(result).toEqual(proofData);
      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:3031/proof/app1/dataset1/key1',
        expect.objectContaining({
          method: 'GET',
        })
      );
    });
  });

  describe('session management', () => {
    it('should check if authenticated', () => {
      expect(client.isAuthenticated()).toBe(false);

      client['session'] = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() + 3600000,
      };

      expect(client.isAuthenticated()).toBe(true);
    });

    it('should handle expired sessions', () => {
      client['session'] = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() - 1000, // Expired
      };

      expect(client.isAuthenticated()).toBe(false);
    });

    it('should get current session', () => {
      expect(client.getSession()).toBeNull();

      const session = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() + 3600000,
      };
      client['session'] = session;

      expect(client.getSession()).toEqual(session);
    });

    it('should clear session', () => {
      client['session'] = {
        did: 'did:willow:test:123',
        token: 'test-token',
        expires_at: Date.now() + 3600000,
      };

      client.clearSession();
      expect(client.getSession()).toBeNull();
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
        undefined
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
        undefined
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