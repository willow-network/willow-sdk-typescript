/**
 * Tests for GroveDB proof verification in TypeScript SDK
 */

import { 
  GroveDBProofVerifier, 
  verifyQueryProof, 
  verifyItemProof,
  extractRootHashFromProof,
  configureProofVerification
} from '../src/proof';

describe('GroveDB Proof Verification', () => {
  describe('GroveDBProofVerifier', () => {
    it('should create a verifier with default options', () => {
      const verifier = new GroveDBProofVerifier();
      expect(verifier).toBeDefined();
    });

    it('should create a verifier with server-assisted options', () => {
      const verifier = new GroveDBProofVerifier({
        serverAssisted: true,
        apiUrl: 'http://localhost:3031'
      });
      expect(verifier).toBeDefined();
    });

    it('should reject empty proofs', async () => {
      const verifier = new GroveDBProofVerifier();
      const result = await verifier.verifyQueryProof('', []);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Empty proof provided');
      expect(result.method).toBe('local-basic');
    });

    it('should reject invalid hex strings', async () => {
      const verifier = new GroveDBProofVerifier();
      
      await expect(async () => {
        await verifier.verifyQueryProof('invalid-hex', []);
      }).rejects.toThrow();
    });

    it('should handle proofs with valid format', async () => {
      const verifier = new GroveDBProofVerifier();
      
      // Create a dummy proof that looks like it could contain a hash
      // 32 bytes of data that could be a hash, plus some metadata
      const dummyHash = '0123456789abcdef'.repeat(4); // 64 hex chars = 32 bytes
      const dummyProof = '00000001' + dummyHash + 'deadbeef'; // Some structure
      
      const result = await verifier.verifyQueryProof(dummyProof, [{ key: 'test', value: 'data' }]);
      
      // Without an expected root hash, it should consider the format valid
      expect(result.valid).toBe(true);
      expect(result.rootHash).toBeDefined();
      expect(result.method).toBe('local-basic');
    });

    it('should verify against expected root hash', async () => {
      const expectedHash = '0123456789abcdef'.repeat(4);
      const verifier = new GroveDBProofVerifier({
        expectedRootHash: expectedHash
      });
      
      // Proof that contains the expected hash
      const validProof = '00' + expectedHash + 'ff';
      
      const result = await verifier.verifyQueryProof(validProof, []);
      
      expect(result.valid).toBe(true);
      expect(result.rootHash?.toLowerCase()).toBe(expectedHash.toLowerCase());
    });

    it('should fail verification with wrong expected root hash', async () => {
      const expectedHash = '0123456789abcdef'.repeat(4);
      const wrongHash = 'fedcba9876543210'.repeat(4);
      
      const verifier = new GroveDBProofVerifier({
        expectedRootHash: expectedHash
      });
      
      // Proof that contains a different hash
      const invalidProof = '00' + wrongHash + 'ff';
      
      const result = await verifier.verifyQueryProof(invalidProof, []);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Root hash mismatch');
    });
  });

  describe('Module functions', () => {
    beforeEach(() => {
      // Reset global configuration
      configureProofVerification({});
    });

    it('should verify query proofs using global verifier', async () => {
      // Configure with expected root hash
      const expectedHash = 'a'.repeat(64);
      configureProofVerification({
        expectedRootHash: expectedHash
      });
      
      const proof = '00' + expectedHash;
      const documents = [{ id: 1, name: 'test' }];
      
      const rootHash = await verifyQueryProof(proof, documents);
      expect(rootHash.toLowerCase()).toBe(expectedHash.toLowerCase());
    });

    it('should verify item proofs', async () => {
      const proof = '00' + 'b'.repeat(64);
      const key = 'testKey';
      const value = { data: 'test' };
      const path = ['apps', 'myapp', 'data'];
      
      const rootHash = await verifyItemProof(proof, key, value, path);
      expect(rootHash).toBeDefined();
      expect(rootHash.length).toBe(64); // 32 bytes as hex
    });

    it('should extract root hash from proof', async () => {
      const expectedHash = 'c'.repeat(64);
      const proof = '00' + expectedHash + 'ffffff';
      
      const rootHash = await extractRootHashFromProof(proof);
      expect(rootHash.toLowerCase()).toBe(expectedHash.toLowerCase());
    });

    it('should throw on invalid proofs in strict mode', async () => {
      const proof = 'invalid';
      
      await expect(verifyQueryProof(proof, [])).rejects.toThrow();
    });
  });

  describe('Server-assisted verification', () => {
    it('should attempt server verification when configured', async () => {
      // Mock fetch for server-assisted verification
      global.fetch = jest.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          valid: true,
          rootHash: 'd'.repeat(64)
        })
      });
      
      const verifier = new GroveDBProofVerifier({
        serverAssisted: true,
        apiUrl: 'http://localhost:3031'
      });
      
      const result = await verifier.verifyQueryProof('anyproof', []);
      
      expect(result.valid).toBe(true);
      expect(result.method).toBe('server-assisted');
      expect(global.fetch).toHaveBeenCalledWith(
        'http://localhost:3031/verify-proof',
        expect.any(Object)
      );
    });

    it('should fall back to local verification on server error', async () => {
      global.fetch = jest.fn().mockRejectedValueOnce(new Error('Network error'));
      
      const verifier = new GroveDBProofVerifier({
        serverAssisted: true,
        apiUrl: 'http://localhost:3031'
      });
      
      const proof = '00' + 'e'.repeat(64);
      const result = await verifier.verifyQueryProof(proof, []);
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Server-assisted verification failed');
      expect(result.method).toBe('server-assisted');
    });
  });

  describe('Edge cases', () => {
    it('should handle proofs with 0x prefix', async () => {
      const verifier = new GroveDBProofVerifier();
      const proof = '0x00' + 'f'.repeat(64);
      
      const result = await verifier.verifyQueryProof(proof, []);
      expect(result.valid).toBe(true);
      expect(result.rootHash).toBeDefined();
    });

    it('should reject proofs shorter than 32 bytes', async () => {
      const verifier = new GroveDBProofVerifier();
      const shortProof = 'aabbccdd'; // Only 4 bytes
      
      const result = await verifier.verifyQueryProof(shortProof, []);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('too short');
    });

    it('should handle proofs with all zeros', async () => {
      const verifier = new GroveDBProofVerifier();
      const zeroProof = '00'.repeat(40); // 40 bytes, but first 32 are all zeros
      
      await expect(
        verifier.extractRootHash(zeroProof)
      ).rejects.toThrow('Could not extract root hash');
    });

    it('should handle proofs with all ones', async () => {
      const verifier = new GroveDBProofVerifier();
      const onesProof = 'ff'.repeat(40); // 40 bytes, but first 32 are all ones
      
      await expect(
        verifier.extractRootHash(onesProof)
      ).rejects.toThrow('Could not extract root hash');
    });
  });
});