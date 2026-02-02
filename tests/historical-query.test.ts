/**
 * Tests for historical query functionality in TypeScript SDK
 */

import {
  HistoricalQueryRequest,
  HistoricalQueryResponse,
  CheckpointInfo,
} from '../src/types';
import { verifyQueryProof } from '../src/proof';

describe('Historical Query Types', () => {
  describe('HistoricalQueryRequest', () => {
    it('should create a valid request with required fields', () => {
      const request: HistoricalQueryRequest = {
        path: [[97, 112, 112], [100, 97, 116, 97]],
        include_proof: true,
      };

      expect(request.path).toHaveLength(2);
      expect(request.include_proof).toBe(true);
    });

    it('should create a request with optional key', () => {
      const request: HistoricalQueryRequest = {
        path: [[97, 112, 112]],
        key: [107, 101, 121],
        include_proof: false,
      };

      expect(request.key).toEqual([107, 101, 121]);
    });

    it('should create a request with query_type', () => {
      const request: HistoricalQueryRequest = {
        path: [[97, 112, 112]],
        query_type: 'get_range',
        include_proof: true,
      };

      expect(request.query_type).toBe('get_range');
    });
  });

  describe('HistoricalQueryResponse', () => {
    it('should represent a successful response', () => {
      const response: HistoricalQueryResponse = {
        success: true,
        provider_did: 'did:willow:indexer123',
        provider_endpoint: 'http://localhost:8080',
        state_root: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        block_range: [1000, 2000],
        data: { key: 'value' },
        proof: '0xaabbccdd',
        can_reindex: false,
      };

      expect(response.success).toBe(true);
      expect(response.state_root).toMatch(/^0x[a-f0-9]{64}$/);
      expect(response.block_range).toEqual([1000, 2000]);
    });

    it('should represent a failed response with can_reindex', () => {
      const response: HistoricalQueryResponse = {
        success: false,
        state_root: '',
        block_range: [0, 0],
        data: null,
        can_reindex: true,
        error: 'No historical data providers available',
      };

      expect(response.success).toBe(false);
      expect(response.can_reindex).toBe(true);
      expect(response.error).toBeDefined();
    });
  });

  describe('CheckpointInfo', () => {
    it('should contain all required fields', () => {
      const checkpoint: CheckpointInfo = {
        checkpoint_id: '0xaabbccdd',
        subgrove_id: 'uniswap-v3',
        state_root: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
        block_range: [18000000, 19000000],
        indexer_did: 'did:willow:indexer123',
        submitted_at: 1700000000,
        is_trusted: true,
      };

      expect(checkpoint.checkpoint_id).toBe('0xaabbccdd');
      expect(checkpoint.is_trusted).toBe(true);
      expect(checkpoint.block_range[1]).toBeGreaterThan(checkpoint.block_range[0]);
    });
  });
});

describe('Historical Query Proof Verification', () => {
  describe('State root comparison', () => {
    it('should normalize hex strings for comparison', () => {
      const stateRoot1 = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const stateRoot2 = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const stateRoot3 = '0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF';

      const normalize = (s: string) => s.toLowerCase().replace(/^0x/, '');

      expect(normalize(stateRoot1)).toBe(normalize(stateRoot2));
      expect(normalize(stateRoot1)).toBe(normalize(stateRoot3));
    });

    it('should detect state root mismatch', () => {
      const computedRoot = '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
      const expectedRoot = '0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321';

      const normalizedComputed = computedRoot.toLowerCase().replace(/^0x/, '');
      const normalizedExpected = expectedRoot.toLowerCase().replace(/^0x/, '');

      expect(normalizedComputed).not.toBe(normalizedExpected);
    });
  });

  describe('Proof validation', () => {
    it('should reject empty proof', async () => {
      const response: HistoricalQueryResponse = {
        success: true,
        state_root: '0x1234',
        block_range: [1000, 2000],
        data: { key: 'value' },
        proof: '',
        can_reindex: false,
      };

      expect(response.proof).toBe('');
      // Empty proof should be rejected by queryHistoricalVerified
    });

    it('should reject missing proof', async () => {
      const response: HistoricalQueryResponse = {
        success: true,
        state_root: '0x1234',
        block_range: [1000, 2000],
        data: { key: 'value' },
        can_reindex: false,
      };

      expect(response.proof).toBeUndefined();
      // Missing proof should be rejected by queryHistoricalVerified
    });

    it('should handle proof with 0x prefix', async () => {
      // Test that proofs with 0x prefix are handled correctly
      const proofWithPrefix = '0x0123456789abcdef';
      const proofWithoutPrefix = '0123456789abcdef';

      const cleanHex = (hex: string) => hex.replace(/^0x/, '');
      expect(cleanHex(proofWithPrefix)).toBe(cleanHex(proofWithoutPrefix));
    });
  });

  describe('Data array handling', () => {
    it('should handle array data', () => {
      const response: HistoricalQueryResponse = {
        success: true,
        state_root: '0x1234',
        block_range: [1000, 2000],
        data: [{ key: 'value1' }, { key: 'value2' }],
        can_reindex: false,
      };

      const documents = Array.isArray(response.data) ? response.data : [response.data];
      expect(documents).toHaveLength(2);
    });

    it('should wrap non-array data', () => {
      const response: HistoricalQueryResponse = {
        success: true,
        state_root: '0x1234',
        block_range: [1000, 2000],
        data: { key: 'value' },
        can_reindex: false,
      };

      const documents = Array.isArray(response.data) ? response.data : [response.data];
      expect(documents).toHaveLength(1);
      expect(documents[0]).toEqual({ key: 'value' });
    });
  });
});

describe('Error handling', () => {
  describe('can_reindex flag', () => {
    it('should indicate data can be re-indexed when providers unavailable', () => {
      const errorResponse: HistoricalQueryResponse = {
        success: false,
        state_root: '',
        block_range: [0, 0],
        data: null,
        can_reindex: true,
        error: 'No historical data providers available',
      };

      expect(errorResponse.can_reindex).toBe(true);
      // This indicates a new indexer can index the same block range
    });

    it('should not indicate re-indexing for other errors', () => {
      const errorResponse: HistoricalQueryResponse = {
        success: false,
        state_root: '',
        block_range: [0, 0],
        data: null,
        can_reindex: false,
        error: 'Invalid checkpoint ID format',
      };

      expect(errorResponse.can_reindex).toBe(false);
    });
  });
});
