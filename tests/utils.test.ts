import { generateId, sleep, retry, parseApiError } from '../src/utils';
import { WillowError } from '../src/errors';

describe('Utils', () => {
  describe('generateId', () => {
    it('should generate unique IDs', () => {
      const id1 = generateId();
      const id2 = generateId();
      expect(id1).not.toBe(id2);
    });

    it('should include prefix if provided', () => {
      const id = generateId('test');
      expect(id).toMatch(/^test_/);
    });

    it('should generate IDs without prefix', () => {
      const id = generateId();
      expect(id).toMatch(/^[a-f0-9]+$/);
    });

    it('should generate consistent length IDs', () => {
      const ids = Array.from({ length: 10 }, () => generateId());
      const lengths = ids.map(id => id.length);
      expect(new Set(lengths).size).toBe(1); // All same length
    });
  });

  describe('sleep', () => {
    it('should delay execution', async () => {
      const start = Date.now();
      await sleep(50);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(45); // Allow some margin
      expect(elapsed).toBeLessThan(100);
    });

    it('should handle zero delay', async () => {
      const start = Date.now();
      await sleep(0);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(10);
    });
  });

  describe('retry', () => {
    it('should succeed on first try', async () => {
      let attempts = 0;
      const result = await retry(async () => {
        attempts++;
        return 'success';
      });

      expect(result).toBe('success');
      expect(attempts).toBe(1);
    });

    it('should retry on failure', async () => {
      let attempts = 0;
      const result = await retry(async () => {
        attempts++;
        if (attempts < 3) {
          throw new Error('Temporary failure');
        }
        return 'success';
      }, { maxAttempts: 3, delay: 10 });

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    });

    it('should throw after max attempts', async () => {
      let attempts = 0;
      await expect(retry(async () => {
        attempts++;
        throw new Error('Permanent failure');
      }, { maxAttempts: 3, delay: 10 })).rejects.toThrow('Permanent failure');

      expect(attempts).toBe(3);
    });

    it('should use exponential backoff', async () => {
      const delays: number[] = [];
      let lastTime = Date.now();

      await expect(retry(async () => {
        const now = Date.now();
        if (lastTime) {
          delays.push(now - lastTime);
        }
        lastTime = now;
        throw new Error('Fail');
      }, {
        maxAttempts: 3,
        delay: 10,
        backoff: true
      })).rejects.toThrow();

      // Verify delays increase
      expect(delays[1]).toBeGreaterThan(delays[0]);
    });

    it('should handle async functions', async () => {
      let attempts = 0;
      const result = await retry(async () => {
        attempts++;
        await sleep(10);
        if (attempts < 2) {
          throw new Error('Async failure');
        }
        return 'async success';
      }, { maxAttempts: 3, delay: 10 });

      expect(result).toBe('async success');
      expect(attempts).toBe(2);
    });
  });

  describe('parseApiError', () => {
    it('should parse JSON error response', () => {
      const response = {
        status: 400,
        statusText: 'Bad Request',
        json: async () => ({ success: false, error: 'Invalid input' }),
      } as Response;

      const error = parseApiError(response);
      expect(error).toBeInstanceOf(WillowError);
      expect(error.message).toBe('Invalid input');
      expect(error.statusCode).toBe(400);
    });

    it('should handle non-JSON responses', () => {
      const response = {
        status: 500,
        statusText: 'Internal Server Error',
        json: async () => { throw new Error('Not JSON'); },
      } as Response;

      const error = parseApiError(response);
      expect(error).toBeInstanceOf(WillowError);
      expect(error.message).toBe('Internal Server Error');
      expect(error.statusCode).toBe(500);
    });

    it('should extract error details', () => {
      const response = {
        status: 422,
        statusText: 'Unprocessable Entity',
        json: async () => ({
          success: false,
          error: 'Validation failed',
          details: { field: 'email', reason: 'Invalid format' }
        }),
      } as Response;

      const error = parseApiError(response);
      expect(error.message).toBe('Validation failed');
      expect(error.details).toEqual({ field: 'email', reason: 'Invalid format' });
    });

    it('should handle missing error message', () => {
      const response = {
        status: 404,
        statusText: 'Not Found',
        json: async () => ({ success: false }),
      } as Response;

      const error = parseApiError(response);
      expect(error.message).toBe('Not Found');
    });
  });

  describe('integration scenarios', () => {
    it('should retry API calls with parsed errors', async () => {
      let attempts = 0;
      const mockApiCall = async () => {
        attempts++;
        if (attempts < 2) {
          const response = {
            status: 503,
            statusText: 'Service Unavailable',
            json: async () => ({ success: false, error: 'Temporarily unavailable' }),
          } as Response;
          throw parseApiError(response);
        }
        return { data: 'success' };
      };

      const result = await retry(mockApiCall, { maxAttempts: 3, delay: 10 });
      expect(result.data).toBe('success');
      expect(attempts).toBe(2);
    });

    it('should generate unique IDs in batch', () => {
      const ids = Array.from({ length: 1000 }, () => generateId('batch'));
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(1000); // All unique
    });
  });
});