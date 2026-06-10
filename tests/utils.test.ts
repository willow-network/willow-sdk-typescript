import { generateId, sleep, retry, isValidDid } from '../src/utils';
import { DEVNET_TEST_ACCOUNT } from '../src';

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

    it('should generate IDs containing base36 characters', () => {
      const id = generateId();
      expect(id).toMatch(/^[a-z0-9_]+$/);
    });

    it('should generate many unique IDs', () => {
      const ids = new Set(
        Array.from({ length: 1000 }, () => generateId('batch')),
      );
      expect(ids.size).toBe(1000);
    });
  });

  describe('sleep', () => {
    it('should delay execution', async () => {
      const start = Date.now();
      await sleep(50);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeGreaterThanOrEqual(45);
      expect(elapsed).toBeLessThan(200);
    });

    it('should handle zero delay', async () => {
      const start = Date.now();
      await sleep(0);
      const elapsed = Date.now() - start;
      expect(elapsed).toBeLessThan(20);
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
      const result = await retry(
        async () => {
          attempts++;
          if (attempts < 3) {
            throw new Error('Temporary failure');
          }
          return 'success';
        },
        { attempts: 3, delay: 10 },
      );

      expect(result).toBe('success');
      expect(attempts).toBe(3);
    });

    it('should throw after max attempts', async () => {
      let attempts = 0;
      await expect(
        retry(
          async () => {
            attempts++;
            throw new Error('Permanent failure');
          },
          { attempts: 3, delay: 10 },
        ),
      ).rejects.toThrow('Permanent failure');

      expect(attempts).toBe(3);
    });

    it('should apply exponential backoff', async () => {
      const delays: number[] = [];
      let lastTime = Date.now();

      await expect(
        retry(
          async () => {
            const now = Date.now();
            delays.push(now - lastTime);
            lastTime = now;
            throw new Error('Fail');
          },
          { attempts: 3, delay: 20, backoff: 2 },
        ),
      ).rejects.toThrow();

      // First attempt is immediate (delta close to 0), so check that the
      // second gap is meaningfully larger than the first. Second gap ≈ 20ms,
      // third gap ≈ 40ms.
      expect(delays[2]).toBeGreaterThan(delays[1]);
    });

    it('should handle async functions', async () => {
      let attempts = 0;
      const result = await retry(
        async () => {
          attempts++;
          await sleep(5);
          if (attempts < 2) {
            throw new Error('Async failure');
          }
          return 'async success';
        },
        { attempts: 3, delay: 10 },
      );

      expect(result).toBe('async success');
      expect(attempts).toBe(2);
    });
  });

  describe('isValidDid', () => {
    it('accepts the SDK devnet test account DID (single segment with hyphen)', () => {
      expect(isValidDid(DEVNET_TEST_ACCOUNT.did)).toBe(true);
    });

    it('accepts multi-segment DIDs', () => {
      expect(isValidDid('did:willow:test:123')).toBe(true);
      expect(isValidDid('did:willow:eth:0xabc123')).toBe(true);
    });

    it('rejects malformed DIDs', () => {
      expect(isValidDid('did:willow:')).toBe(false);
      expect(isValidDid('did:willow:abc:')).toBe(false);
      expect(isValidDid('did:other:abc')).toBe(false);
      expect(isValidDid('willow:abc')).toBe(false);
      expect(isValidDid('did:willow:has space')).toBe(false);
    });
  });
});
