/**
 * Tests that src/proof/index.ts uses the real GroveDB verifier,
 * not the heuristic one. The heuristic verifier accepts arbitrary
 * byte sequences as "proofs" and returns the first 32-byte run that
 * has enough entropy as the "root hash" — giving the appearance of
 * verification without any cryptographic binding.
 *
 * A correct verifier must reject:
 *   - random bytes (not valid bincode-encoded GroveDBProof)
 *   - truncated proofs
 *   - proofs with mismatched internal hashes
 *
 * These tests are expected to FAIL against the heuristic implementation
 * and PASS once src/proof/index.ts delegates to src/grovedb/verifier.ts.
 */

import { verifyItemProof, verifyQueryProof, extractRootHashFromProof } from '../src/proof';

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deterministic, high-entropy byte sequence. Each byte is distinct modulo 256
 * for the first 256 positions, so any 32-byte window has 32 distinct bytes
 * (≫ the heuristic's 8-unique-byte threshold for "looks like a hash"). That
 * way, the heuristic verifier definitely finds a window and returns it as a
 * root hash — i.e., accepts garbage — which is exactly the bug under test.
 */
function highEntropyBytes(length: number, offset = 0): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = (offset + i * 17 + 29) & 0xff;
  }
  return out;
}

describe('proof/index.ts wiring — delegates to real GroveDB verifier', () => {
  describe('garbage input rejection', () => {
    it('rejects 128 bytes of random data as verifyItemProof input', async () => {
      const garbage = highEntropyBytes(128, 42);
      const garbageHex = toHex(garbage);

      await expect(
        verifyItemProof(garbageHex, 'some-key', { any: 'value' }, ['subgroves', 'my-sub', 'data']),
      ).rejects.toThrow();
    });

    it('rejects 128 bytes of random data as verifyQueryProof input', async () => {
      const garbage = highEntropyBytes(128, 7);
      const garbageHex = toHex(garbage);

      await expect(
        verifyQueryProof(garbageHex, [{ key: 'k', value: 'v' }]),
      ).rejects.toThrow();
    });

    it('rejects 256 bytes of random data as extractRootHashFromProof input', async () => {
      const garbage = highEntropyBytes(256, 99);
      const garbageHex = toHex(garbage);

      await expect(extractRootHashFromProof(garbageHex)).rejects.toThrow();
    });
  });

  describe('input validation', () => {
    it('rejects empty proof', async () => {
      await expect(
        verifyItemProof('', 'k', 'v', []),
      ).rejects.toThrow();
    });

    it('rejects invalid hex', async () => {
      await expect(
        verifyItemProof('nothex', 'k', 'v', []),
      ).rejects.toThrow();
    });
  });
});
