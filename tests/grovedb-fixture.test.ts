/**
 * Cross-language round-trip test for the TypeScript GroveDB verifier.
 *
 * The fixtures in tests/fixtures/grovedb/ are produced by a Rust generator
 * that exercises the canonical GroveDB implementation. Each fixture
 * contains real proof bytes and root hashes from that implementation.
 *
 * This test asserts that the pure-TS verifier in src/grovedb/ produces
 * byte-identical root hashes from those proofs — proving the TS verifier
 * is a faithful reimplementation and safe to use in a browser.
 *
 * Also exercises the high-level wrappers in src/proof/ against real proofs
 * so we know the wiring fix (proof-wiring.test.ts) covers real data, not
 * just garbage rejection.
 */

import * as fs from 'fs';
import * as path from 'path';

import {
  verifyGroveDBProof,
  quickVerify,
  hexToBytes,
  bytesToHex,
  hashToHex,
} from '../src/grovedb';
import { verifyItemProof, verifyQueryProof } from '../src/proof';

const FIXTURES_DIR = path.join(__dirname, 'fixtures', 'grovedb');

interface SingleKeyFixture {
  kind: 'single_key';
  description: string;
  path: string[];
  key: string;
  value_hex: string;
  proof_hex: string;
  expected_root_hex: string;
}

interface RangeFullFixture {
  kind: 'range_full';
  description: string;
  path: string[];
  expected_keys: string[];
  expected_values_hex: string[];
  proof_hex: string;
  expected_root_hex: string;
}

function loadFixture<T>(name: string): T {
  const raw = fs.readFileSync(path.join(FIXTURES_DIR, `${name}.json`), 'utf8');
  return JSON.parse(raw) as T;
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('TS GroveDB verifier ↔ Rust prover fixture round-trip', () => {
  describe('single_key_apps_data_key2', () => {
    const f = loadFixture<SingleKeyFixture>('single_key_apps_data_key2');

    it('verifyGroveDBProof returns the Rust-computed root hash', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      expect(hashToHex(result.rootHash)).toBe(f.expected_root_hex);
    });

    it('results contain the requested (path, key, value)', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      const expectedPath = f.path.map(utf8);
      const expectedKey = utf8(f.key);
      const expectedValue = hexToBytes(f.value_hex);

      const match = result.results.find(
        (r) =>
          r.path.length === expectedPath.length &&
          r.path.every((seg, i) => bytesEqual(seg, expectedPath[i])) &&
          bytesEqual(r.key, expectedKey),
      );
      expect(match).toBeDefined();
      expect(match!.value).not.toBeNull();
      expect(bytesToHex(match!.value!)).toContain(bytesToHex(expectedValue));
    });

    it('quickVerify returns the same root hash', () => {
      const root = quickVerify(hexToBytes(f.proof_hex));
      expect(hashToHex(root)).toBe(f.expected_root_hex);
    });

    it('high-level verifyItemProof returns the Rust root hash', async () => {
      const computed = await verifyItemProof(
        f.proof_hex,
        f.key,
        undefined,
        f.path,
      );
      expect(computed).toBe(f.expected_root_hex);
    });

    it('high-level verifyItemProof rejects wrong key', async () => {
      await expect(
        verifyItemProof(f.proof_hex, 'some-other-key', undefined, f.path),
      ).rejects.toThrow(/does not contain key/);
    });

    it('high-level verifyItemProof rejects wrong path', async () => {
      await expect(
        verifyItemProof(f.proof_hex, f.key, undefined, ['wrong', 'path']),
      ).rejects.toThrow(/does not contain key/);
    });
  });

  describe('range_full_apps_data', () => {
    const f = loadFixture<RangeFullFixture>('range_full_apps_data');

    it('verifyGroveDBProof returns the Rust-computed root hash', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      expect(hashToHex(result.rootHash)).toBe(f.expected_root_hex);
    });

    it('results include every expected key/value at the expected path', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      const expectedPath = f.path.map(utf8);

      for (let i = 0; i < f.expected_keys.length; i++) {
        const expectedKey = utf8(f.expected_keys[i]);
        const expectedValue = hexToBytes(f.expected_values_hex[i]);

        const match = result.results.find(
          (r) =>
            r.path.length === expectedPath.length &&
            r.path.every((seg, j) => bytesEqual(seg, expectedPath[j])) &&
            bytesEqual(r.key, expectedKey),
        );
        expect(match).toBeDefined();
        expect(match!.value).not.toBeNull();
        expect(bytesToHex(match!.value!)).toContain(bytesToHex(expectedValue));
      }
    });

    it('high-level verifyQueryProof returns the Rust root hash', async () => {
      const computed = await verifyQueryProof(f.proof_hex, []);
      expect(computed).toBe(f.expected_root_hex);
    });
  });

  describe('nested_single_key_user_bob', () => {
    const f = loadFixture<SingleKeyFixture>('nested_single_key_user_bob');

    it('verifyGroveDBProof returns the Rust-computed root hash (3-layer nesting)', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      expect(hashToHex(result.rootHash)).toBe(f.expected_root_hex);
    });

    it('proven value matches the expected bytes', () => {
      const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
      const expectedKey = utf8(f.key);
      const expectedPath = f.path.map(utf8);

      const match = result.results.find(
        (r) =>
          r.path.length === expectedPath.length &&
          r.path.every((seg, i) => bytesEqual(seg, expectedPath[i])) &&
          bytesEqual(r.key, expectedKey),
      );
      expect(match).toBeDefined();
      expect(bytesToHex(match!.value!)).toContain(f.value_hex);
    });

    it('high-level verifyItemProof returns the Rust root hash', async () => {
      const computed = await verifyItemProof(
        f.proof_hex,
        f.key,
        undefined,
        f.path,
      );
      expect(computed).toBe(f.expected_root_hex);
    });
  });
});
