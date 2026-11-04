/**
 * Helpers shared by the proof checks: proof bytes, the root check, paths,
 * and binding returned JSON values to proven ones.
 */

import { hexToBytes } from '../grovedb';

/** A GroveDB path segment: a string (its UTF-8 bytes) or the bytes. */
export type PathSegment = string | Uint8Array;

/**
 * The GroveDB path of a subgrove's data, `["subgroves", subgroveId, "data"]`:
 * the path `POST /query/:subgrove` and `GET /proof/:subgrove/:key` prove at.
 */
export function subgroveDataPath(subgroveId: string): string[] {
  return ['subgroves', subgroveId, 'data'];
}

export function encodePath(path: PathSegment[]): Uint8Array[] {
  return path.map((segment) =>
    typeof segment === 'string' ? new TextEncoder().encode(segment) : segment,
  );
}

export function decodeProofBytes(proofHex: string): Uint8Array {
  if (!proofHex) throw new Error('Empty proof provided');
  const bytes = hexToBytes(proofHex);
  if (bytes.length === 0) throw new Error('Empty proof provided');
  return bytes;
}

function normalizeRoot(hex: string): string {
  return hex.toLowerCase().replace(/^0x/, '');
}

export function enforceExpectedRoot(computed: string, expected?: string): void {
  if (!expected) return;
  if (normalizeRoot(computed) !== normalizeRoot(expected)) {
    throw new Error(`Root hash mismatch: computed=${computed}, expected=${expected}`);
  }
}

/**
 * A number is fidelity-safe when two distinct JSON source tokens cannot parse
 * to it: exact safe integers, and finite non-integers below the 2^53 boundary.
 * `NaN`, `±Infinity`, `-0`, and any integer past `MAX_SAFE_INTEGER` (which
 * `JSON.parse` silently rounds — e.g. 2^53+1 → 2^53) are NOT fidelity-safe.
 */
export function isFidelitySafeNumber(n: number): boolean {
  if (Number.isInteger(n)) return Number.isSafeInteger(n) && !Object.is(n, -0);
  return Number.isFinite(n) && Math.abs(n) < 2 ** 53;
}

/**
 * Structural (deep) equality over JSON values, used to bind returned documents
 * to the proven bytes. Whitespace and object key order are normalized away by
 * comparing parsed trees; numbers are compared with `Object.is` (so `-0 !== 0`
 * and `NaN` never matches) and only when both are {@link isFidelitySafeNumber}
 * — a precision-unsafe number on either side is a non-match, so two distinct
 * committed byte sequences can never bind to the same JS value.
 */
export function jsonDeepEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== typeof b) return false;
  if (typeof a === 'number') {
    return Object.is(a, b) && isFidelitySafeNumber(a);
  }
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => jsonDeepEqual(v, b[i]));
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a as object);
    const kb = Object.keys(b as object);
    if (ka.length !== kb.length) return false;
    return ka.every((k) =>
      Object.prototype.hasOwnProperty.call(b as object, k) &&
      jsonDeepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]),
    );
  }
  return false;
}
