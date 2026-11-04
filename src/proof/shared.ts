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
 * A number value the binding takes on either side: a safe integer other than
 * `-0`, or a finite non-integer below 2^53 in magnitude. `NaN`, `±Infinity`,
 * `-0`, and any integer past `MAX_SAFE_INTEGER` (which `JSON.parse` rounds:
 * 2^53+1 → 2^53) are not. The value alone can't show that it is exact
 * (`0.1` and `0.10000000000000000001` parse to one value): a proven value's
 * text is checked by {@link isExactJsonNumber}.
 */
export function isFidelitySafeNumber(n: number): boolean {
  if (Number.isInteger(n)) return Number.isSafeInteger(n) && !Object.is(n, -0);
  return Number.isFinite(n) && Math.abs(n) < 2 ** 53;
}

/** The smallest positive normal double; below it a double keeps fewer digits. */
const MIN_NORMAL = 2 ** -1022;

/**
 * Whether the number JSON text `text` parses to in JavaScript is the number
 * it writes, so that no other number's text parses to the same value. An
 * integer (no fraction or exponent) must be a safe integer. Any other number
 * must have at most 15 significant digits, which a double keeps through a
 * round trip, and be zero or of a magnitude a double holds at full precision
 * (from 2^-1022 up); `0.12345678901234567` (17 digits) and `1e-320` are not
 * exact. `-0` is left to {@link isFidelitySafeNumber}.
 */
export function isExactJsonNumber(text: string): boolean {
  const value = Number(text);
  if (!Number.isFinite(value)) return false;
  if (/^-?[0-9]+$/.test(text)) return Number.isSafeInteger(value);
  const digits = text
    .split(/[eE]/)[0]
    .replace(/[-.]/g, '')
    .replace(/^0+/, '')
    .replace(/0+$/, '');
  if (digits.length === 0) return true;
  return digits.length <= 15 && Math.abs(value) >= MIN_NORMAL;
}

/**
 * The first number in JSON text `text` (valid JSON) that JavaScript can't
 * carry exactly ({@link isExactJsonNumber}), or `undefined` when there is
 * none.
 */
export function firstInexactNumber(text: string): string | undefined {
  for (const [token] of text.matchAll(/"(?:[^"\\]|\\.)*"|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/g)) {
    if (token[0] !== '"' && !isExactJsonNumber(token)) return token;
  }
  return undefined;
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
