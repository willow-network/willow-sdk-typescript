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
 * A number value the binding takes on either side: a finite number other
 * than `-0`. `NaN`, `±Infinity`, and `-0` are not. The value alone can't show
 * that it is exact (`0.1` and `0.10000000000000000001` parse to one value, as
 * do 2^53 and 2^53+1): a proven value's text is checked by
 * {@link isExactJsonNumber}.
 */
export function isFidelitySafeNumber(n: number): boolean {
  return Number.isFinite(n) && !Object.is(n, -0);
}

/**
 * A number's exact decimal value: its sign, its significant digits (no
 * leading or trailing zeros; empty for zero, which has no sign), and the
 * power of ten of the last digit. `1.0`, `1e0`, and `1` are the same value.
 */
interface ExactDecimal {
  negative: boolean;
  digits: string;
  exponent: bigint;
}

/**
 * `text` without its leading `0`s, or without its trailing ones (`end`), in
 * one pass. The text is a proven value's, so it is not left to a regex: one
 * such as `/0+$/` retries its match from every `0` of a run that is not at
 * the end, and takes seconds over a document of tens of thousands of them.
 */
function trimZeros(text: string, end: 'start' | 'end'): string {
  if (end === 'start') {
    let i = 0;
    while (i < text.length && text.charCodeAt(i) === 0x30) i++;
    return text.slice(i);
  }
  let j = text.length;
  while (j > 0 && text.charCodeAt(j - 1) === 0x30) j--;
  return text.slice(0, j);
}

/** The exact decimal value of a JSON number token, or `null` for other text. */
function exactDecimal(text: string): ExactDecimal | null {
  const m = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/.exec(text);
  if (!m) return null;
  const [, sign, whole, fraction = '', exp = '0'] = m;
  const all = trimZeros(whole + fraction, 'start');
  const digits = trimZeros(all, 'end');
  if (digits === '') return { negative: false, digits: '', exponent: 0n };
  const exponent = BigInt(exp) - BigInt(fraction.length) + BigInt(all.length - digits.length);
  return { negative: sign === '-', digits, exponent };
}

/**
 * Whether the number JSON text `text` parses to in JavaScript is the number
 * it writes, so that no other number's text parses to the same value: its
 * exact decimal value is the value of the shortest text that parses back to
 * the same double (`String(Number(text))`, what `JSON.stringify` writes). A
 * double has one shortest text, so no two values that pass parse to the same
 * double. Every number a shortest round-trip writer writes passes, at any
 * magnitude (`1.2100000000000002`, the value of `1.1 * 1.1`;
 * `0.3333333333333333`; `1000000000000000000`, the value of `1e18`), as does
 * the same value in another form (`1.0`, `1e2`); `0.33333333333333331`,
 * which parses to the double written `0.3333333333333333`, and
 * `9007199254740993`, which parses to the double written
 * `9007199254740992`, do not. `-0` is left to {@link isFidelitySafeNumber}.
 */
export function isExactJsonNumber(text: string): boolean {
  const value = Number(text);
  if (!Number.isFinite(value)) return false;
  const written = exactDecimal(text);
  const shortest = exactDecimal(String(value));
  return (
    written !== null &&
    shortest !== null &&
    written.negative === shortest.negative &&
    written.digits === shortest.digits &&
    written.exponent === shortest.exponent
  );
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
 * and `NaN` never matches) and only when both are {@link isFidelitySafeNumber}.
 * The values alone don't show that the proven text was exact: the callers
 * check the proven text's numbers with {@link isExactJsonNumber} first, so two
 * distinct committed byte sequences can never bind to the same JS value.
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
