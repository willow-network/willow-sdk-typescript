/**
 * Checked field values for the transactions the SDK signs.
 *
 * A signed transaction is only valid if the node decodes the JSON it is sent
 * to the very values the signature covers. These helpers refuse anything the
 * node would decode differently (a rounded number, a lone surrogate, a byte
 * outside 0..255) instead of letting it through.
 */

import { WillowError } from '../types';
import { hexToBytes } from '../internal/bytes';

const INVALID = 'INVALID_SIGNED_FIELD';

/** Whether `s` holds no lone UTF-16 surrogate, so it has a UTF-8 encoding. */
export function isWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * A text field: a string with a UTF-8 encoding. The API decodes the body as
 * UTF-8, so a lone surrogate would reach the node as something else.
 */
export function text(label: string, value: unknown): string {
  if (typeof value !== 'string') {
    throw new WillowError(`${label} must be a string`, INVALID);
  }
  if (!isWellFormed(value)) {
    throw new WillowError(`${label} holds a lone UTF-16 surrogate`, INVALID);
  }
  return value;
}

/**
 * A `Label: value` line of a signed message. The value goes in verbatim. The
 * chain refuses a text field holding a line feed (the byte 0x0A), so the SDK
 * refuses to sign one. In a JS string only U+000A encodes to that byte, so a
 * CR or U+2028 is signed as it is.
 */
export function textLine(label: string, value: unknown): string {
  const v = text(label, value);
  if (v.includes('\n')) {
    throw new WillowError(
      `${label} holds a line break, which a signed field can't`,
      'LINE_BREAK_IN_SIGNED_FIELD',
    );
  }
  return `${label}: ${v}`;
}

/** The longest DID the chain takes, in bytes. */
const MAX_DID_LEN = 128;

/** `did:willow:` and an identifier of one or more ASCII letters, digits, `_`, or `-`. */
const WILLOW_DID = /^did:willow:[A-Za-z0-9_-]+$/;

/**
 * A DID as the chain takes one: `did:willow:` followed by one or more ASCII
 * letters, digits, `_`, or `-`, at most 128 bytes in all (such a DID is
 * ASCII, so its bytes and characters are the same). Anything else is refused
 * with `INVALID_DID`.
 */
export function willowDid(label: string, value: unknown): string {
  const v = text(label, value);
  if (!WILLOW_DID.test(v) || v.length > MAX_DID_LEN) {
    throw new WillowError(
      `${label} must be 'did:willow:' followed by one or more ASCII letters, digits, '_', or ` +
        `'-', at most ${MAX_DID_LEN} bytes in all; got ${JSON.stringify(v)}`,
      'INVALID_DID',
    );
  }
  return v;
}

/**
 * The subgrove id of a key grant, revoke, or rotation: not empty and with no
 * `:`, which the chain refuses. Anything else is refused with
 * `INVALID_SUBGROVE_ID`.
 */
export function keySubgroveId(label: string, value: unknown): string {
  const v = text(label, value);
  if (v === '' || v.includes(':')) {
    throw new WillowError(
      `${label} must be a non-empty subgrove id with no ':'; got ${JSON.stringify(v)}`,
      'INVALID_SUBGROVE_ID',
    );
  }
  return v;
}

export type UintBits = 8 | 32 | 64 | 128;

/**
 * An unsigned integer of `bits` bits, exactly. Accepts a number that is a
 * safe integer, a bigint, or a string of decimal digits. A number at or
 * above 2^53 may already have been rounded, so it is refused: pass a bigint
 * or a decimal string instead.
 */
export function uint(label: string, value: unknown, bits: UintBits): bigint {
  let v: bigint;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new WillowError(
        `${label} must be a safe integer (or a bigint or decimal string), got ${String(value)}`,
        INVALID,
      );
    }
    v = BigInt(value);
  } else if (typeof value === 'bigint') {
    v = value;
  } else if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
    v = BigInt(value);
  } else {
    throw new WillowError(`${label} must be an unsigned integer, got ${String(value)}`, INVALID);
  }
  if (v < 0n || v >= 1n << BigInt(bits)) {
    throw new WillowError(`${label} is outside u${bits}: ${v}`, INVALID);
  }
  return v;
}

/**
 * An integer as a transaction carries it: a number when it is a safe
 * integer, else a bigint, which the SDK's JSON writer sends as its exact
 * digits.
 */
export function wireInt(v: bigint): number | bigint {
  return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
}

/** {@link uint}, as a transaction carries it ({@link wireInt}). */
export function wireUint(label: string, value: unknown, bits: UintBits): number | bigint {
  return wireInt(uint(label, value, bits));
}

/**
 * A `Label: n` line: an unsigned integer of `bits` bits in decimal, no
 * leading zeros.
 */
export function uintLine(label: string, value: unknown, bits: UintBits): string {
  return `${label}: ${uint(label, value, bits)}`;
}

export function bool(label: string, value: unknown): boolean {
  if (typeof value !== 'boolean') {
    throw new WillowError(`${label} must be a boolean`, INVALID);
  }
  return value;
}

/**
 * A byte string as the chain's JSON carries a `Vec<u8>` or `[u8; N]`: an
 * array of numbers. Accepts an array of integers 0..255 or a `Uint8Array`,
 * and, when `hex` is set, a hex string. With `length`, refuses any other
 * length.
 */
export function bytes(
  label: string,
  value: unknown,
  options: { length?: number; hex?: boolean } = {},
): number[] {
  let out: number[];
  if (value instanceof Uint8Array) {
    out = Array.from(value);
  } else if (Array.isArray(value)) {
    for (const b of value) {
      if (typeof b !== 'number' || !Number.isInteger(b) || b < 0 || b > 255) {
        throw new WillowError(`${label} must hold bytes (integers 0..255)`, INVALID);
      }
    }
    out = value.slice();
  } else if (options.hex && typeof value === 'string') {
    try {
      out = Array.from(hexToBytes(value));
    } catch {
      throw new WillowError(`${label} is not hex`, INVALID);
    }
  } else {
    throw new WillowError(`${label} must be a byte array`, INVALID);
  }
  if (options.length !== undefined && out.length !== options.length) {
    throw new WillowError(`${label} is ${out.length} bytes; it must be ${options.length}`, INVALID);
  }
  return out;
}

/** A list of text fields. */
export function texts(label: string, value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new WillowError(`${label} must be an array of strings`, INVALID);
  }
  return value.map((v, i) => text(`${label}[${i}]`, v));
}

/** The one key and its value of an externally tagged enum value. */
export function variant(label: string, value: unknown): [string, unknown] {
  if (typeof value === 'string') return [value, undefined];
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 1) return entries[0];
  }
  throw new WillowError(`${label} must be one enum variant`, INVALID);
}

export function invalid(message: string): WillowError {
  return new WillowError(message, INVALID);
}
