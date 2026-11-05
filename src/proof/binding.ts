/**
 * Binding returned values to the values a GroveDB proof proves, and the
 * stricter check of one key's value in a subgrove's data that a verified
 * read makes. Internal: the `proof` module's exported functions build on it.
 */

import {
  GroveDBVerificationResult,
  hashToHex,
  isTreeElement,
  verifyGroveDBProof,
} from '../grovedb';
import {
  PathSegment,
  decodeProofBytes,
  encodePath,
  enforceExpectedRoot,
  firstInexactNumber,
  jsonDeepEqual,
  subgroveDataPath,
} from './shared';

/** One entry a proof proves. */
export type ProvenResult = GroveDBVerificationResult['results'][number];

export function pathLabel(path: PathSegment[]): string {
  return path
    .map((segment) => (typeof segment === 'string' ? segment : `0x${hashToHex(segment)}`))
    .join(', ');
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function pathEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!bytesEqual(a[i], b[i])) return false;
  return true;
}

/**
 * A value the proof commits to: the raw proven Item bytes, decoded as JSON
 * when they parse, otherwise kept as opaque bytes so a non-JSON stored Item
 * (raw blob) can still bind to a returned value by exact bytes.
 */
export type ProvenValue =
  /** `inexact`: the first number in the text JavaScript can't carry exactly. */
  | { kind: 'json'; value: unknown; inexact?: string }
  | { kind: 'raw'; bytes: Uint8Array };

/**
 * Bytes that are not UTF-8, or that start with a byte-order mark, are not
 * JSON text to the node, so they stay raw: a decoder that replaced bad bytes
 * or dropped the mark would read other bytes as the same JSON.
 */
export function decodeProvenValue(raw: Uint8Array): ProvenValue {
  try {
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw);
    return { kind: 'json', value: JSON.parse(text), inexact: firstInexactNumber(text) };
  } catch {
    return { kind: 'raw', bytes: raw };
  }
}

/**
 * Test whether a returned `document` binds to a proven value. JSON-proven
 * bytes bind by structural equality (number fidelity enforced), and never
 * when they hold a number JavaScript can't carry exactly; non-JSON proven
 * bytes bind only when the document is itself raw bytes equal to them
 * (DataRecord documents are JSON, so they never bind to a raw blob).
 */
export function documentBindsTo(proven: ProvenValue, document: unknown): boolean {
  if (proven.kind === 'json') return proven.inexact === undefined && jsonDeepEqual(proven.value, document);
  return document instanceof Uint8Array && bytesEqual(proven.bytes, document);
}

/**
 * The bytes a proven result commits to as a value: an Item's payload, or the
 * raw leaf bytes when the element didn't deserialize. A subtree is not a
 * value (and one proven without its lower layer is not bound byte for byte),
 * so it gives none.
 */
export function provenRaw(result: ProvenResult): Uint8Array | null {
  if (result.tree) return null;
  if (result.element?.type === 'Item') return result.element.value;
  if (result.element && isTreeElement(result.element)) return null;
  return result.value;
}

/** The proven entry at exactly `path` and `key`, if the proof proves one. */
export function provenEntry(
  verification: GroveDBVerificationResult,
  path: Uint8Array[],
  key: Uint8Array,
): ProvenResult | undefined {
  return verification.results.find((r) => pathEqual(r.path, path) && bytesEqual(r.key, key));
}

/**
 * Require `value` to bind to `raw`, the bytes proven at `key` (`null`: no
 * value is proven there). Throws when it doesn't, or when the proven bytes
 * hold a number JavaScript can't carry exactly.
 */
export function requireValueBinds(key: string, raw: Uint8Array | null, value: unknown): void {
  const proven = raw ? decodeProvenValue(raw) : null;
  if (proven?.kind === 'json' && proven.inexact !== undefined) {
    throw new Error(
      `Proven value for key "${key}" holds the number ${proven.inexact}, which JavaScript can't ` +
        'carry exactly; store such values as strings',
    );
  }
  if (!proven || !documentBindsTo(proven, value)) {
    throw new Error(
      `Proven value for key "${key}" does not match the returned data — ` +
        'the server returned data the proof does not cover',
    );
  }
}

/**
 * Verify a `GET /proof/:subgrove/:key` proof of the value the API returned
 * for `key` in subgrove `subgroveId`'s data, and return the proof's root
 * hash (hex), still to be compared with a trusted root.
 *
 * Nothing is skipped: `value` is the value returned, and one the API's
 * answer does not carry (`undefined`) is refused, not checked for the key
 * alone. The proof must descend to the subgrove's data path and prove an
 * Item at `key` whose payload `value` binds to.
 */
export function verifySubgroveItem(
  proofHex: string,
  subgroveId: string,
  key: string,
  value: unknown,
  expectedRootHash?: string,
): string {
  if (value === undefined) {
    throw new Error(`The API's answer for key "${key}" carries no value to check against the proof`);
  }
  const path = encodePath(subgroveDataPath(subgroveId));
  const verification = verifyGroveDBProof(decodeProofBytes(proofHex), { expectedPath: path });
  const entry = provenEntry(verification, path, new TextEncoder().encode(key));
  if (!entry) {
    throw new Error(
      `Proof does not contain key "${key}" at path [${pathLabel(subgroveDataPath(subgroveId))}]`,
    );
  }
  requireValueBinds(key, entry.element?.type === 'Item' ? entry.element.value : null, value);
  const computed = hashToHex(verification.rootHash);
  enforceExpectedRoot(computed, expectedRootHash);
  return computed;
}
