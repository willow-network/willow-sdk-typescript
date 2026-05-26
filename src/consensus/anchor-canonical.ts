/**
 * Canonical anchor body + Merkle root helpers.
 *
 * **MUST** produce byte-identical output to the Rust validator's
 * `canonicalize_anchor_body` and `compute_merkle_root` so the chain
 * accepts the recomputed hashes.
 */

import { sha256 } from '@noble/hashes/sha256';

export function sha256Hex(input: string | Uint8Array): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const digest = sha256(bytes);
  let hex = '';
  for (let i = 0; i < digest.length; i++) {
    hex += digest[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Anchor body fields the chain hashes. Keys must be emitted in
 * alphabetical order; the validator hardcodes the order in
 * `canonicalize_anchor_body`.
 */
export interface AnchorBodyInput {
  anchor_id: string;
  count: number;
  did: string;
  is_genesis: boolean;
  merkle_root: string;
  previous_anchor_hash: string;
  receipt_hashes: string[];
  sequence_range: [number, number];
  timestamp: string;
}

function jsonEscape(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\r') out += '\\r';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\b') out += '\\b';
    else if (ch === '\f') out += '\\f';
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  out += '"';
  return out;
}

export function canonicalizeAnchorBody(body: AnchorBodyInput): string {
  // Emit fields in alphabetical key order — matches the Rust validator.
  const parts: string[] = [];
  parts.push(`${jsonEscape('anchor_id')}:${jsonEscape(body.anchor_id)}`);
  parts.push(`${jsonEscape('count')}:${body.count}`);
  parts.push(`${jsonEscape('did')}:${jsonEscape(body.did)}`);
  parts.push(`${jsonEscape('is_genesis')}:${body.is_genesis}`);
  parts.push(`${jsonEscape('merkle_root')}:${jsonEscape(body.merkle_root)}`);
  parts.push(`${jsonEscape('previous_anchor_hash')}:${jsonEscape(body.previous_anchor_hash)}`);
  parts.push(`${jsonEscape('receipt_hashes')}:[${body.receipt_hashes.map(jsonEscape).join(',')}]`);
  parts.push(`${jsonEscape('sequence_range')}:[${body.sequence_range[0]},${body.sequence_range[1]}]`);
  parts.push(`${jsonEscape('timestamp')}:${jsonEscape(body.timestamp)}`);
  return '{' + parts.join(',') + '}';
}

/**
 * Pair-and-hash Merkle root with duplicate-last-on-odd. Matches the
 * Rust validator and `mcp/src/merkle.ts`.
 */
export function computeAnchorMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) return '';
  let level = [...hashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256Hex(left + right));
    }
    level = next;
  }
  return level[0];
}
