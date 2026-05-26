/**
 * Cross-language fixture test: confirm the TypeScript canonical anchor body
 * emits the same bytes as the pinned fixture in
 * `tests/fixtures/anchor_canonical_body.json`. The Rust validator runs the
 * same fixture through its own canonicalize implementation; if either side
 * drifts, its CI fails. Update both sides in lockstep.
 */

import { readFileSync } from 'fs';
import { resolve } from 'path';
import {
  canonicalizeAnchorBody,
  sha256Hex,
} from '../src/consensus/anchor-canonical';

const FIXTURE_PATH = resolve(
  __dirname,
  'fixtures',
  'anchor_canonical_body.json',
);

interface Fixture {
  input: {
    did: string;
    anchor_id: string;
    sequence_range: [number, number];
    merkle_root: string;
    count: number;
    receipt_hashes: string[];
    timestamp: string;
    previous_anchor_hash: string;
    is_genesis: boolean;
  };
  expected_canonical: string;
  expected_anchor_hash: string;
}

describe('SubmitAnchorTx canonical body cross-language fixture', () => {
  const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as Fixture;

  it('canonicalizeAnchorBody matches the pinned fixture (must agree byte-for-byte with the Rust validator)', () => {
    const canonical = canonicalizeAnchorBody({
      anchor_id: fixture.input.anchor_id,
      count: fixture.input.count,
      did: fixture.input.did,
      is_genesis: fixture.input.is_genesis,
      merkle_root: fixture.input.merkle_root,
      previous_anchor_hash: fixture.input.previous_anchor_hash,
      receipt_hashes: fixture.input.receipt_hashes,
      sequence_range: fixture.input.sequence_range,
      timestamp: fixture.input.timestamp,
    });
    expect(canonical).toBe(fixture.expected_canonical);
  });

  it('sha256Hex of the canonical body matches the pinned anchor_hash', () => {
    const canonical = canonicalizeAnchorBody({
      anchor_id: fixture.input.anchor_id,
      count: fixture.input.count,
      did: fixture.input.did,
      is_genesis: fixture.input.is_genesis,
      merkle_root: fixture.input.merkle_root,
      previous_anchor_hash: fixture.input.previous_anchor_hash,
      receipt_hashes: fixture.input.receipt_hashes,
      sequence_range: fixture.input.sequence_range,
      timestamp: fixture.input.timestamp,
    });
    const hash = sha256Hex(canonical);
    expect(hash).toBe(fixture.expected_anchor_hash);
  });
});
