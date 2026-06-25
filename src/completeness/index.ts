/**
 * Client-side completeness verification.
 *
 * Mirrors Willow's on-chain `canonical_event_set_hash`
 * (`willow-network::data_sources::types`, surfaced by consensus as the
 * per-block `events_commitment`). The chain commits to the filter-matched
 * event set of a `(subgrove, block)` via a single domain-separated
 * keccak-256 hash. An indexer can serve the matched-log preimage, and a
 * client re-hashes it here and compares against that on-chain anchor — so
 * the served set is provably the complete, untampered set the chain
 * attests to, without trusting the indexer.
 *
 * The hash binds only `(address, topics, data)` — the consensus-derivable,
 * root-bound fields — length-prefixed so no boundary is ambiguous. It
 * deliberately excludes transaction hashes, indices, and block-header
 * fields, so every honest party computes the same value.
 *
 * NOTE: there is no `verifyBlockCompleteness(subgroveId, blockNumber)`
 * convenience here. That would require both an ABCI store-query helper for
 * the `events_commitment` anchor and an indexer client for the matched-log
 * preimage endpoint, neither of which this SDK wires up yet. Fetch the
 * 32-byte commitment and the matched logs with your own transport, then
 * call `verifyServedEvents` directly.
 */

import { keccak_256 } from "@noble/hashes/sha3";

import { bytesToHex, hexToBytes } from "../internal/bytes";

/** Domain-separation tag, ASCII, no null terminator (23 bytes). */
const DOMAIN_TAG = "WILLOW_CRYPTO_EVENTS_V1";

/** Fixed widths of the canonical encoding, in bytes. */
const ADDRESS_LEN = 20;
const TOPIC_LEN = 32;
const COMMITMENT_LEN = 32;

/** Block number, accepted as a `number` (must be a safe integer) or `bigint`. */
export type BlockNumber = number | bigint;

/** Raw bytes, accepted as a `Uint8Array` or a `0x`-prefixed (or bare) hex string. */
export type ByteInput = Uint8Array | string;

/**
 * A filter-matched Ethereum log, in the canonical shape the commitment
 * binds. Only these three fields are hashed.
 */
export interface Log {
  /** Emitting contract address, exactly 20 bytes. */
  address: ByteInput;
  /** Indexed topics, each exactly 32 bytes. */
  topics: ByteInput[];
  /** ABI-encoded non-indexed event data, arbitrary length. */
  data: ByteInput;
}

function toBytes(input: ByteInput, what: string): Uint8Array {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") return hexToBytes(input);
  throw new TypeError(`${what} must be a Uint8Array or hex string`);
}

function toFixedBytes(input: ByteInput, len: number, what: string): Uint8Array {
  const bytes = toBytes(input, what);
  if (bytes.length !== len) {
    throw new Error(
      `${what} must be exactly ${len} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}

function blockNumberToU64Be(blockNumber: BlockNumber): Uint8Array {
  const v = typeof blockNumber === "bigint" ? blockNumber : BigInt(blockNumber);
  if (typeof blockNumber === "number" && !Number.isSafeInteger(blockNumber)) {
    throw new Error(`blockNumber must be a safe integer, got ${blockNumber}`);
  }
  if (v < 0n || v > 0xffffffffffffffffn) {
    throw new Error(`blockNumber out of u64 range: ${v}`);
  }
  const out = new Uint8Array(8);
  let n = v;
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function u64Be(value: number): Uint8Array {
  return blockNumberToU64Be(value);
}

function u32Be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`u32 out of range: ${value}`);
  }
  const out = new Uint8Array(4);
  out[0] = (value >>> 24) & 0xff;
  out[1] = (value >>> 16) & 0xff;
  out[2] = (value >>> 8) & 0xff;
  out[3] = value & 0xff;
  return out;
}

/**
 * Domain-separated keccak-256 commitment over the filter-matched event set
 * in canonical order — byte-identical to Willow's on-chain
 * `canonical_event_set_hash` / `events_commitment`.
 *
 * Preimage (all integers big-endian, no separators):
 *   "WILLOW_CRYPTO_EVENTS_V1" (23 bytes)
 *   ‖ blockNumber : u64 BE (8 bytes)
 *   ‖ matchedLogs.length : u64 BE (8 bytes)
 *   ‖ for each log, in order:
 *       address (20 bytes)
 *       ‖ topics.length : u32 BE (4 bytes)
 *       ‖ each topic (32 bytes)
 *       ‖ data.length : u32 BE (4 bytes)
 *       ‖ data (raw)
 *
 * @returns the 32-byte commitment.
 */
export function canonicalEventSetHash(
  blockNumber: BlockNumber,
  matchedLogs: Log[],
): Uint8Array {
  const hasher = keccak_256.create();
  hasher.update(new TextEncoder().encode(DOMAIN_TAG));
  hasher.update(blockNumberToU64Be(blockNumber));
  hasher.update(u64Be(matchedLogs.length));
  for (const log of matchedLogs) {
    hasher.update(toFixedBytes(log.address, ADDRESS_LEN, "log.address"));
    hasher.update(u32Be(log.topics.length));
    for (const topic of log.topics) {
      hasher.update(toFixedBytes(topic, TOPIC_LEN, "log.topic"));
    }
    const data = toBytes(log.data, "log.data");
    hasher.update(u32Be(data.length));
    hasher.update(data);
  }
  return hasher.digest();
}

/** Hex (`0x`-prefixed) form of {@link canonicalEventSetHash}. */
export function canonicalEventSetHashHex(
  blockNumber: BlockNumber,
  matchedLogs: Log[],
): string {
  return "0x" + bytesToHex(canonicalEventSetHash(blockNumber, matchedLogs));
}

function constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verify that `matchedLogs` is exactly the complete, untampered event set
 * the chain committed to for `blockNumber` via `commitment` (the on-chain
 * 32-byte `events_commitment`).
 *
 * Re-hashes the served logs with {@link canonicalEventSetHash} and compares
 * against `commitment` in constant time. Any added, dropped, reordered, or
 * mutated log — or a wrong block number — yields `false`.
 *
 * @param commitment the trusted 32-byte anchor (`Uint8Array` or hex).
 */
export function verifyServedEvents(
  commitment: ByteInput,
  blockNumber: BlockNumber,
  matchedLogs: Log[],
): boolean {
  const expected = toFixedBytes(commitment, COMMITMENT_LEN, "commitment");
  const actual = canonicalEventSetHash(blockNumber, matchedLogs);
  return constantTimeEquals(expected, actual);
}
