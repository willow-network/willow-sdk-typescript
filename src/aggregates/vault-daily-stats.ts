/**
 * Codec + fetch helpers for the per-(vault, day) ERC-4626 flow aggregate
 * sidecar persisted by `willow-indexer-node` for the `vault-daily-stats`
 * template. Pairs with the indexer's
 * `GET /verifiable-rpc-range/:subgrove_id/:from_key_hex/:to_key_hex`
 * endpoint, which returns raw `(key, value)` byte pairs alongside a
 * GroveDB inclusion proof + the latest GKR proof.
 *
 * The sidecar key + value layouts are pinned by
 * `crates/indexer-node/src/vault_daily_stats_sidecar.rs`. Browser-safe:
 * uses `Uint8Array` and `bigint` only.
 *
 * # Trust model
 *
 * The aggregate value isn't directly bound by the GKR `output_root` for
 * the day — each per-block proof commits to per-block totals, and the
 * sidecar sums them locally. To verify a day's value cryptographically,
 * fetch every per-block proof in the day's block range and re-run the
 * sum. See issue #311 for the long-term cryptographic-binding paths.
 */

const KEY_PREFIX_BYTES = new TextEncoder().encode('vds:');

/** Length in bytes of a (vault, day) key: `vds:` + 20-byte address + 8-byte day_id. */
export const VAULT_DAILY_STATS_KEY_LEN = 32;

/** Length in bytes of an encoded `DayAggregate` value. */
export const VAULT_DAILY_STATS_VALUE_LEN = 56;

/** Seconds per UTC day — matches the sidecar's `day_id_from_timestamp`. */
export const SECONDS_PER_DAY = 86_400n;

/**
 * Decoded per-(vault, day) aggregate. `totalIn`, `totalOut`, and `maxIn`
 * are u128 (bigint); counts fit in u32 (regular `number`).
 */
export interface DayAggregate {
  /** Deposit event count for this (vault, day). */
  depositCount: number;
  /** Withdraw event count. */
  withdrawCount: number;
  /** Sum of `assets` over all matching deposits. */
  totalIn: bigint;
  /** Sum of `assets` over all matching withdraws. */
  totalOut: bigint;
  /** Largest single deposit's `assets` over this (vault, day). */
  maxIn: bigint;
}

/**
 * UTC day index from a unix-second timestamp. Matches
 * `vault_daily_stats_sidecar::day_id_from_timestamp`. Day boundaries
 * fall on UTC midnight, so monthly retros line up with calendar dates.
 */
export function dayIdFromTimestamp(unixSecs: bigint | number): bigint {
  const secs = typeof unixSecs === 'bigint' ? unixSecs : BigInt(unixSecs);
  return secs / SECONDS_PER_DAY;
}

/** Convenience: UTC day index from a JS `Date`. */
export function dayIdFromDate(date: Date): bigint {
  return dayIdFromTimestamp(Math.floor(date.getTime() / 1000));
}

/**
 * Encode a `(vault, day_id)` lookup key.
 *
 * @param vault - 20-byte EVM address
 * @param dayId - UTC day index (e.g. from {@link dayIdFromTimestamp})
 */
export function encodeVaultDailyStatsKey(
  vault: Uint8Array,
  dayId: bigint,
): Uint8Array {
  if (vault.length !== 20) {
    throw new Error(
      `vault address must be 20 bytes, got ${vault.length}`,
    );
  }
  const out = new Uint8Array(VAULT_DAILY_STATS_KEY_LEN);
  out.set(KEY_PREFIX_BYTES, 0);
  out.set(vault, 4);
  // 8-byte big-endian day_id at offset 24.
  let v = dayId;
  for (let i = 7; i >= 0; i--) {
    out[24 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Inverse of {@link encodeVaultDailyStatsKey}. Throws on malformed input. */
export function decodeVaultDailyStatsKey(
  bytes: Uint8Array,
): { vault: Uint8Array; dayId: bigint } {
  if (bytes.length !== VAULT_DAILY_STATS_KEY_LEN) {
    throw new Error(
      `vault-daily-stats key must be ${VAULT_DAILY_STATS_KEY_LEN} bytes, got ${bytes.length}`,
    );
  }
  for (let i = 0; i < KEY_PREFIX_BYTES.length; i++) {
    if (bytes[i] !== KEY_PREFIX_BYTES[i]) {
      throw new Error(`vault-daily-stats key prefix mismatch at byte ${i}`);
    }
  }
  const vault = bytes.slice(4, 24);
  let dayId = 0n;
  for (let i = 0; i < 8; i++) {
    dayId = (dayId << 8n) | BigInt(bytes[24 + i]);
  }
  return { vault, dayId };
}

/** Decode a 56-byte value into a `DayAggregate`. Throws on wrong length. */
export function decodeDayAggregate(bytes: Uint8Array): DayAggregate {
  if (bytes.length !== VAULT_DAILY_STATS_VALUE_LEN) {
    throw new Error(
      `DayAggregate value must be ${VAULT_DAILY_STATS_VALUE_LEN} bytes, got ${bytes.length}`,
    );
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const depositCount = view.getUint32(0, false);
  const withdrawCount = view.getUint32(4, false);
  const totalIn = readU128BE(bytes, 8);
  const totalOut = readU128BE(bytes, 24);
  const maxIn = readU128BE(bytes, 40);
  return { depositCount, withdrawCount, totalIn, totalOut, maxIn };
}

/** Encode a `DayAggregate` into the wire byte layout. Inverse of {@link decodeDayAggregate}. */
export function encodeDayAggregate(agg: DayAggregate): Uint8Array {
  const out = new Uint8Array(VAULT_DAILY_STATS_VALUE_LEN);
  const view = new DataView(out.buffer);
  view.setUint32(0, agg.depositCount, false);
  view.setUint32(4, agg.withdrawCount, false);
  writeU128BE(out, 8, agg.totalIn);
  writeU128BE(out, 24, agg.totalOut);
  writeU128BE(out, 40, agg.maxIn);
  return out;
}

/** One row from the verifiable-rpc-range endpoint with its decoded form. */
export interface VaultDailyStatsRow {
  /** Vault address from the row's key. */
  vault: Uint8Array;
  /** UTC day index from the row's key. */
  dayId: bigint;
  /** Decoded value. */
  aggregate: DayAggregate;
  /** Raw key bytes (32) — exactly what the server returned. */
  rawKey: Uint8Array;
  /** Raw value bytes (56) — exactly what the server returned. */
  rawValue: Uint8Array;
}

/**
 * Decode a `verifiable-rpc-range` response's `rows: [{key, value}]` list
 * into typed rows. Skips rows whose value isn't 56 bytes (server returns
 * empty `value` for non-Item GroveDB elements that happen to fall in the
 * range — those aren't aggregate entries).
 *
 * Caller is still responsible for verifying the GroveDB inclusion proof
 * and the GKR proofs the response carries.
 */
export function decodeVaultDailyStatsRows(
  rows: ReadonlyArray<{ key: ArrayLike<number> | Uint8Array; value: ArrayLike<number> | Uint8Array }>,
): VaultDailyStatsRow[] {
  const out: VaultDailyStatsRow[] = [];
  for (const r of rows) {
    const key = toUint8Array(r.key);
    const value = toUint8Array(r.value);
    if (value.length !== VAULT_DAILY_STATS_VALUE_LEN) {
      continue;
    }
    const { vault, dayId } = decodeVaultDailyStatsKey(key);
    const aggregate = decodeDayAggregate(value);
    out.push({ vault, dayId, aggregate, rawKey: key, rawValue: value });
  }
  return out;
}

/**
 * Build the inclusive `[fromDayId, toDayId]` byte-key range for one
 * vault. Pass these to `verifiable-rpc-range` as `from_key_hex` /
 * `to_key_hex`.
 */
export function vaultDayRangeKeys(
  vault: Uint8Array,
  fromDayId: bigint,
  toDayId: bigint,
): { fromKey: Uint8Array; toKey: Uint8Array } {
  if (toDayId < fromDayId) {
    throw new Error(
      `toDayId (${toDayId}) must be >= fromDayId (${fromDayId})`,
    );
  }
  return {
    fromKey: encodeVaultDailyStatsKey(vault, fromDayId),
    toKey: encodeVaultDailyStatsKey(vault, toDayId),
  };
}

function readU128BE(bytes: Uint8Array, offset: number): bigint {
  let v = 0n;
  for (let i = 0; i < 16; i++) {
    v = (v << 8n) | BigInt(bytes[offset + i]);
  }
  return v;
}

function writeU128BE(out: Uint8Array, offset: number, value: bigint): void {
  if (value < 0n) {
    throw new Error('u128 cannot be negative');
  }
  if (value >> 128n !== 0n) {
    throw new Error(`value ${value} exceeds u128`);
  }
  let v = value;
  for (let i = 15; i >= 0; i--) {
    out[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function toUint8Array(input: ArrayLike<number> | Uint8Array): Uint8Array {
  if (input instanceof Uint8Array) {
    return input;
  }
  return Uint8Array.from(input as ArrayLike<number>);
}
