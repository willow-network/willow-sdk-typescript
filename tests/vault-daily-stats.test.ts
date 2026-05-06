import {
  VAULT_DAILY_STATS_KEY_LEN,
  VAULT_DAILY_STATS_VALUE_LEN,
  SECONDS_PER_DAY,
  dayIdFromTimestamp,
  dayIdFromDate,
  encodeVaultDailyStatsKey,
  decodeVaultDailyStatsKey,
  decodeDayAggregate,
  encodeDayAggregate,
  decodeVaultDailyStatsRows,
  vaultDayRangeKeys,
  type DayAggregate,
} from '../src/aggregates/vault-daily-stats';

describe('vault-daily-stats codec', () => {
  describe('day_id boundaries', () => {
    it('rounds 2026-04-29 00:00 UTC to its own day', () => {
      // 2026-04-29 00:00:00 UTC = 1777593600
      expect(dayIdFromTimestamp(1_777_593_600)).toBe(
        BigInt(1_777_593_600) / SECONDS_PER_DAY,
      );
    });

    it('keeps 23:59:59 of the same day in the same bucket', () => {
      const midnight = 1_777_593_600n;
      expect(dayIdFromTimestamp(midnight + 86_399n)).toBe(
        dayIdFromTimestamp(midnight),
      );
    });

    it('rolls over at the next UTC midnight', () => {
      const midnight = 1_777_593_600n;
      expect(dayIdFromTimestamp(midnight + 86_400n)).toBe(
        dayIdFromTimestamp(midnight) + 1n,
      );
    });

    it('accepts both number and bigint timestamps', () => {
      expect(dayIdFromTimestamp(1_777_593_600)).toBe(
        dayIdFromTimestamp(1_777_593_600n),
      );
    });

    it('dayIdFromDate matches dayIdFromTimestamp for the same instant', () => {
      const d = new Date('2026-04-29T12:34:56Z');
      const secs = Math.floor(d.getTime() / 1000);
      expect(dayIdFromDate(d)).toBe(dayIdFromTimestamp(secs));
    });
  });

  describe('key codec', () => {
    const vault = new Uint8Array([
      0xab, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
      0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
    ]);

    it('encodes 32 bytes total', () => {
      const key = encodeVaultDailyStatsKey(vault, 12_345n);
      expect(key.length).toBe(VAULT_DAILY_STATS_KEY_LEN);
      expect(key.length).toBe(32);
    });

    it('starts with vds: prefix', () => {
      const key = encodeVaultDailyStatsKey(vault, 12_345n);
      expect(String.fromCharCode(...key.slice(0, 4))).toBe('vds:');
    });

    it('round-trips through decode', () => {
      const dayId = 19_842n;
      const key = encodeVaultDailyStatsKey(vault, dayId);
      const decoded = decodeVaultDailyStatsKey(key);
      expect(decoded.dayId).toBe(dayId);
      expect(Array.from(decoded.vault)).toEqual(Array.from(vault));
    });

    it('rejects wrong-length addresses', () => {
      expect(() =>
        encodeVaultDailyStatsKey(new Uint8Array(19), 0n),
      ).toThrow(/20 bytes/);
    });

    it('rejects wrong-length keys on decode', () => {
      expect(() => decodeVaultDailyStatsKey(new Uint8Array(31))).toThrow(
        /32 bytes/,
      );
    });

    it('rejects bad prefix on decode', () => {
      const bogus = new Uint8Array(32);
      expect(() => decodeVaultDailyStatsKey(bogus)).toThrow(/prefix/);
    });

    it('encodes day_id as big-endian u64', () => {
      const key = encodeVaultDailyStatsKey(vault, 0x0102030405060708n);
      expect(Array.from(key.slice(24))).toEqual([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      ]);
    });
  });

  describe('value codec', () => {
    const sample: DayAggregate = {
      depositCount: 7,
      withdrawCount: 3,
      totalIn: 1_000_000_000_000_000_000n,
      totalOut: 500_000_000_000_000_000n,
      maxIn: 750_000_000_000_000_000n,
    };

    it('encodes 56 bytes total', () => {
      const bytes = encodeDayAggregate(sample);
      expect(bytes.length).toBe(VAULT_DAILY_STATS_VALUE_LEN);
      expect(bytes.length).toBe(56);
    });

    it('round-trips through decode', () => {
      const bytes = encodeDayAggregate(sample);
      const decoded = decodeDayAggregate(bytes);
      expect(decoded).toEqual(sample);
    });

    it('handles zero aggregate', () => {
      const zero: DayAggregate = {
        depositCount: 0,
        withdrawCount: 0,
        totalIn: 0n,
        totalOut: 0n,
        maxIn: 0n,
      };
      expect(decodeDayAggregate(encodeDayAggregate(zero))).toEqual(zero);
    });

    it('handles u128 max', () => {
      const max = (1n << 128n) - 1n;
      const big: DayAggregate = {
        depositCount: 0xffffffff,
        withdrawCount: 0xffffffff,
        totalIn: max,
        totalOut: max,
        maxIn: max,
      };
      expect(decodeDayAggregate(encodeDayAggregate(big))).toEqual(big);
    });

    it('rejects values that exceed u128 on encode', () => {
      const bad: DayAggregate = {
        depositCount: 0,
        withdrawCount: 0,
        totalIn: 1n << 128n,
        totalOut: 0n,
        maxIn: 0n,
      };
      expect(() => encodeDayAggregate(bad)).toThrow(/u128/);
    });

    it('rejects wrong-length values on decode', () => {
      expect(() => decodeDayAggregate(new Uint8Array(40))).toThrow(/56/);
    });
  });

  describe('decodeVaultDailyStatsRows', () => {
    const vault = new Uint8Array(20).fill(0xaa);
    const sample: DayAggregate = {
      depositCount: 1,
      withdrawCount: 0,
      totalIn: 1_000n,
      totalOut: 0n,
      maxIn: 1_000n,
    };

    it('decodes well-formed rows', () => {
      const key = encodeVaultDailyStatsKey(vault, 100n);
      const value = encodeDayAggregate(sample);
      const decoded = decodeVaultDailyStatsRows([
        { key, value },
      ]);
      expect(decoded).toHaveLength(1);
      expect(decoded[0].aggregate).toEqual(sample);
      expect(decoded[0].dayId).toBe(100n);
    });

    it('skips rows with non-aggregate value lengths', () => {
      const key = encodeVaultDailyStatsKey(vault, 100n);
      const value = encodeDayAggregate(sample);
      // Server returns empty value for non-Item GroveDB elements that
      // happen to fall in the range — not aggregates, must be skipped.
      const decoded = decodeVaultDailyStatsRows([
        { key, value: new Uint8Array(0) },
        { key, value },
        { key, value: new Uint8Array(10) },
      ]);
      expect(decoded).toHaveLength(1);
      expect(decoded[0].aggregate).toEqual(sample);
    });

    it('accepts plain arrays from JSON parsing', () => {
      const key = Array.from(encodeVaultDailyStatsKey(vault, 100n));
      const value = Array.from(encodeDayAggregate(sample));
      const decoded = decodeVaultDailyStatsRows([{ key, value }]);
      expect(decoded).toHaveLength(1);
      expect(decoded[0].aggregate).toEqual(sample);
    });
  });

  describe('vaultDayRangeKeys', () => {
    const vault = new Uint8Array(20).fill(0xcc);

    it('builds inclusive range keys', () => {
      const { fromKey, toKey } = vaultDayRangeKeys(vault, 100n, 110n);
      expect(decodeVaultDailyStatsKey(fromKey).dayId).toBe(100n);
      expect(decodeVaultDailyStatsKey(toKey).dayId).toBe(110n);
    });

    it('rejects inverted ranges', () => {
      expect(() => vaultDayRangeKeys(vault, 110n, 100n)).toThrow(
        />=/,
      );
    });

    it('allows single-day ranges', () => {
      const { fromKey, toKey } = vaultDayRangeKeys(vault, 100n, 100n);
      expect(Array.from(fromKey)).toEqual(Array.from(toKey));
    });
  });
});
