import {
  canonicalEventSetHash,
  canonicalEventSetHashHex,
  verifyServedEvents,
} from "../src/completeness";
import type { Log } from "../src/completeness";

/** Build an `n`-byte array filled with `byte`. */
function repeat(byte: number, n: number): Uint8Array {
  return new Uint8Array(n).fill(byte);
}

// Cross-language correctness gate. These vectors are authoritative and must
// match Willow's on-chain `canonical_event_set_hash` byte-for-byte.
const VECTOR_A_HASH =
  "0x52089e4c924fbab0475d310d7f74bf8cae542d006a45d3c5d94adacda6937da5";
const VECTOR_B_HASH =
  "0xe1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd";

// Vector B: block 7, two matched logs.
const VECTOR_B_LOGS: Log[] = [
  {
    address: repeat(0x42, 20),
    topics: [repeat(0xdd, 32), repeat(0x11, 32)],
    data: new Uint8Array([0x01, 0x02, 0x03, 0x04]),
  },
  {
    address: repeat(0x43, 20),
    topics: [repeat(0xaa, 32)],
    data: new Uint8Array(),
  },
];

describe("canonicalEventSetHash", () => {
  it("vector A: empty set at block 0", () => {
    expect(canonicalEventSetHashHex(0, [])).toBe(VECTOR_A_HASH);
  });

  it("vector B: two logs at block 7", () => {
    expect(canonicalEventSetHashHex(7, VECTOR_B_LOGS)).toBe(VECTOR_B_HASH);
  });

  it("returns 32 raw bytes", () => {
    const h = canonicalEventSetHash(0, []);
    expect(h).toBeInstanceOf(Uint8Array);
    expect(h.length).toBe(32);
  });

  it("accepts hex-string log fields equivalently to Uint8Array", () => {
    const hexLogs: Log[] = [
      {
        address: "0x" + "42".repeat(20),
        topics: ["0x" + "dd".repeat(32), "0x" + "11".repeat(32)],
        data: "0x01020304",
      },
      {
        address: "0x" + "43".repeat(20),
        topics: ["0x" + "aa".repeat(32)],
        data: "0x",
      },
    ];
    expect(canonicalEventSetHashHex(7, hexLogs)).toBe(VECTOR_B_HASH);
  });

  it("accepts bigint block numbers", () => {
    expect(canonicalEventSetHashHex(7n, VECTOR_B_LOGS)).toBe(VECTOR_B_HASH);
  });

  it("rejects a wrong-length address", () => {
    expect(() =>
      canonicalEventSetHash(7, [
        { address: repeat(0x42, 19), topics: [], data: new Uint8Array() },
      ]),
    ).toThrow(/log.address must be exactly 20 bytes/);
  });

  it("rejects a wrong-length topic", () => {
    expect(() =>
      canonicalEventSetHash(7, [
        {
          address: repeat(0x42, 20),
          topics: [repeat(0xdd, 31)],
          data: new Uint8Array(),
        },
      ]),
    ).toThrow(/log.topic must be exactly 32 bytes/);
  });
});

describe("verifyServedEvents", () => {
  it("accepts the exact committed set (vector A)", () => {
    expect(verifyServedEvents(VECTOR_A_HASH, 0, [])).toBe(true);
  });

  it("accepts the exact committed set (vector B)", () => {
    expect(verifyServedEvents(VECTOR_B_HASH, 7, VECTOR_B_LOGS)).toBe(true);
  });

  it("accepts a raw 32-byte commitment", () => {
    const commitment = canonicalEventSetHash(7, VECTOR_B_LOGS);
    expect(verifyServedEvents(commitment, 7, VECTOR_B_LOGS)).toBe(true);
  });

  it("rejects a changed block number", () => {
    expect(verifyServedEvents(VECTOR_B_HASH, 8, VECTOR_B_LOGS)).toBe(false);
  });

  it("rejects a dropped log", () => {
    expect(verifyServedEvents(VECTOR_B_HASH, 7, [VECTOR_B_LOGS[0]])).toBe(
      false,
    );
  });

  it("rejects an added log", () => {
    const extra: Log = {
      address: repeat(0x44, 20),
      topics: [],
      data: new Uint8Array(),
    };
    expect(
      verifyServedEvents(VECTOR_B_HASH, 7, [...VECTOR_B_LOGS, extra]),
    ).toBe(false);
  });

  it("rejects a mutated log (flipped data byte)", () => {
    const tampered: Log[] = [
      { ...VECTOR_B_LOGS[0], data: new Uint8Array([0x01, 0x02, 0x03, 0x05]) },
      VECTOR_B_LOGS[1],
    ];
    expect(verifyServedEvents(VECTOR_B_HASH, 7, tampered)).toBe(false);
  });

  it("rejects reordered logs", () => {
    const reordered = [VECTOR_B_LOGS[1], VECTOR_B_LOGS[0]];
    expect(verifyServedEvents(VECTOR_B_HASH, 7, reordered)).toBe(false);
  });

  it("rejects a wrong-length commitment", () => {
    expect(() => verifyServedEvents(repeat(0, 31), 0, [])).toThrow(
      /commitment must be exactly 32 bytes/,
    );
  });
});
