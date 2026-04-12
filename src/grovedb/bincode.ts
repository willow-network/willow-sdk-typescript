/**
 * Bincode 2 reader + hex helpers.
 *
 * Implements the wire format used by `bincode = "2.0.0-rc.3"` with
 * `config::standard().with_big_endian().with_no_limit()`. This is the format
 * grovedb 3.1.0 uses for both `GroveDBProof` (emitted by `prove_query`) and
 * `Element` (stored as Merk leaf values).
 *
 * Wire format summary (from bincode-2.0.0-rc.3/src/varint/encode_unsigned.rs
 * and encode_signed.rs):
 *
 *   Unsigned varint (big-endian):
 *     0..=250           → 1 byte  (value as u8)
 *     251..=65535       → 1 byte tag 0xFB + u16 BE
 *     65536..=2^32-1    → 1 byte tag 0xFC + u32 BE
 *     2^32..=2^64-1     → 1 byte tag 0xFD + u64 BE
 *     2^64..=2^128-1    → 1 byte tag 0xFE + u128 BE
 *
 *   Signed varint: zigzag-encode first, then unsigned varint.
 *     zigzag_i64(n)  = (n << 1) ^ (n >> 63)
 *     zigzag_i128(n) = (n << 1) ^ (n >> 127)
 *
 *   Enum variant: u32-as-varint (so V0 is 0x00)
 *   Vec<u8>/String: usize-as-varint (u64 form) + bytes
 *   BTreeMap / Vec<T>: length-as-varint + entries
 *   Option<T>: 1 byte tag (0=None, 1=Some) + T
 *   bool: 1 byte (0 or 1)
 *   Structs: fields in declaration order, no length prefix
 */

import { GroveDBVerificationError } from './types';

const U16_TAG = 0xfb;
const U32_TAG = 0xfc;
const U64_TAG = 0xfd;
const U128_TAG = 0xfe;

export class BincodeReader {
  private view: DataView;
  private offset: number;

  constructor(private readonly data: Uint8Array) {
    this.view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    this.offset = 0;
  }

  position(): number {
    return this.offset;
  }

  remaining(): number {
    return this.data.length - this.offset;
  }

  hasMore(): boolean {
    return this.offset < this.data.length;
  }

  private requireBytes(n: number, context: string): void {
    if (this.offset + n > this.data.length) {
      throw new GroveDBVerificationError(
        `${context}: need ${n} bytes at offset ${this.offset}, only ${
          this.data.length - this.offset
        } remaining`,
      );
    }
  }

  readU8(): number {
    this.requireBytes(1, 'readU8');
    return this.data[this.offset++];
  }

  readBool(): boolean {
    const b = this.readU8();
    if (b === 0) return false;
    if (b === 1) return true;
    throw new GroveDBVerificationError(
      `Invalid bool tag ${b} at offset ${this.offset - 1}`,
    );
  }

  /**
   * Read a variable-length unsigned integer. Returns a bigint since the wire
   * format supports up to u128.
   */
  readVarintU128(): bigint {
    this.requireBytes(1, 'readVarint tag');
    const tag = this.data[this.offset++];

    if (tag <= 250) return BigInt(tag);

    if (tag === U16_TAG) {
      this.requireBytes(2, 'readVarint U16');
      const v = this.view.getUint16(this.offset, false);
      this.offset += 2;
      return BigInt(v);
    }

    if (tag === U32_TAG) {
      this.requireBytes(4, 'readVarint U32');
      const v = this.view.getUint32(this.offset, false);
      this.offset += 4;
      return BigInt(v);
    }

    if (tag === U64_TAG) {
      this.requireBytes(8, 'readVarint U64');
      const hi = this.view.getUint32(this.offset, false);
      const lo = this.view.getUint32(this.offset + 4, false);
      this.offset += 8;
      return (BigInt(hi) << 32n) | BigInt(lo);
    }

    if (tag === U128_TAG) {
      this.requireBytes(16, 'readVarint U128');
      let v = 0n;
      for (let i = 0; i < 16; i++) {
        v = (v << 8n) | BigInt(this.data[this.offset + i]);
      }
      this.offset += 16;
      return v;
    }

    throw new GroveDBVerificationError(
      `Unknown varint tag 0x${tag.toString(16)} at offset ${this.offset - 1}`,
    );
  }

  /**
   * Read a varint as bigint (u64-range).
   */
  readVarintU64(): bigint {
    return this.readVarintU128();
  }

  /**
   * Read a varint that is expected to fit in a JS Number (<= 2^53-1).
   */
  readVarintAsNumber(): number {
    const big = this.readVarintU128();
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new GroveDBVerificationError(
        `Varint value ${big} exceeds Number.MAX_SAFE_INTEGER`,
      );
    }
    return Number(big);
  }

  /**
   * Read a zigzag-encoded signed i64 varint.
   *
   * zigzag_decode(v) = (v >> 1) ^ -(v & 1)
   */
  readVarintI64(): bigint {
    const u = this.readVarintU128();
    return (u >> 1n) ^ -(u & 1n);
  }

  /**
   * Read a zigzag-encoded signed i128 varint.
   */
  readVarintI128(): bigint {
    const u = this.readVarintU128();
    return (u >> 1n) ^ -(u & 1n);
  }

  /**
   * Read an enum variant tag. In bincode 2, enum discriminants are encoded as
   * u32-as-varint.
   */
  readVariant(): number {
    return this.readVarintAsNumber();
  }

  /**
   * Read a Vec<u8> or any length-prefixed byte sequence.
   */
  readByteVec(): Uint8Array {
    const len = this.readVarintAsNumber();
    this.requireBytes(len, 'readByteVec body');
    const out = this.data.slice(this.offset, this.offset + len);
    this.offset += len;
    return out;
  }

  /**
   * Read a sequence length prefix (for Vec<T>, BTreeMap, etc).
   */
  readLength(): number {
    return this.readVarintAsNumber();
  }

  /**
   * Read `Option<Vec<u8>>`: 1 byte tag + optional bytes.
   */
  readOptionByteVec(): Uint8Array | null {
    const tag = this.readU8();
    if (tag === 0) return null;
    if (tag === 1) return this.readByteVec();
    throw new GroveDBVerificationError(
      `Invalid Option tag ${tag} at offset ${this.offset - 1}`,
    );
  }

  /**
   * Read `Option<u8>`: 1 byte tag + optional single byte.
   */
  readOptionU8(): number | null {
    const tag = this.readU8();
    if (tag === 0) return null;
    if (tag === 1) return this.readU8();
    throw new GroveDBVerificationError(
      `Invalid Option tag ${tag} at offset ${this.offset - 1}`,
    );
  }

  /**
   * Read `Vec<Vec<u8>>` (length + repeated byte vecs).
   */
  readVecOfByteVec(): Uint8Array[] {
    const len = this.readLength();
    const out: Uint8Array[] = [];
    for (let i = 0; i < len; i++) out.push(this.readByteVec());
    return out;
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return bytes;
}
