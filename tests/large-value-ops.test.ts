/**
 * Large-value merk ops (0x20..0x23, 0x28..0x2b).
 *
 * grovedb 3.1.0 writes a proof value's length as a u16, so a value of 64 KiB
 * or more could not be proven. The Willow GroveDB fork writes such values
 * with large-value ops (u32 length). The fixtures are real proofs from the
 * fork's prover: a 70,000-byte item (its merk op is 0x20) and a 65,530-byte
 * item whose 65,535-byte merk value is the largest a 3.1.0 op (0x03) carries.
 */
import * as fs from 'fs';
import * as path from 'path';

import {
  verifyGroveDBProof,
  decodeGroveDBProof,
  decodeMerkOps,
  hexToBytes,
  hashToHex,
  GroveDBVerificationError,
} from '../src/grovedb';
import { verifyItemProof } from '../src/proof';

interface LargeValueFixture {
  path: string[];
  key: string;
  value_len: number;
  element_len: number;
  item_opcode: number;
  proof_hex: string;
  expected_root_hex: string;
}

const load = (name: string): LargeValueFixture =>
  JSON.parse(
    fs.readFileSync(path.join(__dirname, 'fixtures', 'grovedb', `${name}.json`), 'utf8'),
  );

const katValue = (len: number): Uint8Array => {
  const v = new Uint8Array(len);
  for (let i = 0; i < len; i++) v[i] = (i * 7 + 3) % 256;
  return v;
};

const utf8 = (s: string) => new TextEncoder().encode(s);
const eq = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

function leafMerkProof(proofHex: string): Uint8Array {
  const proof = decodeGroveDBProof(hexToBytes(proofHex));
  let layer: any = proof.proof.rootLayer;
  for (const seg of ['apps', 'data']) {
    layer = layer.lowerLayers.get(Buffer.from(seg).toString('hex'));
    expect(layer).toBeDefined();
  }
  return layer.merkProof;
}

describe.each([
  ['large_value_item', 0x20],
  ['small_value_item', 0x03],
])('%s', (name, opcode) => {
  const f = load(name);

  it('carries the item in the expected op', () => {
    expect(f.item_opcode).toBe(opcode);
    const merk = leafMerkProof(f.proof_hex);
    const ops = decodeMerkOps(merk);
    const item = ops.find((op: any) => op.node && op.node.key && eq(op.node.key, utf8(f.key)));
    expect(item).toBeDefined();
    expect((item as any).node.type).toBe('KV');
    expect((item as any).node.value.length).toBe(f.element_len);
    // the op byte itself
    const keyBytes = utf8(f.key);
    const at = merk.findIndex(
      (b, i) => b === opcode && merk[i + 1] === keyBytes.length && eq(merk.slice(i + 2, i + 2 + keyBytes.length), keyBytes),
    );
    expect(at).toBeGreaterThanOrEqual(0);
  });

  it('verifies to the Rust root hash with the exact value', () => {
    const result = verifyGroveDBProof(hexToBytes(f.proof_hex));
    expect(hashToHex(result.rootHash)).toBe(f.expected_root_hex);
    const row = result.results.find((r) => eq(r.key, utf8(f.key)));
    expect(row).toBeDefined();
    const element = row!.value!;
    expect(element.length).toBe(f.element_len);
    // Item(value, None): [0x00, varint len, value, 0x00]
    expect(element[0]).toBe(0x00);
    expect(element[element.length - 1]).toBe(0x00);
    expect(eq(element.slice(element.length - 1 - f.value_len, element.length - 1), katValue(f.value_len))).toBe(true);
  });

  it('verifyItemProof (strict path binding) returns the Rust root hash', async () => {
    expect(await verifyItemProof(f.proof_hex, f.key, undefined, f.path)).toBe(f.expected_root_hex);
  });
});

describe('large-value op framing', () => {
  const kvLarge = (len: number, carried = len) => {
    const out = [0x20, 1, 0x6b, (len >>> 24) & 0xff, (len >>> 16) & 0xff, (len >>> 8) & 0xff, len & 0xff];
    return new Uint8Array([...out, ...new Array(carried).fill(9)]);
  };

  it('decodes every large-value op as the op it mirrors', () => {
    const v = 65536;
    const hash = new Array(32).fill(5);
    const lenBytes = [0, 1, 0, 0];
    const body = [1, 0x6b, ...lenBytes, ...new Array(v).fill(1)];
    const cases: Array<[number, string, string, number[]]> = [
      [0x20, 'Push', 'KV', []],
      [0x21, 'Push', 'KVValueHash', hash],
      [0x22, 'Push', 'KVRefValueHash', hash],
      [0x23, 'Push', 'KVValueHashFeatureType', [...hash, 0x00]],
      [0x28, 'PushInverted', 'KV', []],
      [0x29, 'PushInverted', 'KVValueHash', hash],
      [0x2a, 'PushInverted', 'KVRefValueHash', hash],
      [0x2b, 'PushInverted', 'KVValueHashFeatureType', [...hash, 0x00]],
    ];
    for (const [op, push, node, tail] of cases) {
      const [decoded] = decodeMerkOps(new Uint8Array([op, ...body, ...tail]));
      expect(decoded.type).toBe(push);
      expect((decoded as any).node.type).toBe(node);
      expect((decoded as any).node.value.length).toBe(v);
    }
  });

  it('refuses a large-value op carrying a value under 64 KiB', () => {
    expect(() => decodeMerkOps(kvLarge(100))).toThrow(GroveDBVerificationError);
    expect(() => decodeMerkOps(kvLarge(65535))).toThrow(/at least 65536/);
    expect(decodeMerkOps(kvLarge(65536))).toHaveLength(1);
  });

  it('refuses a declared length over 64 MiB, and truncation', () => {
    expect(() => decodeMerkOps(kvLarge(64 * 1024 * 1024 + 1, 0))).toThrow(/limit/);
    expect(() => decodeMerkOps(kvLarge(0xffffffff, 0))).toThrow(GroveDBVerificationError);
    expect(() => decodeMerkOps(kvLarge(70000, 69999))).toThrow(GroveDBVerificationError);
    expect(() => decodeMerkOps(new Uint8Array([0x21, 1, 0x6b, 0, 1]))).toThrow(/u32/);
  });

  it('leaves the unassigned opcodes unknown', () => {
    for (const op of [0x24, 0x25, 0x26, 0x27, 0x2c, 0x2d, 0x2e, 0x2f]) {
      expect(() => decodeMerkOps(new Uint8Array([op, 1, 0x6b, 0, 1, 0, 0]))).toThrow(/Unknown op code/);
    }
  });

  it('refuses every truncation of the large-value proof', () => {
    const full = hexToBytes(load('large_value_item').proof_hex);
    for (let len = 0; len < full.length; len += 997) {
      expect(() => verifyGroveDBProof(full.slice(0, len))).toThrow(GroveDBVerificationError);
    }
  });
});
