/**
 * GroveDB Proof Verification Tests
 *
 * Tests for the TypeScript GroveDB proof verification implementation.
 */

import {
  encodeVarint,
  decodeVarint,
  decodeSignedVarint64,
  decodeVarint64
} from '../src/grovedb/varint';
import {
  blake3Hash,
  valueHash,
  kvHash,
  kvDigestToKvHash,
  nodeHash,
  combineHash,
  hashEquals,
  hashToHex
} from '../src/grovedb/hash';
import { MerkDecoder, decodeMerkOps } from '../src/grovedb/merk-decoder';
import { executeOps, executeMerkProof, executeMerkProofWithQuery } from '../src/grovedb/executor';
import { Tree } from '../src/grovedb/tree';
import { BincodeReader, bytesToHex, hexToBytes } from '../src/grovedb/bincode';
import { HASH_LENGTH, NULL_HASH } from '../src/grovedb/types';

describe('Varint', () => {
  describe('encodeVarint', () => {
    it('encodes small values', () => {
      expect(encodeVarint(0)).toEqual(new Uint8Array([0]));
      expect(encodeVarint(1)).toEqual(new Uint8Array([1]));
      expect(encodeVarint(127)).toEqual(new Uint8Array([127]));
    });

    it('encodes values requiring multiple bytes', () => {
      expect(encodeVarint(128)).toEqual(new Uint8Array([0x80, 0x01]));
      expect(encodeVarint(300)).toEqual(new Uint8Array([0xac, 0x02]));
      expect(encodeVarint(16384)).toEqual(new Uint8Array([0x80, 0x80, 0x01]));
    });
  });

  describe('decodeVarint', () => {
    it('decodes small values', () => {
      expect(decodeVarint(new Uint8Array([0]))).toEqual({ value: 0, bytesRead: 1 });
      expect(decodeVarint(new Uint8Array([1]))).toEqual({ value: 1, bytesRead: 1 });
      expect(decodeVarint(new Uint8Array([127]))).toEqual({ value: 127, bytesRead: 1 });
    });

    it('decodes multi-byte values', () => {
      expect(decodeVarint(new Uint8Array([0x80, 0x01]))).toEqual({ value: 128, bytesRead: 2 });
      expect(decodeVarint(new Uint8Array([0xac, 0x02]))).toEqual({ value: 300, bytesRead: 2 });
    });

    it('decodes from offset', () => {
      const bytes = new Uint8Array([0xff, 0xff, 0x80, 0x01]);
      expect(decodeVarint(bytes, 2)).toEqual({ value: 128, bytesRead: 2 });
    });

    it('round-trips correctly', () => {
      for (const value of [0, 1, 127, 128, 300, 16384, 1000000]) {
        const encoded = encodeVarint(value);
        const decoded = decodeVarint(encoded);
        expect(decoded.value).toBe(value);
        expect(decoded.bytesRead).toBe(encoded.length);
      }
    });
  });

  describe('decodeSignedVarint64', () => {
    it('decodes positive values', () => {
      // Zigzag: 0 -> 0, 2 -> 1, 4 -> 2
      expect(decodeSignedVarint64(new Uint8Array([0]))).toEqual({ value: 0n, bytesRead: 1 });
      expect(decodeSignedVarint64(new Uint8Array([2]))).toEqual({ value: 1n, bytesRead: 1 });
      expect(decodeSignedVarint64(new Uint8Array([4]))).toEqual({ value: 2n, bytesRead: 1 });
    });

    it('decodes negative values', () => {
      // Zigzag: 1 -> -1, 3 -> -2
      expect(decodeSignedVarint64(new Uint8Array([1]))).toEqual({ value: -1n, bytesRead: 1 });
      expect(decodeSignedVarint64(new Uint8Array([3]))).toEqual({ value: -2n, bytesRead: 1 });
    });
  });
});

describe('Hash Functions', () => {
  describe('blake3Hash', () => {
    it('produces 32-byte hashes', () => {
      const hash = blake3Hash(new Uint8Array([1, 2, 3]));
      expect(hash.length).toBe(32);
    });

    it('produces different hashes for different inputs', () => {
      const hash1 = blake3Hash(new Uint8Array([1, 2, 3]));
      const hash2 = blake3Hash(new Uint8Array([1, 2, 4]));
      expect(hashEquals(hash1, hash2)).toBe(false);
    });

    it('produces same hash for same input', () => {
      const hash1 = blake3Hash(new Uint8Array([1, 2, 3]));
      const hash2 = blake3Hash(new Uint8Array([1, 2, 3]));
      expect(hashEquals(hash1, hash2)).toBe(true);
    });
  });

  describe('valueHash', () => {
    it('hashes value with length prefix', () => {
      const hash = valueHash(new Uint8Array([1, 2, 3]));
      expect(hash.length).toBe(32);
    });

    it('empty value produces valid hash', () => {
      const hash = valueHash(new Uint8Array([]));
      expect(hash.length).toBe(32);
    });
  });

  describe('kvHash', () => {
    it('hashes key and value', () => {
      const hash = kvHash(
        new Uint8Array([1, 2, 3]),
        new Uint8Array([4, 5, 6])
      );
      expect(hash.length).toBe(32);
    });
  });

  describe('nodeHash', () => {
    it('combines kv hash with children', () => {
      const kv = blake3Hash(new Uint8Array([1]));
      const left = blake3Hash(new Uint8Array([2]));
      const right = blake3Hash(new Uint8Array([3]));
      const hash = nodeHash(kv, left, right);
      expect(hash.length).toBe(32);
    });

    it('null children produce different hash', () => {
      const kv = blake3Hash(new Uint8Array([1]));
      const left = blake3Hash(new Uint8Array([2]));
      const right = blake3Hash(new Uint8Array([3]));

      const hash1 = nodeHash(kv, left, right);
      const hash2 = nodeHash(kv, NULL_HASH, right);
      expect(hashEquals(hash1, hash2)).toBe(false);
    });
  });

  describe('combineHash', () => {
    it('combines two hashes', () => {
      const a = blake3Hash(new Uint8Array([1]));
      const b = blake3Hash(new Uint8Array([2]));
      const combined = combineHash(a, b);
      expect(combined.length).toBe(32);
    });

    it('order matters', () => {
      const a = blake3Hash(new Uint8Array([1]));
      const b = blake3Hash(new Uint8Array([2]));
      const ab = combineHash(a, b);
      const ba = combineHash(b, a);
      expect(hashEquals(ab, ba)).toBe(false);
    });
  });

  describe('hashEquals', () => {
    it('returns true for equal hashes', () => {
      const a = new Uint8Array(32).fill(42);
      const b = new Uint8Array(32).fill(42);
      expect(hashEquals(a, b)).toBe(true);
    });

    it('returns false for different hashes', () => {
      const a = new Uint8Array(32).fill(42);
      const b = new Uint8Array(32).fill(43);
      expect(hashEquals(a, b)).toBe(false);
    });

    it('returns false for different lengths', () => {
      const a = new Uint8Array(32).fill(42);
      const b = new Uint8Array(31).fill(42);
      expect(hashEquals(a, b)).toBe(false);
    });
  });
});

describe('Merk Decoder', () => {
  describe('basic operations', () => {
    it('decodes Parent op', () => {
      const ops = decodeMerkOps(new Uint8Array([0x10]));
      expect(ops).toEqual([{ type: 'Parent' }]);
    });

    it('decodes Child op', () => {
      const ops = decodeMerkOps(new Uint8Array([0x11]));
      expect(ops).toEqual([{ type: 'Child' }]);
    });

    it('decodes ParentInverted op', () => {
      const ops = decodeMerkOps(new Uint8Array([0x12]));
      expect(ops).toEqual([{ type: 'ParentInverted' }]);
    });

    it('decodes ChildInverted op', () => {
      const ops = decodeMerkOps(new Uint8Array([0x13]));
      expect(ops).toEqual([{ type: 'ChildInverted' }]);
    });
  });

  describe('Push operations', () => {
    it('decodes Push(Hash)', () => {
      const hashBytes = new Uint8Array(32).fill(123);
      const bytes = new Uint8Array([0x01, ...hashBytes]);
      const ops = decodeMerkOps(bytes);

      expect(ops.length).toBe(1);
      expect(ops[0].type).toBe('Push');
      if (ops[0].type === 'Push') {
        expect(ops[0].node.type).toBe('Hash');
        if (ops[0].node.type === 'Hash') {
          expect(ops[0].node.hash).toEqual(hashBytes);
        }
      }
    });

    it('decodes Push(KVHash)', () => {
      const kvHashBytes = new Uint8Array(32).fill(123);
      const bytes = new Uint8Array([0x02, ...kvHashBytes]);
      const ops = decodeMerkOps(bytes);

      expect(ops.length).toBe(1);
      expect(ops[0].type).toBe('Push');
      if (ops[0].type === 'Push') {
        expect(ops[0].node.type).toBe('KVHash');
      }
    });

    it('decodes Push(KV)', () => {
      // 0x03, key_len=3, key=[1,2,3], value_len=3 (big-endian u16), value=[4,5,6]
      const bytes = new Uint8Array([0x03, 3, 1, 2, 3, 0, 3, 4, 5, 6]);
      const ops = decodeMerkOps(bytes);

      expect(ops.length).toBe(1);
      expect(ops[0].type).toBe('Push');
      if (ops[0].type === 'Push' && ops[0].node.type === 'KV') {
        expect(ops[0].node.key).toEqual(new Uint8Array([1, 2, 3]));
        expect(ops[0].node.value).toEqual(new Uint8Array([4, 5, 6]));
      }
    });

    it('decodes Push(KVDigest)', () => {
      const hash = new Uint8Array(32).fill(123);
      const bytes = new Uint8Array([0x05, 3, 1, 2, 3, ...hash]);
      const ops = decodeMerkOps(bytes);

      expect(ops.length).toBe(1);
      expect(ops[0].type).toBe('Push');
      if (ops[0].type === 'Push' && ops[0].node.type === 'KVDigest') {
        expect(ops[0].node.key).toEqual(new Uint8Array([1, 2, 3]));
        expect(ops[0].node.valueHash).toEqual(hash);
      }
    });
  });

  describe('multiple operations', () => {
    it('decodes sequence of ops', () => {
      const bytes = new Uint8Array([0x11, 0x11, 0x11, 0x10]);
      const ops = decodeMerkOps(bytes);

      expect(ops).toEqual([
        { type: 'Child' },
        { type: 'Child' },
        { type: 'Child' },
        { type: 'Parent' }
      ]);
    });
  });

  describe('error handling', () => {
    it('throws on unknown op code', () => {
      expect(() => decodeMerkOps(new Uint8Array([0x88]))).toThrow('Unknown op code');
    });
  });
});

describe('Executor', () => {
  describe('executeOps', () => {
    it('executes single Push', () => {
      const ops = [{ type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([2]) } }];
      const tree = executeOps(ops, false);

      expect(tree.node.type).toBe('KV');
      expect(tree.left).toBeNull();
      expect(tree.right).toBeNull();
    });

    it('executes Push + Push + Parent (left child)', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Parent' as const }
      ];
      const tree = executeOps(ops, false);

      expect(tree.node.type).toBe('KV');
      if (tree.node.type === 'KV') {
        expect(tree.node.key).toEqual(new Uint8Array([2]));
      }
      expect(tree.left).not.toBeNull();
      expect(tree.right).toBeNull();
    });

    it('executes Push + Push + Child (right child)', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Child' as const }
      ];
      const tree = executeOps(ops, false);

      expect(tree.node.type).toBe('KV');
      if (tree.node.type === 'KV') {
        expect(tree.node.key).toEqual(new Uint8Array([1]));
      }
      expect(tree.left).toBeNull();
      expect(tree.right).not.toBeNull();
    });

    it('builds balanced 3-node tree', () => {
      // Create: Push(1), Push(2), Parent, Push(3), Child
      // Result: 2 as root, 1 as left, 3 as right
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Parent' as const },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([3]), value: new Uint8Array([3]) } },
        { type: 'Child' as const }
      ];
      const tree = executeOps(ops, false);

      expect(tree.node.type).toBe('KV');
      if (tree.node.type === 'KV') {
        expect(tree.node.key).toEqual(new Uint8Array([2]));
      }
      expect(tree.left?.tree.getKey()).toEqual(new Uint8Array([1]));
      expect(tree.right?.tree.getKey()).toEqual(new Uint8Array([3]));
    });

    it('throws on stack underflow', () => {
      const ops = [{ type: 'Parent' as const }];
      expect(() => executeOps(ops)).toThrow('Stack underflow');
    });

    it('throws on multiple items left on stack', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } }
      ];
      expect(() => executeOps(ops)).toThrow('exactly one stack item');
    });

    it('throws on incorrect key ordering', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Parent' as const }
      ];
      expect(() => executeOps(ops)).toThrow('Incorrect key ordering');
    });

    it('accepts an unbalanced reconstruction (partial proofs are legitimately unbalanced)', () => {
      // A query proof is a *partial* reconstruction, so the result is often not
      // AVL-balanced (sibling subtrees collapse to height-0 hash nodes). We no
      // longer reject on imbalance — integrity comes from the root-hash
      // recomputation, not the AVL property. (Tree: 1 -> 2 -> 3, all right.)
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Parent' as const },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([3]), value: new Uint8Array([3]) } },
        { type: 'Parent' as const }
      ];
      expect(() => executeOps(ops)).not.toThrow();
    });
  });

  describe('tree hashing', () => {
    it('produces consistent hash for same tree', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Parent' as const },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([3]), value: new Uint8Array([3]) } },
        { type: 'Child' as const }
      ];

      const tree1 = executeOps(ops, false);
      const tree2 = executeOps(ops, false);

      expect(hashEquals(tree1.hash(), tree2.hash())).toBe(true);
    });

    it('collapsed tree has same hash as full tree', () => {
      const ops = [
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([1]), value: new Uint8Array([1]) } },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([2]), value: new Uint8Array([2]) } },
        { type: 'Parent' as const },
        { type: 'Push' as const, node: { type: 'KV' as const, key: new Uint8Array([3]), value: new Uint8Array([3]) } },
        { type: 'Child' as const }
      ];

      const fullTree = executeOps(ops, false);
      const collapsedTree = executeOps(ops, true);

      expect(hashEquals(fullTree.hash(), collapsedTree.hash())).toBe(true);
    });
  });
});

describe('BincodeReader (bincode 2)', () => {
  it('reads u8', () => {
    const reader = new BincodeReader(new Uint8Array([0x42]));
    expect(reader.readU8()).toBe(0x42);
  });

  describe('readVarintU128', () => {
    it('decodes single-byte values (0..=250)', () => {
      expect(new BincodeReader(new Uint8Array([0])).readVarintU128()).toBe(0n);
      expect(new BincodeReader(new Uint8Array([1])).readVarintU128()).toBe(1n);
      expect(new BincodeReader(new Uint8Array([250])).readVarintU128()).toBe(250n);
    });

    it('decodes 3-byte u16 form (tag 0xFB + 2 bytes BE)', () => {
      // 300 → tag + u16 BE(300) = [0xFB, 0x01, 0x2c]
      expect(
        new BincodeReader(new Uint8Array([0xfb, 0x01, 0x2c])).readVarintU128(),
      ).toBe(300n);
      // 65535 → [0xFB, 0xFF, 0xFF]
      expect(
        new BincodeReader(new Uint8Array([0xfb, 0xff, 0xff])).readVarintU128(),
      ).toBe(65535n);
    });

    it('decodes 5-byte u32 form (tag 0xFC + 4 bytes BE)', () => {
      // 65536 → [0xFC, 0x00, 0x01, 0x00, 0x00]
      expect(
        new BincodeReader(
          new Uint8Array([0xfc, 0x00, 0x01, 0x00, 0x00]),
        ).readVarintU128(),
      ).toBe(65536n);
    });

    it('decodes 9-byte u64 form (tag 0xFD + 8 bytes BE)', () => {
      // 5_000_000_000 → [0xFD, 0, 0, 0, 1, 0x2A, 0x05, 0xF2, 0x00]
      const bytes = new Uint8Array([
        0xfd, 0x00, 0x00, 0x00, 0x01, 0x2a, 0x05, 0xf2, 0x00,
      ]);
      expect(new BincodeReader(bytes).readVarintU128()).toBe(5_000_000_000n);
    });

    it('throws on unknown varint tag', () => {
      expect(() =>
        new BincodeReader(new Uint8Array([0xff])).readVarintU128(),
      ).toThrow(/Unknown varint tag/);
    });
  });

  describe('readVarintI64 (zigzag)', () => {
    it('decodes 0', () => {
      // zigzag(0) = 0
      expect(new BincodeReader(new Uint8Array([0])).readVarintI64()).toBe(0n);
    });

    it('decodes small positives', () => {
      // zigzag(5) = 10
      expect(new BincodeReader(new Uint8Array([10])).readVarintI64()).toBe(5n);
      // zigzag(1) = 2
      expect(new BincodeReader(new Uint8Array([2])).readVarintI64()).toBe(1n);
    });

    it('decodes small negatives', () => {
      // zigzag(-1) = 1
      expect(new BincodeReader(new Uint8Array([1])).readVarintI64()).toBe(-1n);
      // zigzag(-5) = 9
      expect(new BincodeReader(new Uint8Array([9])).readVarintI64()).toBe(-5n);
    });
  });

  describe('readByteVec', () => {
    it('reads length-prefixed bytes with varint length', () => {
      // length 3 + bytes [a,b,c]
      const reader = new BincodeReader(new Uint8Array([3, 0x61, 0x62, 0x63]));
      const bytes = reader.readByteVec();
      expect(Array.from(bytes)).toEqual([0x61, 0x62, 0x63]);
    });

    it('reads empty byte vec (length 0)', () => {
      const reader = new BincodeReader(new Uint8Array([0]));
      const bytes = reader.readByteVec();
      expect(bytes.length).toBe(0);
    });
  });

  describe('readOptionByteVec', () => {
    it('reads None (tag 0)', () => {
      expect(new BincodeReader(new Uint8Array([0])).readOptionByteVec()).toBeNull();
    });

    it('reads Some(bytes) (tag 1 + varint length + bytes)', () => {
      const reader = new BincodeReader(new Uint8Array([1, 2, 0xaa, 0xbb]));
      const bytes = reader.readOptionByteVec();
      expect(bytes).not.toBeNull();
      expect(Array.from(bytes!)).toEqual([0xaa, 0xbb]);
    });

    it('throws on invalid Option tag', () => {
      expect(() =>
        new BincodeReader(new Uint8Array([2])).readOptionByteVec(),
      ).toThrow(/Invalid Option tag/);
    });
  });

  it('reads boolean', () => {
    const reader = new BincodeReader(new Uint8Array([0, 1]));
    expect(reader.readBool()).toBe(false);
    expect(reader.readBool()).toBe(true);
  });

  it('throws on invalid boolean', () => {
    const reader = new BincodeReader(new Uint8Array([2]));
    expect(() => reader.readBool()).toThrow(/Invalid bool tag/);
  });
});

describe('Utility functions', () => {
  describe('bytesToHex', () => {
    it('converts empty array', () => {
      expect(bytesToHex(new Uint8Array([]))).toBe('');
    });

    it('converts bytes to hex', () => {
      expect(bytesToHex(new Uint8Array([0, 1, 15, 255]))).toBe('00010fff');
    });
  });

  describe('hexToBytes', () => {
    it('converts hex to bytes', () => {
      expect(hexToBytes('00010fff')).toEqual(new Uint8Array([0, 1, 15, 255]));
    });

    it('handles 0x prefix', () => {
      expect(hexToBytes('0x00010fff')).toEqual(new Uint8Array([0, 1, 15, 255]));
    });
  });

  describe('round-trip', () => {
    it('bytesToHex and hexToBytes are inverses', () => {
      const original = new Uint8Array([0, 1, 128, 255, 16, 32]);
      const hex = bytesToHex(original);
      const back = hexToBytes(hex);
      expect(back).toEqual(original);
    });
  });
});
