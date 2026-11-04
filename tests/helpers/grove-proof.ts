/**
 * Synthetic GroveDB state and proofs, built as grovedb 3.1.0 builds them:
 * each subtree a merk (a binary search tree of its keys, balanced here),
 * items as `KV` nodes, subtrees as `KVValueHash` nodes whose value hash is
 * `combine_hash(value_hash(element), subtree root)`, and a proof of a layer
 * revealing some keys, the nodes on their way as `KVHash`, and every other
 * subtree as a `Hash`.
 */
import {
  combineHash,
  kvDigestToKvHash,
  kvHash,
  nodeHash,
  valueHash,
  NULL_HASH,
} from '../../src/grovedb';

export const enc = (s: string): Uint8Array => new TextEncoder().encode(s);

/** A bincode 2 (big-endian config) unsigned varint, as grovedb writes lengths. */
export function varint(n: number): number[] {
  if (n < 251) return [n];
  if (n < 0x10000) return [251, n >> 8, n & 0xff];
  throw new Error('length too large for these fixtures');
}

/** `Element::Item(payload, None)`. */
export function itemElement(payload: Uint8Array): Uint8Array {
  return Uint8Array.from([0x00, ...varint(payload.length), ...payload, 0x00]);
}

/** `Element::Tree(rootKey, None)`. */
export function treeElement(rootKey: Uint8Array | null): Uint8Array {
  return rootKey
    ? Uint8Array.from([0x02, 0x01, ...varint(rootKey.length), ...rootKey, 0x00])
    : Uint8Array.from([0x02, 0x00, 0x00]);
}

const u16 = (n: number) => [n >> 8, n & 0xff];

export const op = {
  hash: (h: Uint8Array) => [0x01, ...h],
  kvHash: (h: Uint8Array) => [0x02, ...h],
  kv: (key: Uint8Array, value: Uint8Array) => [0x03, key.length, ...key, ...u16(value.length), ...value],
  kvValueHash: (key: Uint8Array, value: Uint8Array, vh: Uint8Array) => [
    0x04,
    key.length,
    ...key,
    ...u16(value.length),
    ...value,
    ...vh,
  ],
  kvDigest: (key: Uint8Array, vh: Uint8Array) => [0x05, key.length, ...key, ...vh],
  parent: 0x10,
  child: 0x11,
};

/** An entry of a merk: an item (its JSON text) or a subtree. */
export type Entry = { key: string; item: string } | { key: string; tree: Merk };

interface Node {
  entry: Entry;
  left: Node | null;
  right: Node | null;
}

/** A merk of `entries` (any order; sorted by key bytes), balanced. */
export class Merk {
  readonly root: Node | null;

  constructor(entries: Entry[]) {
    const sorted = [...entries].sort((a, b) => Buffer.compare(Buffer.from(enc(a.key)), Buffer.from(enc(b.key))));
    const build = (lo: number, hi: number): Node | null => {
      if (lo > hi) return null;
      const mid = (lo + hi) >> 1;
      return { entry: sorted[mid], left: build(lo, mid - 1), right: build(mid + 1, hi) };
    };
    this.root = build(0, sorted.length - 1);
  }

  rootHash(): Uint8Array {
    return this.root ? Merk.hashOf(this.root) : NULL_HASH;
  }

  rootKey(): Uint8Array | null {
    return this.root ? enc(this.root.entry.key) : null;
  }

  /** The element bytes an entry is stored as. */
  static element(entry: Entry): Uint8Array {
    return 'item' in entry ? itemElement(enc(entry.item)) : treeElement(entry.tree.rootKey());
  }

  /** A subtree entry's value hash: combine_hash(value_hash(element), its root). */
  static layeredValueHash(entry: Entry & { tree: Merk }): Uint8Array {
    return combineHash(valueHash(Merk.element(entry)), entry.tree.rootHash());
  }

  private static kvHashOf(entry: Entry): Uint8Array {
    const key = enc(entry.key);
    return 'item' in entry
      ? kvHash(key, Merk.element(entry))
      : kvDigestToKvHash(key, Merk.layeredValueHash(entry));
  }

  private static hashOf(node: Node): Uint8Array {
    return nodeHash(
      Merk.kvHashOf(node.entry),
      node.left ? Merk.hashOf(node.left) : NULL_HASH,
      node.right ? Merk.hashOf(node.right) : NULL_HASH,
    );
  }

  /** The entry at `key`, if any. */
  get(key: string): Entry | undefined {
    let node = this.root;
    while (node) {
      const c = Buffer.compare(Buffer.from(enc(key)), Buffer.from(enc(node.entry.key)));
      if (c === 0) return node.entry;
      node = c < 0 ? node.left : node.right;
    }
    return undefined;
  }

  /**
   * A merk proof revealing the keys in `reveal` (items as KV, subtrees as
   * KVValueHash): every subtree with no revealed key is one Hash node, and
   * every unrevealed node above a revealed one a KVHash node.
   */
  prove(reveal: string[]): Uint8Array {
    const shows = (node: Node | null): boolean =>
      !!node && (reveal.includes(node.entry.key) || shows(node.left) || shows(node.right));
    const ops = (node: Node): number[] => {
      if (!shows(node)) return op.hash(Merk.hashOf(node));
      const out: number[] = [];
      if (node.left) out.push(...ops(node.left));
      const { entry } = node;
      const key = enc(entry.key);
      if (!reveal.includes(entry.key)) out.push(...op.kvHash(Merk.kvHashOf(entry)));
      else if ('item' in entry) out.push(...op.kv(key, Merk.element(entry)));
      else out.push(...op.kvValueHash(key, Merk.element(entry), Merk.layeredValueHash(entry)));
      if (node.left) out.push(op.parent);
      if (node.right) out.push(...ops(node.right), op.child);
      return out;
    };
    if (!this.root) throw new Error('an empty merk has no proof');
    return Uint8Array.from(ops(this.root));
  }
}

/** One layer of a GroveDB proof: a merk proof and the layers under its keys. */
export interface LayerProof {
  merk: Uint8Array;
  lower?: Array<[string | Uint8Array, LayerProof]>;
}

function encodeLayer(layer: LayerProof): number[] {
  const lower = layer.lower ?? [];
  return [
    ...varint(layer.merk.length),
    ...layer.merk,
    ...varint(lower.length),
    ...lower.flatMap(([key, sub]) => {
      const k = typeof key === 'string' ? enc(key) : key;
      return [...varint(k.length), ...k, ...encodeLayer(sub)];
    }),
  ];
}

/** A `GroveDBProof::V0` with the chain's prove options. */
export function groveProof(root: LayerProof): Uint8Array {
  return Uint8Array.from([0x00, ...encodeLayer(root), 0x01]);
}

/**
 * The layer proof of a query along `path` in `merk`, revealing `reveal` at
 * the end of the path (each layer above it reveals only its path segment).
 */
export function pathProof(merk: Merk, path: string[], reveal: string[]): LayerProof {
  if (path.length === 0) return { merk: merk.prove(reveal) };
  const [segment, ...rest] = path;
  const entry = merk.get(segment);
  if (!entry || !('tree' in entry)) throw new Error(`no subtree at ${segment}`);
  const lower: LayerProof['lower'] = entry.tree.root ? [[segment, pathProof(entry.tree, rest, reveal)]] : [];
  return { merk: merk.prove([segment]), lower };
}

export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
