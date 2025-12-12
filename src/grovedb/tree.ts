/**
 * Merk Tree Data Structure
 *
 * Represents the tree structure built during proof execution.
 */

import { MerkNode, CryptoHash, NULL_HASH, GroveDBVerificationError } from './types';
import { kvHash, kvDigestToKvHash, nodeHash, valueHash, combineHash } from './hash';

/**
 * Child node with cached hash
 */
export interface Child {
  tree: Tree;
  hash: CryptoHash;
}

/**
 * Binary tree for proof verification
 */
export class Tree {
  node: MerkNode;
  left: Child | null = null;
  right: Child | null = null;
  height: number = 1;
  childHeights: [number, number] = [0, 0];

  constructor(node: MerkNode) {
    this.node = node;
  }

  /**
   * Compute the hash of this tree node
   */
  hash(): CryptoHash {
    // For Hash nodes, the stored hash IS the complete node hash
    if (this.node.type === 'Hash') {
      return this.node.hash;
    }

    const kvh = this.computeKVHash();
    return nodeHash(kvh, this.childHash(true), this.childHash(false));
  }

  /**
   * Compute the KV hash portion based on node type
   */
  private computeKVHash(): CryptoHash {
    switch (this.node.type) {
      case 'Hash':
        // Should not reach here - handled in hash()
        throw new GroveDBVerificationError('Hash nodes should not compute KV hash');

      case 'KVHash':
        return this.node.kvHash;

      case 'KV':
        return kvHash(this.node.key, this.node.value);

      case 'KVValueHash':
      case 'KVValueHashFeatureType':
        return kvDigestToKvHash(this.node.key, this.node.valueHash);

      case 'KVDigest':
        return kvDigestToKvHash(this.node.key, this.node.valueHash);

      case 'KVRefValueHash': {
        // For references, combine the node's value hash with the referenced value hash
        const refValueHash = valueHash(this.node.value);
        const combinedValueHash = combineHash(this.node.valueHash, refValueHash);
        return kvDigestToKvHash(this.node.key, combinedValueHash);
      }

      default:
        throw new GroveDBVerificationError(`Unknown node type: ${(this.node as any).type}`);
    }
  }

  /**
   * Get the hash of a child, or NULL_HASH if no child
   */
  childHash(left: boolean): CryptoHash {
    const child = left ? this.left : this.right;
    return child ? child.hash : NULL_HASH;
  }

  /**
   * Attach a child to this node
   */
  attach(left: boolean, child: Tree): void {
    this.attachWithHeight(left, child, child.height);
  }

  /**
   * Attach a child to this node with explicit height
   * This is used when the child may have been collapsed (hash converted)
   * and we need to preserve the original height for AVL checking
   */
  attachWithHeight(left: boolean, child: Tree, originalHeight: number): void {
    if (left && this.left !== null) {
      throw new GroveDBVerificationError('Left child already attached');
    }
    if (!left && this.right !== null) {
      throw new GroveDBVerificationError('Right child already attached');
    }

    this.height = Math.max(this.height, originalHeight + 1);

    if (left) {
      this.childHeights[0] = originalHeight;
      this.left = { tree: child, hash: child.hash() };
    } else {
      this.childHeights[1] = originalHeight;
      this.right = { tree: child, hash: child.hash() };
    }
  }

  /**
   * Convert this tree to a hash-only node (for memory efficiency during execution)
   */
  intoHash(): Tree {
    const h = this.hash();
    return new Tree({ type: 'Hash', hash: h });
  }

  /**
   * Get the key from this node (if it has one)
   */
  getKey(): Uint8Array | null {
    switch (this.node.type) {
      case 'KV':
      case 'KVValueHash':
      case 'KVDigest':
      case 'KVRefValueHash':
      case 'KVValueHashFeatureType':
        return this.node.key;
      default:
        return null;
    }
  }

  /**
   * Get the value from this node (if it has one)
   */
  getValue(): Uint8Array | null {
    switch (this.node.type) {
      case 'KV':
      case 'KVValueHash':
      case 'KVRefValueHash':
      case 'KVValueHashFeatureType':
        return this.node.value;
      default:
        return null;
    }
  }

  /**
   * Get the value hash from this node
   */
  getValueHash(): CryptoHash | null {
    switch (this.node.type) {
      case 'KVValueHash':
      case 'KVDigest':
      case 'KVRefValueHash':
      case 'KVValueHashFeatureType':
        return this.node.valueHash;
      case 'KV':
        return valueHash(this.node.value);
      default:
        return null;
    }
  }

  /**
   * Check if this node has key-value data
   */
  hasKV(): boolean {
    return this.node.type !== 'Hash' && this.node.type !== 'KVHash';
  }

  /**
   * In-order traversal of the tree
   */
  *inOrder(): Generator<Tree> {
    if (this.left) {
      yield* this.left.tree.inOrder();
    }
    yield this;
    if (this.right) {
      yield* this.right.tree.inOrder();
    }
  }
}

/**
 * Compare two byte arrays
 */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}
