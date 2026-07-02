import { ethers } from 'ethers';
import { sha3_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { base58 } from '@scure/base';
import { DidDocument, PublicKey } from '../types';
import { hexToBytes } from '../internal/bytes';

/** Signature algorithms whose keys can back a self-certifying Willow DID. */
export type DidKeyAlgorithm = 'Ed25519' | 'secp256k1';

// Multicodec varint prefixes (same registry used by `did:key`). The Willow
// chain hashes `prefix || public_key` to derive the self-certifying id.
const MULTICODEC_ED25519 = Uint8Array.from([0xed, 0x01]);
const MULTICODEC_SECP256K1 = Uint8Array.from([0xe7, 0x01]);

/**
 * Normalize a secp256k1 public key to its 33-byte COMPRESSED form.
 *
 * Accepts hex (optionally `0x`-prefixed) or raw bytes in any of the usual
 * encodings: 33-byte compressed, 65-byte uncompressed (`0x04…`), or the
 * 64-byte raw `x || y` form (no prefix). The Willow DID derivation always
 * hashes the compressed key, so uncompressed input is normalized here.
 */
function toCompressedSecp256k1(publicKey: string | Uint8Array): Uint8Array {
  let bytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
  if (bytes.length === 64) {
    // Raw x || y with no SEC1 prefix — prepend the uncompressed 0x04 tag.
    const withPrefix = new Uint8Array(65);
    withPrefix[0] = 0x04;
    withPrefix.set(bytes, 1);
    bytes = withPrefix;
  }
  // Point.fromHex accepts compressed(33)/uncompressed(65) and re-encodes it
  // compressed, validating that the point is actually on the curve.
  return secp256k1.ProjectivePoint.fromHex(bytes).toRawBytes(true);
}

/**
 * Derive a self-certifying Willow DID from a public key.
 *
 * ```
 * did = "did:willow:z" + base58btc( SHA3-256( multicodec_prefix || public_key ) )
 * ```
 *
 * - `SHA3-256` is FIPS-202 SHA3-256 — **not** Keccak-256 (the two differ).
 * - Ed25519 uses the `0xED 0x01` prefix over the raw 32-byte public key.
 * - secp256k1 uses the `0xE7 0x01` prefix over the 33-byte **compressed**
 *   public key (uncompressed input is normalized first).
 * - `base58btc` uses the Bitcoin alphabet, with each leading `0x00` byte
 *   encoded as a leading `1`.
 * - The literal `z` is the multibase base58btc marker.
 *
 * The id is fully determined by the key and cannot be chosen. The chain's
 * `RegisterDid` check rejects any id that is not exactly this derivation.
 *
 * @returns the derived `did` and its conventional `publicKeyId` (`{did}#key-1`).
 */
export function deriveDid(
  publicKey: string | Uint8Array,
  algorithm: DidKeyAlgorithm = 'Ed25519'
): { did: string; publicKeyId: string } {
  let prefix: Uint8Array;
  let keyBytes: Uint8Array;

  if (algorithm === 'Ed25519') {
    prefix = MULTICODEC_ED25519;
    keyBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
  } else if (algorithm === 'secp256k1') {
    prefix = MULTICODEC_SECP256K1;
    keyBytes = toCompressedSecp256k1(publicKey);
  } else {
    throw new Error(`Unsupported DID key algorithm: ${algorithm}`);
  }

  const preimage = new Uint8Array(prefix.length + keyBytes.length);
  preimage.set(prefix, 0);
  preimage.set(keyBytes, prefix.length);

  const did = `did:willow:z${base58.encode(sha3_256(preimage))}`;
  return { did, publicKeyId: `${did}#key-1` };
}

/**
 * Generate a new Ethereum wallet
 */
export function generateWallet() {
  const wallet = ethers.Wallet.createRandom();
  return {
    address: wallet.address,
    privateKey: wallet.privateKey,
    publicKey: wallet.publicKey,
  };
}

/**
 * Build a DID document from a public key, deriving the self-certifying id.
 *
 * The id is derived via {@link deriveDid} — it is bound to the key and is not
 * chosen. Because the id depends on the key, a freshly created DID must be
 * funded (someone transfers at least the registration fee to the derived id)
 * *before* `client.registerDid(...)` is called; the fee is then paid from that
 * balance. See the README "Registration" section for the full bootstrap order.
 */
export function createDidFromPublicKey(
  publicKey: string,
  algorithm: DidKeyAlgorithm = 'Ed25519'
): DidDocument {
  const { did, publicKeyId } = deriveDid(publicKey, algorithm);
  const now = Math.floor(Date.now() / 1000);

  return {
    id: did,
    publicKeys: [
      {
        id: publicKeyId,
        type: algorithm === 'Ed25519' ? 'Ed25519' : 'EcdsaSecp256k1VerificationKey2019',
        publicKeyHex: publicKey.replace(/^0x/, ''),
      },
    ],
    created: now,
    updated: now,
  };
}

/**
 * Create a DID document from an Ethereum (secp256k1) wallet.
 *
 * The id is the self-certifying derivation over the wallet's compressed
 * secp256k1 public key (see {@link deriveDid}) — it is no longer the old
 * `did:willow:eth:<address>` form, which the chain now rejects.
 */
export function createDidFromWallet(wallet: { address: string; publicKey: string }): DidDocument {
  const { did, publicKeyId } = deriveDid(wallet.publicKey, 'secp256k1');
  const now = Math.floor(Date.now() / 1000);

  return {
    id: did,
    publicKeys: [
      {
        id: publicKeyId,
        type: 'EcdsaSecp256k1VerificationKey2019',
        publicKeyHex: wallet.publicKey.replace('0x', ''),
      },
    ],
    created: now,
    updated: now,
  };
}

/**
 * Validate DID format: `did:willow:<body>` where the body is a non-empty run
 * of ASCII alphanumerics, hyphens, and underscores (e.g. `did:willow:devnet-test`,
 * `did:willow:owner_1700000000`). Mirrors the chain's `validate_did`, which
 * does not permit further colon-separated segments in the body.
 */
export function isValidDid(did: string): boolean {
  return /^did:willow:[a-zA-Z0-9_-]+$/.test(did);
}

/**
 * Extract public key from DID document
 */
export function getPublicKeyFromDid(
  didDocument: DidDocument,
  keyId?: string
): PublicKey | undefined {
  if (!didDocument.publicKeys || didDocument.publicKeys.length === 0) {
    return undefined;
  }

  if (keyId) {
    return didDocument.publicKeys.find((key) => key.id === keyId);
  }

  return didDocument.publicKeys[0];
}

/**
 * Generate a unique ID
 */
export function generateId(prefix?: string): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 9);
  return prefix ? `${prefix}_${timestamp}_${random}` : `${timestamp}_${random}`;
}

/**
 * Sleep utility for testing
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Chunk array for batch operations
 */
export function chunk<T>(array: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < array.length; i += size) {
    chunks.push(array.slice(i, i + size));
  }
  return chunks;
}

/**
 * Retry wrapper for network operations
 */
export async function retry<T>(
  fn: () => Promise<T>,
  options: {
    attempts?: number;
    delay?: number;
    backoff?: number;
  } = {}
): Promise<T> {
  const { attempts = 3, delay = 1000, backoff = 2 } = options;

  let lastError: Error | undefined;

  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      if (i < attempts - 1) {
        await sleep(delay * Math.pow(backoff, i));
      }
    }
  }

  throw lastError;
}