import { ethers } from 'ethers';
import { DidDocument, PublicKey } from '../types';

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
 * Create a DID document from an Ethereum wallet
 */
export function createDidFromWallet(wallet: { address: string; publicKey: string }): DidDocument {
  const did = `did:willow:eth:${wallet.address.toLowerCase()}`;
  const now = Math.floor(Date.now() / 1000);

  return {
    id: did,
    publicKeys: [
      {
        id: `${did}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        publicKeyHex: wallet.publicKey.replace('0x', ''),
      },
    ],
    created: now,
    updated: now,
  };
}

/**
 * Validate DID format: `did:willow:<segment>` with one or more
 * colon-separated segments of alphanumerics and hyphens
 * (e.g. `did:willow:devnet-test`, `did:willow:eth:0xabc...`).
 */
export function isValidDid(did: string): boolean {
  return /^did:willow:[a-zA-Z0-9-]+(:[a-zA-Z0-9-]+)*$/.test(did);
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