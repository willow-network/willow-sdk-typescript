import { ethers } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import {
  ApiResponse,
  WillowError,
  DidDocument,
} from '../types';
import { HttpClient } from '../internal/http';
import { bytesToHex, hexToBytes } from '../internal/bytes';

/**
 * Supported signature algorithms
 */
export type SignatureAlgorithm = 'Ed25519' | 'secp256k1';

/**
 * Best-effort signature-algorithm detection from a DID or key format.
 *
 * NOTE: self-certifying Willow DIDs (`did:willow:z<base58btc(hash)>`) no longer
 * encode the algorithm in the id string, so the `:eth:` / `:eip155:` hints only
 * fire for legacy/other-method DIDs. The private-key heuristic below is likewise
 * ambiguous — an Ed25519 and a raw-hex secp256k1 key are both 64 hex chars — so
 * it only recognizes secp256k1 when the key is in ethers' `0x`-prefixed 66-char
 * form. Prefer the authoritative signal: pass the algorithm explicitly (e.g.
 * derived from the on-chain DID document via {@link algorithmFromKeyType}) to
 * {@link WillowAuth.setIdentity}. This function remains only as a fallback.
 */
export function detectAlgorithm(did: string, privateKey?: string): SignatureAlgorithm {
  // Check DID method hints (legacy DIDs only; self-certifying ids carry none).
  if (did.includes(':eth:') || did.includes(':eip155:')) {
    return 'secp256k1';
  }

  // Check private key format
  if (privateKey) {
    // Ethereum private keys start with 0x and are 66 chars (0x + 64 hex)
    if (privateKey.startsWith('0x') && privateKey.length === 66) {
      return 'secp256k1';
    }
    // Ed25519 private keys are 64 hex chars (32 bytes) or 128 hex chars (64 bytes with pubkey)
    const cleanKey = privateKey.replace(/^0x/, '');
    if (cleanKey.length === 64 || cleanKey.length === 128) {
      return 'Ed25519';
    }
  }

  // Default to Ed25519 for Willow DIDs
  return 'Ed25519';
}

/**
 * Map a DID-document public-key / verification-method `type` to a signature
 * algorithm.
 *
 * Because self-certifying Willow DIDs cannot reveal their algorithm from the id
 * string, the on-chain DID document's key `type` is the authoritative signal.
 * The SDK derives these types itself (see `createDidFromPublicKey` /
 * `createDidFromWallet` in `../utils`): Ed25519 keys use `'Ed25519'` and
 * secp256k1 keys use `'EcdsaSecp256k1VerificationKey2019'`. Other common W3C
 * spellings are accepted too. Returns `undefined` for unrecognized types so
 * callers can fall back to {@link detectAlgorithm}.
 */
export function algorithmFromKeyType(
  type: string | undefined,
): SignatureAlgorithm | undefined {
  if (!type) return undefined;
  const t = type.toLowerCase();
  if (t.includes('secp256k1')) {
    return 'secp256k1';
  }
  if (t.includes('ed25519')) {
    return 'Ed25519';
  }
  return undefined;
}

/**
 * Sign a message with Ed25519
 */
export function signEd25519(message: string, privateKeyHex: string): string {
  const cleanKey = privateKeyHex.replace(/^0x/, '');

  // Ed25519 private key can be 32 bytes (seed) or 64 bytes (seed + public key)
  let privateKey: Uint8Array;
  if (cleanKey.length === 128) {
    // 64 bytes - take first 32 as the seed
    privateKey = hexToBytes(cleanKey.slice(0, 64));
  } else if (cleanKey.length === 64) {
    // 32 bytes - use as-is
    privateKey = hexToBytes(cleanKey);
  } else {
    throw new WillowError(
      `Invalid Ed25519 private key length: ${cleanKey.length / 2} bytes (expected 32 or 64)`,
      'INVALID_KEY'
    );
  }

  const messageBytes = new TextEncoder().encode(message);
  const signature = ed25519.sign(messageBytes, privateKey);
  return bytesToHex(signature);
}

/**
 * Verify an Ed25519 signature
 */
export function verifyEd25519(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const messageBytes = new TextEncoder().encode(message);
    const signature = hexToBytes(signatureHex);
    const publicKey = hexToBytes(publicKeyHex);
    return ed25519.verify(signature, messageBytes, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a new Ed25519 key pair
 */
export function generateEd25519KeyPair(): { privateKey: string; publicKey: string } {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return {
    privateKey: bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey)
  };
}

/**
 * Get public key from Ed25519 private key
 */
export function getEd25519PublicKey(privateKeyHex: string): string {
  const cleanKey = privateKeyHex.replace(/^0x/, '');

  let privateKey: Uint8Array;
  if (cleanKey.length === 128) {
    // 64 bytes - public key is the second half
    return cleanKey.slice(64);
  } else if (cleanKey.length === 64) {
    // 32 bytes - derive public key
    privateKey = hexToBytes(cleanKey);
    const publicKey = ed25519.getPublicKey(privateKey);
    return bytesToHex(publicKey);
  } else {
    throw new WillowError(
      `Invalid Ed25519 private key length: ${cleanKey.length / 2} bytes`,
      'INVALID_KEY'
    );
  }
}

/**
 * Per-request signature headers
 */
export interface SignedRequestHeaders {
  [key: string]: string;
  'X-DID': string;
  'X-Public-Key-ID': string;
  'X-Signature': string;
  'X-Timestamp': string;
}

export class WillowAuth {
  private api: HttpClient;
  private did?: string;
  private privateKey?: string;
  private publicKeyId?: string;
  private algorithm?: SignatureAlgorithm;
  private apiKey?: string;

  constructor(apiUrl: string, apiKey?: string) {
    this.apiKey = apiKey;
    this.api = new HttpClient({
      baseURL: apiUrl,
      headers: apiKey ? { 'X-API-Key': apiKey } : {},
    });
  }

  /**
   * Set or rotate the managed-tier API key. Affects all subsequent
   * requests from this client.
   */
  setApiKey(apiKey: string | undefined): void {
    this.apiKey = apiKey;
    this.api.setHeader('X-API-Key', apiKey);
  }

  /** Returns the configured API key (if any). */
  getApiKey(): string | undefined {
    return this.apiKey;
  }

  /** Returns `{ 'X-API-Key': key }` when a key is set, else `{}`. */
  apiKeyHeaders(): Record<string, string> {
    return this.apiKey ? { 'X-API-Key': this.apiKey } : {};
  }

  /**
   * Set identity for per-request signing.
   * Call this once; all subsequent requests will be signed automatically.
   *
   * @param algorithm - Signature algorithm for per-request auth. Pass this
   *   explicitly for secp256k1 (Ethereum/wallet) identities: self-certifying
   *   Willow DIDs no longer encode the algorithm in the id, so it cannot be
   *   parsed from `did`. When omitted, falls back to best-effort
   *   {@link detectAlgorithm} (Ed25519 for a typical Willow DID), preserving
   *   backward-compatible behavior. `WillowClient.init()` supplies this
   *   automatically from the on-chain DID document's key type.
   */
  setIdentity(
    did: string,
    privateKey: string,
    publicKeyId: string,
    algorithm?: SignatureAlgorithm,
  ): void {
    this.did = did;
    this.privateKey = privateKey;
    this.publicKeyId = publicKeyId;
    this.algorithm = algorithm ?? detectAlgorithm(did, privateKey);
  }

  /**
   * Check if an identity is configured for signing
   */
  hasIdentity(): boolean {
    return !!(this.did && this.privateKey && this.publicKeyId);
  }

  /**
   * Get the current DID
   */
  getDid(): string | undefined {
    return this.did;
  }

  /**
   * Get the current private key (hex-encoded)
   */
  getPrivateKey(): string | undefined {
    return this.privateKey;
  }

  /**
   * Get the current public key ID
   */
  getPublicKeyId(): string | undefined {
    return this.publicKeyId;
  }

  /**
   * Register a new DID document
   */
  async registerDid(didDocument: DidDocument): Promise<DidDocument> {
    const response = await this.api.post<ApiResponse<DidDocument>>('/did', didDocument);

    if (!response.success) {
      throw new WillowError(response.error || 'Failed to register DID', 'REGISTRATION_FAILED');
    }

    return response.data!;
  }

  /**
   * Resolve a DID to its DID document
   */
  async getDidDocument(did: string): Promise<DidDocument> {
    const response = await this.api.get<ApiResponse<DidDocument>>(`/did/${did}`);

    if (!response.success) {
      throw new WillowError(response.error || 'Failed to get DID', 'DID_NOT_FOUND', 404);
    }

    return response.data!;
  }

  /** @deprecated Use {@link getDidDocument}. */
  async getDid_(did: string): Promise<DidDocument> {
    return this.getDidDocument(did);
  }

  /**
   * Sign a request and return the authentication headers.
   *
   * Message format: `{METHOD}:{PATH}:{TIMESTAMP}`
   */
  signRequest(method: string, path: string): SignedRequestHeaders {
    if (!this.did || !this.privateKey || !this.publicKeyId) {
      throw new WillowError(
        'Identity not set. Call setIdentity() first.',
        'NO_IDENTITY'
      );
    }

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const message = `${method}:${path}:${timestamp}`;

    let signature: string;
    if (this.algorithm === 'secp256k1') {
      const wallet = new ethers.Wallet(this.privateKey);
      const messageBytes = ethers.toUtf8Bytes(message);
      const messageHash = ethers.keccak256(messageBytes);
      // signMessageSync returns a hex string with 0x prefix
      const sig = wallet.signMessageSync(ethers.getBytes(messageHash));
      signature = sig.replace('0x', '');
    } else {
      signature = signEd25519(message, this.privateKey);
    }

    return {
      'X-DID': this.did,
      'X-Public-Key-ID': this.publicKeyId,
      'X-Signature': signature,
      'X-Timestamp': timestamp,
    };
  }

  /**
   * Get authentication headers for an API request.
   *
   * Returns the merge of:
   *  - DID-signature headers (X-DID, X-Public-Key-ID, X-Signature, X-Timestamp)
   *    when an identity is set via setIdentity().
   *  - X-API-Key when a key is set via the constructor or setApiKey().
   *
   * Either, both, or neither may be present.
   */
  getAuthHeaders(method: string, path: string): Record<string, string> {
    const apiKeyHeaders = this.apiKeyHeaders();
    if (!this.hasIdentity()) {
      return apiKeyHeaders;
    }
    return { ...this.signRequest(method, path), ...apiKeyHeaders };
  }

  /**
   * Get query parameters for authentication (DID only, for pay-per-read fallback)
   */
  getAuthParams(): Record<string, string> {
    if (!this.did) {
      return {};
    }
    return { did: this.did };
  }
}
