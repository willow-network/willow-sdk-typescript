import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import {
  ApiResponse,
  WillowError,
  DidDocument,
} from '../types';
import { HttpClient } from '../internal/http';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../internal/bytes';

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

/** Parse a secp256k1 private key given as hex, with or without `0x`. */
function secp256k1PrivateKey(privateKeyHex: string): Uint8Array {
  const clean = privateKeyHex.replace(/^0x/, '');
  if (clean.length !== 64) {
    throw new WillowError(
      `Invalid secp256k1 private key length: ${clean.length / 2} bytes (expected 32)`,
      'INVALID_KEY'
    );
  }
  return hexToBytes(clean);
}

/**
 * Sign a message with secp256k1, as Willow verifies it: ECDSA over the
 * Keccak-256 of the UTF-8 message (Ethereum's Keccak, not FIPS SHA3-256, and
 * not an EIP-191 personal message), deterministic (RFC 6979), lower-S.
 *
 * @returns the 64-byte compact `r || s` signature as `0x`-prefixed hex. The
 *   server reads an unprefixed secp256k1 signature as base64 before hex, so
 *   request signatures must carry the prefix.
 */
export function signSecp256k1(message: string, privateKeyHex: string): string {
  const digest = keccak_256(utf8ToBytes(message));
  const signature = secp256k1.sign(digest, secp256k1PrivateKey(privateKeyHex), { lowS: true });
  return `0x${signature.toCompactHex()}`;
}

/**
 * Verify a secp256k1 signature the way Willow does: ECDSA over the Keccak-256
 * of the message, a 64-byte compact `r || s` or a DER signature (hex, with or
 * without `0x`), lower-S only.
 *
 * `publicKeyHex` may be 33-byte compressed, 65-byte uncompressed (`04…`), or
 * the 64-byte `x || y` form without the `04` tag.
 */
export function verifySecp256k1(
  message: string,
  signatureHex: string,
  publicKeyHex: string,
): boolean {
  try {
    const signature = hexToBytes(signatureHex);
    let publicKey = hexToBytes(publicKeyHex);
    if (publicKey.length === 64) {
      const tagged = new Uint8Array(65);
      tagged[0] = 0x04;
      tagged.set(publicKey, 1);
      publicKey = tagged;
    }
    const digest = keccak_256(utf8ToBytes(message));
    return secp256k1.verify(signature, digest, publicKey, {
      lowS: true,
      format: signature.length === 64 ? 'compact' : 'der',
    });
  } catch {
    return false;
  }
}

/** The first line of a nonce-signed request's message. */
export const SIGNED_REQUEST_VERSION = 'willow-request-v2';

/**
 * The message a nonce-signed request signs, eight lines joined by `\n` with
 * no trailing newline: the version line, the DID, its key's id, the method,
 * the path and query exactly as the server receives them, the Unix timestamp,
 * the nonce, and the lowercase hex SHA-256 of the exact body bytes (of no
 * bytes, for a request without a body).
 *
 * A string body is hashed as its UTF-8 bytes, which is what `fetch` sends.
 */
export function signedRequestMessage(
  did: string,
  publicKeyId: string,
  method: string,
  pathAndQuery: string,
  timestamp: string,
  nonce: string,
  body?: Uint8Array | string,
): string {
  const bytes =
    body === undefined ? new Uint8Array(0) : typeof body === 'string' ? utf8ToBytes(body) : body;
  return [
    SIGNED_REQUEST_VERSION,
    did,
    publicKeyId,
    method,
    pathAndQuery,
    timestamp,
    nonce,
    bytesToHex(sha256(bytes)),
  ].join('\n');
}

/**
 * The message the older request form signs: `{METHOD}:{PATH}:{TIMESTAMP}`,
 * where PATH is the path alone. The server verifies it against the request's
 * path without its query string, so anything from the first `?` is dropped.
 */
export function legacyRequestMessage(method: string, path: string, timestamp: string): string {
  const q = path.indexOf('?');
  return `${method}:${q >= 0 ? path.slice(0, q) : path}:${timestamp}`;
}

/**
 * A fresh nonce for a nonce-signed request: 32 lowercase hex characters from
 * 16 random bytes. The server accepts 16 to 128 characters of
 * `A-Z a-z 0-9 - _`, and each (DID, nonce) once.
 */
export function newRequestNonce(): string {
  return bytesToHex(randomBytes(16));
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

/** Signature headers of a nonce-signed request. */
export interface NonceSignedRequestHeaders extends SignedRequestHeaders {
  'X-Nonce': string;
}

/**
 * Fixed inputs for {@link WillowAuth.signRequestWithNonce}, for tests and
 * reproducible signatures. The server accepts each (DID, nonce) once, so a
 * request sent to it needs a fresh nonce: leave these unset.
 */
export interface SignRequestOptions {
  /** Unix seconds. Default: now. */
  timestamp?: number | string;
  /** Default: {@link newRequestNonce}. */
  nonce?: string;
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

  private requireIdentity(): { did: string; privateKey: string; publicKeyId: string } {
    if (!this.did || !this.privateKey || !this.publicKeyId) {
      throw new WillowError(
        'Identity not set. Call setIdentity() first.',
        'NO_IDENTITY'
      );
    }
    return { did: this.did, privateKey: this.privateKey, publicKeyId: this.publicKeyId };
  }

  /**
   * Sign a request message and encode the signature as the server decodes
   * `X-Signature`: Ed25519 as hex, secp256k1 as `0x`-prefixed hex.
   */
  private signMessage(message: string, privateKey: string): string {
    return this.algorithm === 'secp256k1'
      ? signSecp256k1(message, privateKey)
      : signEd25519(message, privateKey);
  }

  /**
   * Sign a request in the server's older form and return the authentication
   * headers. The message is `{METHOD}:{PATH}:{TIMESTAMP}`, where PATH is the
   * path as sent (percent-encoded) without its query string, as the server
   * verifies it (see {@link legacyRequestMessage}).
   *
   * This form proves the DID but carries none of its read rights (a Reader
   * permission or a place on a free-reader list), and it can be replayed with
   * any body until the timestamp expires. The client signs its reads of
   * subgrove data with {@link signRequestWithNonce}, and its other signed
   * requests (writes, key-grant reads, transaction submission) with this form.
   */
  signRequest(method: string, path: string): SignedRequestHeaders {
    const { did, privateKey, publicKeyId } = this.requireIdentity();
    const timestamp = Math.floor(Date.now() / 1000).toString();
    return {
      'X-DID': did,
      'X-Public-Key-ID': publicKeyId,
      'X-Signature': this.signMessage(legacyRequestMessage(method, path, timestamp), privateKey),
      'X-Timestamp': timestamp,
    };
  }

  /**
   * Sign a request with a one-time nonce over the whole request and return
   * the authentication headers, `X-Nonce` among them.
   *
   * `pathAndQuery` is the request target exactly as the server receives it:
   * percent-encoded as sent, query string included, without any path the
   * base URL adds in front. `body` is the exact body sent (omit it for none).
   * The server accepts the timestamp for 300 s and each (DID, nonce) once,
   * so sign every attempt of a request anew.
   *
   * Only this form carries the DID's read rights: a Reader permission on a
   * subgrove, or a place on a priced subgrove's free-reader list.
   *
   * @param options - Fixed timestamp and nonce, for tests only.
   */
  signRequestWithNonce(
    method: string,
    pathAndQuery: string,
    body?: Uint8Array | string,
    options: SignRequestOptions = {},
  ): NonceSignedRequestHeaders {
    const { did, privateKey, publicKeyId } = this.requireIdentity();
    const timestamp = String(options.timestamp ?? Math.floor(Date.now() / 1000));
    const nonce = options.nonce ?? newRequestNonce();
    const message = signedRequestMessage(
      did,
      publicKeyId,
      method,
      pathAndQuery,
      timestamp,
      nonce,
      body,
    );
    return {
      'X-DID': did,
      'X-Public-Key-ID': publicKeyId,
      'X-Signature': this.signMessage(message, privateKey),
      'X-Timestamp': timestamp,
      'X-Nonce': nonce,
    };
  }

  /**
   * Headers for a read of subgrove data sent to the API (`GET /data/:sg/:key`,
   * `GET /proof/:sg/:key`, and `POST /query/:sg`, `/sql/:sg`, and
   * `/graphql/:sg`): `X-API-Key` when a key is set, and the nonce-form
   * signature headers ({@link signRequestWithNonce}) when an identity is set.
   * Only that form carries the DID's read rights. Pass the exact target and
   * body of the request as sent.
   */
  getSignedHeaders(
    method: string,
    pathAndQuery: string,
    body?: Uint8Array | string,
  ): Record<string, string> {
    const apiKeyHeaders = this.apiKeyHeaders();
    if (!this.hasIdentity()) {
      return apiKeyHeaders;
    }
    return { ...this.signRequestWithNonce(method, pathAndQuery, body), ...apiKeyHeaders };
  }

  /**
   * Headers in the older signature form: `X-API-Key` when a key is set, and
   * {@link signRequest}'s headers when an identity is set. Pass the path as
   * sent (percent-encoded); a query string is ignored.
   *
   * These prove the DID but carry none of its read rights; for a read of
   * subgrove data, use {@link getSignedHeaders}. The nonce form is refused for
   * a short while after the API restarts and allows less clock skew, so the
   * client keeps other signed requests on this form.
   */
  getAuthHeaders(method: string, path: string): Record<string, string> {
    const apiKeyHeaders = this.apiKeyHeaders();
    if (!this.hasIdentity()) {
      return apiKeyHeaders;
    }
    return { ...this.signRequest(method, path), ...apiKeyHeaders };
  }
}
