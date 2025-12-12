import axios, { AxiosInstance } from 'axios';
import { ethers } from 'ethers';
import { ed25519 } from '@noble/curves/ed25519';
import {
  ApiResponse,
  AuthenticationChallenge,
  AuthenticationResponse,
  WillowError,
  DidDocument,
  Session,
} from '../types';

/**
 * Supported signature algorithms
 */
export type SignatureAlgorithm = 'Ed25519' | 'secp256k1';

/**
 * Detect signature algorithm from DID or key format
 */
export function detectAlgorithm(did: string, privateKey?: string): SignatureAlgorithm {
  // Check DID method hints
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
 * Convert hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
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

export class WillowAuth {
  private api: AxiosInstance;
  private session?: Session;

  constructor(apiUrl: string) {
    this.api = axios.create({
      baseURL: apiUrl,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Register a new DID document
   */
  async registerDid(didDocument: DidDocument): Promise<DidDocument> {
    const response = await this.api.post<ApiResponse<DidDocument>>('/did', didDocument);

    if (!response.data.success) {
      throw new WillowError(response.data.error || 'Failed to register DID', 'REGISTRATION_FAILED');
    }

    return response.data.data!;
  }

  /**
   * Get DID document
   */
  async getDid(did: string): Promise<DidDocument> {
    const response = await this.api.get<ApiResponse<DidDocument>>(`/did/${did}`);

    if (!response.data.success) {
      throw new WillowError(response.data.error || 'Failed to get DID', 'DID_NOT_FOUND', 404);
    }

    return response.data.data!;
  }

  /**
   * Create an authentication challenge
   */
  async createChallenge(did: string): Promise<AuthenticationChallenge> {
    const response = await this.api.get<ApiResponse<AuthenticationChallenge>>(
      `/auth/challenge/${did}`
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to create challenge',
        'CHALLENGE_FAILED'
      );
    }

    return response.data.data!;
  }

  /**
   * Sign a challenge with a private key
   * Supports both Ed25519 and secp256k1 (Ethereum) keys
   */
  async signChallenge(
    challenge: AuthenticationChallenge,
    privateKey: string,
    publicKeyId: string
  ): Promise<AuthenticationResponse> {
    // Build the message to sign - must match server's expected format
    const messageToSign = `DID Authentication\nChallenge: ${challenge.challenge}\nNonce: ${(challenge as any).nonce || ''}\nDID: ${challenge.did}\nExpires: ${challenge.expires_at}`;

    // Detect algorithm from key format
    const algorithm = detectAlgorithm(challenge.did, privateKey);
    let signature: string;

    if (algorithm === 'secp256k1') {
      // Ethereum-style signing with ethers.js
      const wallet = new ethers.Wallet(privateKey);
      const messageBytes = ethers.toUtf8Bytes(messageToSign);
      const messageHash = ethers.keccak256(messageBytes);
      const sig = await wallet.signMessage(ethers.getBytes(messageHash));
      signature = sig.replace('0x', '');
    } else {
      // Ed25519 signing with @noble/curves
      signature = signEd25519(messageToSign, privateKey);
    }

    return {
      did: challenge.did,
      challenge: challenge.challenge,
      signature,
      public_key_id: publicKeyId,
    };
  }

  /**
   * Authenticate with a signed challenge
   */
  async authenticate(
    challenge: AuthenticationChallenge,
    response: AuthenticationResponse
  ): Promise<Session> {
    const result = await this.api.post<ApiResponse<Session>>(
      '/auth/verify',
      [challenge, response]
    );

    if (!result.data.success) {
      throw new WillowError(
        result.data.error || 'Authentication failed',
        'AUTH_FAILED',
        401
      );
    }

    this.session = result.data.data!;
    return this.session;
  }

  /**
   * Full authentication flow
   */
  async login(did: string, privateKey: string, publicKeyId: string): Promise<Session> {
    // Get challenge
    const challenge = await this.createChallenge(did);

    // Sign challenge
    const response = await this.signChallenge(challenge, privateKey, publicKeyId);

    // Authenticate
    return await this.authenticate(challenge, response);
  }

  /**
   * Get current session
   */
  getSession(): Session | undefined {
    if (this.session && this.session.expires_at > Date.now() / 1000) {
      return this.session;
    }
    return undefined;
  }

  /**
   * Clear session (logout)
   */
  clearSession(): void {
    this.session = undefined;
  }

  /**
   * Check if currently authenticated
   */
  isAuthenticated(): boolean {
    return this.getSession() !== undefined;
  }

  /**
   * Get authentication headers for API requests
   */
  getAuthHeaders(): Record<string, string> {
    const session = this.getSession();
    if (!session) {
      return {};
    }

    return {
      'X-DID': session.did,
      'X-Session': session.token,
    };
  }

  /**
   * Get query parameters for authentication
   */
  getAuthParams(): Record<string, string> {
    const session = this.getSession();
    if (!session) {
      return {};
    }

    return {
      did: session.did,
      session: session.token,
    };
  }
}
