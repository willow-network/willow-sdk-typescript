/**
 * Privacy module for Willow SDK.
 *
 * Provides key grant management for private subgroves, including
 * granting, revoking, and rotating encryption keys, as well as querying
 * key grants and their cryptographic proofs.
 */

import axios, { AxiosInstance } from "axios";
import { ApiResponse, WillowError } from "../types";
import { WillowAuth, signEd25519 } from "../auth";
import {
  BroadcastResult,
  stringToBase64,
  createBroadcastResult,
} from "../consensus";

// ── Types ─────────────────────────────────────────────────────────────

/**
 * How often the provider must publish state root commitments on-chain.
 *
 * Mirrors the Rust `CommitmentFrequency` enum from `willow-types`.
 * Represented as a discriminated union matching the serde serialization.
 */
export type CommitmentFrequency =
  | "EveryUpdate"
  | { EveryNBlocks: number }
  | { EveryNSeconds: number }
  | "Never";

/** Convenience constructors for CommitmentFrequency. */
export const CommitmentFrequency = {
  /** Commit after every write/block update (strongest freshness). */
  everyUpdate(): CommitmentFrequency {
    return "EveryUpdate";
  },
  /** Commit every N blocks processed. */
  everyNBlocks(n: number): CommitmentFrequency {
    return { EveryNBlocks: n };
  },
  /** Commit at least every N seconds. */
  everyNSeconds(n: number): CommitmentFrequency {
    return { EveryNSeconds: n };
  },
  /** No on-chain commitments (trusted/internal scenarios only). */
  never(): CommitmentFrequency {
    return "Never";
  },
} as const;

/**
 * Configuration for a private subgrove.
 *
 * Mirrors the Rust `PrivacyConfig` struct from `willow-types`.
 */
export interface PrivacyConfig {
  /** Optional whitelist of indexer DIDs allowed to index this subgrove. */
  allowed_indexers?: string[];
  /** How often the provider must commit state roots to consensus. */
  commitment_frequency: CommitmentFrequency;
}

/**
 * Encrypted copy of a subgrove's symmetric key, wrapped for a specific reader DID.
 *
 * Mirrors the Rust `EncryptedKeyGrant` struct from `willow-types`.
 * The owner wraps the subgrove key for each authorized reader using ECDH.
 */
export interface EncryptedKeyGrant {
  /** DID of the grantee receiving access. */
  grantee_did: string;
  /** Key epoch this grant belongs to. */
  key_epoch: number;
  /** ID of the grantee's public key used for ECDH. */
  grantee_public_key_id: string;
  /** Ephemeral public key for ECDH (32 bytes X25519, as byte array). */
  ephemeral_public_key: number[];
  /** nonce (24 bytes) || ciphertext || auth_tag (16 bytes), as byte array. */
  encrypted_key: number[];
  /** DID that granted this key. */
  granted_by: string;
  /** Unix timestamp when granted. */
  granted_at: number;
}

/**
 * Response from the key grant proof endpoint.
 */
export interface KeyGrantProofResponse {
  /** Hex-encoded GroveDB Merkle proof. */
  proof: string;
  /** Application ID. */
  app_id: string;
  /** Subgrove ID. */
  subgrove_id: string;
  /** DID of the grantee. */
  grantee_did: string;
}

// ── Internal transaction field types ──────────────────────────────────

interface GrantSubgroveKeyTxFields {
  app_id: string;
  subgrove_id: string;
  encrypted_key_grant: EncryptedKeyGrant;
  sender_did: string;
  signature: string;
  public_key_id: string;
  nonce: number;
}

interface RevokeSubgroveKeyTxFields {
  app_id: string;
  subgrove_id: string;
  revokee_did: string;
  sender_did: string;
  signature: string;
  public_key_id: string;
  nonce: number;
}

interface RotateSubgroveKeyTxFields {
  app_id: string;
  subgrove_id: string;
  new_epoch: number;
  new_grants: EncryptedKeyGrant[];
  sender_did: string;
  signature: string;
  public_key_id: string;
  nonce: number;
}

// ── Client ────────────────────────────────────────────────────────────

/**
 * Privacy operations for managing key grants on private subgroves.
 *
 * Read operations (get/list/proof) go through the REST API using auth headers.
 * Write operations (grant/revoke/rotate) build signed transactions and
 * broadcast them to CometBFT via the consensus JSON-RPC endpoint.
 *
 * @example
 * ```typescript
 * const auth = new WillowAuth('http://localhost:3031');
 * auth.setIdentity(did, privateKey, publicKeyId);
 *
 * const privacy = new PrivacyOperations(
 *   'http://localhost:3031',
 *   auth,
 *   privateKey,
 *   publicKeyId,
 * );
 *
 * // Read operations
 * const grant = await privacy.getMyKeyGrant('my-app', 'private-data');
 * const grantees = await privacy.listKeyGrantees('my-app', 'private-data');
 * const proof = await privacy.getKeyGrantProof('my-app', 'private-data', did);
 *
 * // Write operations (broadcast to consensus)
 * await privacy.grantSubgroveKey('my-app', 'private-data', encryptedGrant);
 * await privacy.revokeSubgroveKey('my-app', 'private-data', revokeDid);
 * await privacy.rotateSubgroveKey('my-app', 'private-data', 2, newGrants);
 * ```
 */
export class PrivacyOperations {
  private api: AxiosInstance;
  private auth: WillowAuth;
  private privateKey: string;
  private publicKeyId: string;
  private consensusRpcUrl: string;
  private apiUrl: string;

  /**
   * Create a new PrivacyOperations instance.
   *
   * @param apiUrl - Willow REST API base URL (e.g. "http://localhost:3031")
   * @param auth - WillowAuth instance with identity set (used for REST auth headers)
   * @param privateKey - Ed25519 private key hex (used for signing consensus transactions)
   * @param publicKeyId - Public key ID for the DID (e.g. "did:willow:abc#key-1")
   * @param consensusRpcUrl - CometBFT JSON-RPC URL. If omitted, derived from
   *   apiUrl by replacing port 3031 with 26657.
   */
  constructor(
    apiUrl: string,
    auth: WillowAuth,
    privateKey: string,
    publicKeyId: string,
    consensusRpcUrl?: string,
  ) {
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.api = axios.create({
      baseURL: this.apiUrl,
      headers: { "Content-Type": "application/json" },
    });
    this.auth = auth;
    this.privateKey = privateKey;
    this.publicKeyId = publicKeyId;
    this.consensusRpcUrl =
      consensusRpcUrl || this.apiUrl.replace(":3031", ":26657");
  }

  // ── Read operations (REST API) ─────────────────────────────────────

  /**
   * Get the encrypted key grant for the authenticated DID.
   *
   * Calls GET /key-grants/:app_id/:subgrove_id/:did where the DID is
   * the caller's own DID from the auth instance.
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @returns The encrypted key grant for the caller's DID
   * @throws {WillowError} if no identity is set or the grant is not found
   */
  async getMyKeyGrant(
    appId: string,
    subgroveId: string,
  ): Promise<EncryptedKeyGrant> {
    const did = this.requireDid();
    const path = `/key-grants/${encodeURIComponent(appId)}/${encodeURIComponent(subgroveId)}/${encodeURIComponent(did)}`;
    const headers = this.auth.getAuthHeaders("GET", path);
    const response = await this.api.get<ApiResponse<EncryptedKeyGrant>>(path, {
      headers,
    });

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Key grant not found",
        "KEY_GRANT_NOT_FOUND",
        404,
      );
    }

    return response.data.data!;
  }

  /**
   * List all grantee DIDs for a subgrove.
   *
   * Calls GET /key-grants/:app_id/:subgrove_id.
   * Requires the caller to be the subgrove owner or admin.
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @returns Array of grantee DIDs
   */
  async listKeyGrantees(
    appId: string,
    subgroveId: string,
  ): Promise<string[]> {
    const path = `/key-grants/${encodeURIComponent(appId)}/${encodeURIComponent(subgroveId)}`;
    const headers = this.auth.getAuthHeaders("GET", path);
    const response = await this.api.get<ApiResponse<string[]>>(path, {
      headers,
    });

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to list key grantees",
        "LIST_GRANTEES_FAILED",
      );
    }

    return response.data.data!;
  }

  /**
   * Get a GroveDB Merkle proof for a key grant.
   *
   * Calls GET /proof/key-grant/:app_id/:subgrove_id/:did.
   * This endpoint is public (proofs are non-sensitive).
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @param did - DID of the grantee
   * @returns Proof response with hex-encoded Merkle proof
   */
  async getKeyGrantProof(
    appId: string,
    subgroveId: string,
    did: string,
  ): Promise<KeyGrantProofResponse> {
    const path = `/proof/key-grant/${encodeURIComponent(appId)}/${encodeURIComponent(subgroveId)}/${encodeURIComponent(did)}`;
    const response = await this.api.get<ApiResponse<KeyGrantProofResponse>>(
      path,
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to get key grant proof",
        "KEY_GRANT_PROOF_FAILED",
        404,
      );
    }

    return response.data.data!;
  }

  // ── Write operations (CometBFT broadcast) ──────────────────────────

  /**
   * Grant a subgrove encryption key to a DID.
   *
   * Builds a GrantSubgroveKey transaction, signs it with Ed25519, and
   * broadcasts to the CometBFT consensus layer.
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @param grant - The encrypted key grant for the grantee
   * @returns Broadcast result with transaction hash
   */
  async grantSubgroveKey(
    appId: string,
    subgroveId: string,
    grant: EncryptedKeyGrant,
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const nonce = await this.getNextNonce(did);

    // Sign message format must match the Rust consensus handler:
    // "GrantSubgroveKey:{app_id}:{subgrove_id}:{grantee_did}:{sender_did}:{nonce}"
    const message = `GrantSubgroveKey:${appId}:${subgroveId}:${grant.grantee_did}:${did}:${nonce}`;
    const signature = signEd25519(message, this.privateKey);

    const tx: GrantSubgroveKeyTxFields = {
      app_id: appId,
      subgrove_id: subgroveId,
      encrypted_key_grant: grant,
      sender_did: did,
      signature,
      public_key_id: this.publicKeyId,
      nonce,
    };

    return this.broadcastTransaction("GrantSubgroveKey", tx);
  }

  /**
   * Revoke a subgrove encryption key from a DID.
   *
   * Builds a RevokeSubgroveKey transaction, signs it with Ed25519, and
   * broadcasts to the CometBFT consensus layer.
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @param revokeDid - DID to revoke access from
   * @returns Broadcast result with transaction hash
   */
  async revokeSubgroveKey(
    appId: string,
    subgroveId: string,
    revokeDid: string,
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const nonce = await this.getNextNonce(did);

    // Sign message format must match the Rust consensus handler:
    // "RevokeSubgroveKey:{app_id}:{subgrove_id}:{revokee_did}:{sender_did}:{nonce}"
    const message = `RevokeSubgroveKey:${appId}:${subgroveId}:${revokeDid}:${did}:${nonce}`;
    const signature = signEd25519(message, this.privateKey);

    const tx: RevokeSubgroveKeyTxFields = {
      app_id: appId,
      subgrove_id: subgroveId,
      revokee_did: revokeDid,
      sender_did: did,
      signature,
      public_key_id: this.publicKeyId,
      nonce,
    };

    return this.broadcastTransaction("RevokeSubgroveKey", tx);
  }

  /**
   * Rotate the subgrove encryption key and re-grant to authorized DIDs.
   *
   * Builds a RotateSubgroveKey transaction, signs it with Ed25519, and
   * broadcasts to the CometBFT consensus layer.
   *
   * Only the subgrove owner can rotate keys. The new epoch must be
   * exactly current_epoch + 1. All existing grants are deleted and
   * replaced with the provided new grants.
   *
   * @param appId - Application ID
   * @param subgroveId - Subgrove ID
   * @param newEpoch - New key epoch (must be current_epoch + 1)
   * @param newGrants - New encrypted key grants for all authorized DIDs
   * @returns Broadcast result with transaction hash
   */
  async rotateSubgroveKey(
    appId: string,
    subgroveId: string,
    newEpoch: number,
    newGrants: EncryptedKeyGrant[],
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const nonce = await this.getNextNonce(did);

    // Sign message format must match the Rust consensus handler:
    // "RotateSubgroveKey:{app_id}:{subgrove_id}:{new_epoch}:{sender_did}:{nonce}"
    const message = `RotateSubgroveKey:${appId}:${subgroveId}:${newEpoch}:${did}:${nonce}`;
    const signature = signEd25519(message, this.privateKey);

    const tx: RotateSubgroveKeyTxFields = {
      app_id: appId,
      subgrove_id: subgroveId,
      new_epoch: newEpoch,
      new_grants: newGrants,
      sender_did: did,
      signature,
      public_key_id: this.publicKeyId,
      nonce,
    };

    return this.broadcastTransaction("RotateSubgroveKey", tx);
  }

  // ── Private helpers ─────────────────────────────────────────────────

  /**
   * Require a DID from the auth instance, throwing if not set.
   */
  private requireDid(): string {
    const did = this.auth.getDid();
    if (!did) {
      throw new WillowError(
        "Identity not set. Call auth.setIdentity() first.",
        "NO_IDENTITY",
      );
    }
    return did;
  }

  /**
   * Get the next nonce for a DID from the REST API.
   * Propagates errors instead of silently falling back to nonce 1,
   * which could cause transaction replay or rejection.
   */
  private async getNextNonce(did: string): Promise<number> {
    const response = await this.api.get<{
      success: boolean;
      data?: { nonce: number };
      error?: string;
    }>(`/account/${encodeURIComponent(did)}/nonce`);

    if (response.data.success && response.data.data !== undefined) {
      return response.data.data.nonce + 1;
    }

    throw new WillowError(
      `Failed to fetch nonce for ${did}: ${response.data.error || "unknown error"}`,
      "NONCE_FETCH_FAILED",
    );
  }

  /**
   * Broadcast a wrapped transaction to CometBFT via JSON-RPC broadcast_tx_sync.
   */
  private async broadcastTransaction(
    txType: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    transaction: any,
  ): Promise<BroadcastResult> {
    const txWrapper = { [txType]: transaction };
    const txJson = JSON.stringify(txWrapper);
    const txBase64 = stringToBase64(txJson);

    const rpcRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "broadcast_tx_sync",
      params: { tx: txBase64 },
    };

    try {
      const response = await fetch(this.consensusRpcUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rpcRequest),
        signal: AbortSignal.timeout(30_000),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new WillowError(
          `Consensus RPC error: HTTP ${response.status}: ${errorText}`,
          "BROADCAST_FAILED",
        );
      }

      const data = (await response.json()) as {
        error?: { message?: string };
        result?: Record<string, unknown>;
      };

      if (data.error) {
        throw new WillowError(
          `Consensus RPC error: ${data.error.message || JSON.stringify(data.error)}`,
          "BROADCAST_FAILED",
        );
      }

      return createBroadcastResult({ result: data.result || {} });
    } catch (error) {
      if (error instanceof WillowError) {
        throw error;
      }
      throw new WillowError(
        `Failed to broadcast transaction: ${error instanceof Error ? error.message : String(error)}`,
        "BROADCAST_FAILED",
      );
    }
  }
}
