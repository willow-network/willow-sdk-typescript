/**
 * Privacy module for Willow SDK.
 *
 * Provides key grant management for private subgroves, including
 * granting, revoking, and rotating encryption keys, as well as querying
 * key grants and their cryptographic proofs.
 */

import { ApiResponse, WillowError } from "../types";
import { WillowAuth } from "../auth";
import { BroadcastResult } from "../consensus";
import {
  SignFunction,
  TransactionSubmitError,
  Transaction,
  createTransactionWrapper,
  grantSubgroveKeySignMessage,
  revokeSubgroveKeySignMessage,
  rotateSubgroveKeySignMessage,
} from "../consensus/types";
import { HttpClient, HttpError, RequestSigner } from "../internal/http";
import { submitTxToApi } from "../internal/tx";
import { NonceAllocator, NONCE_WINDOW } from "../consensus/nonces";

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
  /** Subgrove ID. */
  subgrove_id: string;
  /** DID of the grantee. */
  grantee_did: string;
}

// ── Client ────────────────────────────────────────────────────────────

/**
 * Privacy operations for managing key grants on private subgroves.
 *
 * Read operations (get/list/proof) go through the REST API using auth headers.
 * Write operations (grant/revoke/rotate) build signed transactions and
 * submit them through the API server's `/tx/submit` endpoint.
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
 * const grant = await privacy.getMyKeyGrant('private-data');
 * const grantees = await privacy.listKeyGrantees('private-data');
 * const proof = await privacy.getKeyGrantProof('private-data', did);
 *
 * // Write operations (broadcast to consensus)
 * await privacy.grantSubgroveKey('private-data', encryptedGrant);
 * await privacy.revokeSubgroveKey('private-data', revokeDid);
 * await privacy.rotateSubgroveKey('private-data', 2, newGrants);
 * ```
 */
export class PrivacyOperations {
  private api: HttpClient;
  private auth: WillowAuth;
  private privateKey: string;
  private publicKeyId: string;
  private signFunction?: SignFunction;
  private apiUrl: string;
  /**
   * Signs a key-grant read in the older form, over the path exactly as sent
   * (percent-encoded). These routes take that form; read rights don't apply.
   */
  private sign: RequestSigner;
  /** Hands out this instance's transaction nonces, per DID. */
  readonly nonces: NonceAllocator;

  /**
   * Create a new PrivacyOperations instance.
   *
   * @param apiUrl - Willow REST API base URL (e.g. "http://localhost:3031")
   * @param auth - WillowAuth instance with identity set (used for REST auth headers)
   * @param privateKey - Private key hex (used for signing consensus transactions)
   * @param publicKeyId - Public key ID for the DID (e.g. "did:willow:abc#key-1")
   * @param signFunction - Signs a transaction's message with `privateKey`.
   *   Defaults to the sign function of `auth`'s identity
   *   (`auth.getSignFunction()`: secp256k1 or Ed25519).
   * @param nonceAllocator - Hands out transaction nonces. Defaults to
   *   `NonceAllocator.shared(apiUrl)`, shared with every other client of
   *   that API URL in the process (a `WillowClient`'s among them).
   */
  constructor(
    apiUrl: string,
    auth: WillowAuth,
    privateKey: string,
    publicKeyId: string,
    signFunction?: SignFunction,
    nonceAllocator?: NonceAllocator,
  ) {
    this.apiUrl = apiUrl.replace(/\/+$/, "");
    this.api = new HttpClient({ baseURL: this.apiUrl });
    this.auth = auth;
    this.sign = (method, target) => auth.getAuthHeaders(method, target);
    this.privateKey = privateKey;
    this.publicKeyId = publicKeyId;
    this.signFunction = signFunction;
    this.nonces = nonceAllocator ?? NonceAllocator.shared(this.apiUrl);
  }

  /** Sign a transaction's message with this instance's key. */
  private signMessage(message: string): string {
    const sign = this.signFunction ?? this.auth.getSignFunction();
    return sign(message, this.privateKey);
  }

  // ── Read operations (REST API) ─────────────────────────────────────

  /**
   * Get the encrypted key grant for the authenticated DID.
   *
   * Calls GET /key-grants/:subgrove_id/:did where the DID is
   * the caller's own DID from the auth instance.
   *
   * @param subgroveId - Subgrove ID
   * @returns The encrypted key grant for the caller's DID
   * @throws {WillowError} if no identity is set or the grant is not found
   */
  async getMyKeyGrant(
    subgroveId: string,
  ): Promise<EncryptedKeyGrant> {
    const did = this.requireDid();
    const path = `/key-grants/${encodeURIComponent(subgroveId)}/${encodeURIComponent(did)}`;
    const response = await this.api
      .get<ApiResponse<EncryptedKeyGrant>>(path, { sign: this.sign })
      .catch((err) => {
        throw toWillowError(err, "Key grant not found", "KEY_GRANT_NOT_FOUND");
      });

    if (!response.success) {
      throw new WillowError(
        response.error || "Key grant not found",
        "KEY_GRANT_NOT_FOUND",
        404,
      );
    }

    return response.data!;
  }

  /**
   * List all grantee DIDs for a subgrove.
   *
   * Calls GET /key-grants/:subgrove_id.
   * Requires the caller to be the subgrove owner or admin.
   *
   * @param subgroveId - Subgrove ID
   * @returns Array of grantee DIDs
   */
  async listKeyGrantees(
    subgroveId: string,
  ): Promise<string[]> {
    const path = `/key-grants/${encodeURIComponent(subgroveId)}`;
    const response = await this.api
      .get<ApiResponse<string[]>>(path, { sign: this.sign })
      .catch((err) => {
        throw toWillowError(err, "Failed to list key grantees", "LIST_GRANTEES_FAILED");
      });

    if (!response.success) {
      throw new WillowError(
        response.error || "Failed to list key grantees",
        "LIST_GRANTEES_FAILED",
      );
    }

    return response.data!;
  }

  /**
   * Get a GroveDB Merkle proof for a key grant.
   *
   * Calls GET /proof/key-grant/:subgrove_id/:did.
   * Requires the caller to be the grantee or the subgrove's owner or admin.
   *
   * @param subgroveId - Subgrove ID
   * @param did - DID of the grantee
   * @returns Proof response with hex-encoded Merkle proof
   */
  async getKeyGrantProof(
    subgroveId: string,
    did: string,
  ): Promise<KeyGrantProofResponse> {
    const path = `/proof/key-grant/${encodeURIComponent(subgroveId)}/${encodeURIComponent(did)}`;
    const response = await this.api
      .get<ApiResponse<KeyGrantProofResponse>>(path, { sign: this.sign })
      .catch((err) => {
        throw toWillowError(err, "Failed to get key grant proof", "KEY_GRANT_PROOF_FAILED");
      });

    if (!response.success) {
      throw new WillowError(
        response.error || "Failed to get key grant proof",
        "KEY_GRANT_PROOF_FAILED",
        404,
      );
    }

    return response.data!;
  }

  // ── Write operations (CometBFT broadcast) ──────────────────────────

  /**
   * Grant a subgrove encryption key to a DID.
   *
   * Builds a GrantSubgroveKey transaction, signs every field of it and its
   * nonce ({@link grantSubgroveKeySignMessage}), and submits it.
   *
   * The chain refuses a grant whose subgrove id is empty or holds a `:`
   * (`INVALID_SUBGROVE_ID`), or whose grantee is not a Willow DID
   * (`INVALID_DID`); such a grant is refused before a nonce is taken.
   *
   * @param subgroveId - Subgrove ID
   * @param grant - The encrypted key grant for the grantee
   * @returns Broadcast result with transaction hash
   */
  async grantSubgroveKey(
    subgroveId: string,
    grant: EncryptedKeyGrant,
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const unsigned = {
      subgroveId,
      encryptedKeyGrant: grant,
      senderDid: did,
      publicKeyId: this.publicKeyId,
    };
    grantSubgroveKeySignMessage({ ...unsigned, nonce: 0 }); // refuses a field before a nonce is taken
    return this.submitWithNonce(did, "GrantSubgroveKey", (nonce) => {
      const tx = { ...unsigned, nonce };
      return { ...tx, signature: this.signMessage(grantSubgroveKeySignMessage(tx)) };
    });
  }

  /**
   * Revoke a subgrove encryption key from a DID.
   *
   * Builds a RevokeSubgroveKey transaction, signs it
   * ({@link revokeSubgroveKeySignMessage}), and submits it.
   *
   * The chain refuses a revoke whose subgrove id is empty or holds a `:`
   * (`INVALID_SUBGROVE_ID`), or whose revokee or sender (the identity) is not
   * a Willow DID (`INVALID_DID`); such a revoke is refused before a nonce is
   * taken.
   *
   * @param subgroveId - Subgrove ID
   * @param revokeDid - DID to revoke access from
   * @returns Broadcast result with transaction hash
   */
  async revokeSubgroveKey(
    subgroveId: string,
    revokeDid: string,
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const unsigned = {
      subgroveId,
      revokeeDid: revokeDid,
      senderDid: did,
      publicKeyId: this.publicKeyId,
    };
    revokeSubgroveKeySignMessage({ ...unsigned, nonce: 0 }); // refuses a field before a nonce is taken
    return this.submitWithNonce(did, "RevokeSubgroveKey", (nonce) => {
      const tx = { ...unsigned, nonce };
      return { ...tx, signature: this.signMessage(revokeSubgroveKeySignMessage(tx)) };
    });
  }

  /**
   * Rotate the subgrove encryption key and re-grant to authorized DIDs.
   *
   * Builds a RotateSubgroveKey transaction, signs every field of it,
   * every grant, and its nonce ({@link rotateSubgroveKeySignMessage}), and
   * submits it.
   *
   * Only the subgrove owner can rotate keys. The new epoch must be
   * exactly current_epoch + 1. All existing grants are deleted and
   * replaced with the provided new grants.
   *
   * The chain refuses a rotation whose subgrove id is empty or holds a `:`
   * (`INVALID_SUBGROVE_ID`), or with a grantee that is not a Willow DID
   * (`INVALID_DID`); such a rotation is refused before a nonce is taken.
   *
   * @param subgroveId - Subgrove ID
   * @param newEpoch - New key epoch (must be current_epoch + 1)
   * @param newGrants - New encrypted key grants for all authorized DIDs
   * @returns Broadcast result with transaction hash
   */
  async rotateSubgroveKey(
    subgroveId: string,
    newEpoch: number,
    newGrants: EncryptedKeyGrant[],
  ): Promise<BroadcastResult> {
    const did = this.requireDid();
    const unsigned = {
      subgroveId,
      newEpoch,
      newGrants,
      senderDid: did,
      publicKeyId: this.publicKeyId,
    };
    rotateSubgroveKeySignMessage({ ...unsigned, nonce: 0 }); // refuses a field before a nonce is taken
    return this.submitWithNonce(did, "RotateSubgroveKey", (nonce) => {
      const tx = { ...unsigned, nonce };
      return { ...tx, signature: this.signMessage(rotateSubgroveKeySignMessage(tx)) };
    });
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
   * Take the next nonce for a DID from the nonce allocator, against the base
   * the REST API reports. A failed read propagates rather than fabricating a
   * nonce.
   */
  private async getNextNonce(did: string): Promise<number> {
    const base = await this.readNonceBase(did);
    return this.nonces.take(did, { base, used: 0 });
  }

  /** The account's nonce base from `/account/{did}/nonce`. */
  private async readNonceBase(did: string): Promise<number> {
    const response = await this.api
      .get<{
        success: boolean;
        data?: { nonce: number };
        error?: string;
      }>(`/account/${encodeURIComponent(did)}/nonce`)
      .catch((err) => {
        throw toWillowError(
          err,
          `Failed to fetch nonce for ${did}`,
          "NONCE_FETCH_FAILED",
        );
      });

    if (response.success && response.data !== undefined) {
      const base = response.data.nonce;
      if (
        !Number.isSafeInteger(base) ||
        base < 0 ||
        base > Number.MAX_SAFE_INTEGER - NONCE_WINDOW
      ) {
        throw new WillowError(
          `Failed to fetch nonce for ${did}: ${String(base)} is not a nonce this SDK can send`,
          "NONCE_FETCH_FAILED",
        );
      }
      return base;
    }

    throw new WillowError(
      `Failed to fetch nonce for ${did}: ${response.error || "unknown error"}`,
      "NONCE_FETCH_FAILED",
    );
  }

  /**
   * Take a nonce for `did`, build and sign the transaction under it, and
   * submit it through the API server's `/tx/submit`; then record the outcome
   * with the nonce allocator. An accepted write holds its nonce; one refused
   * at CheckTx gives it back unless the refusal says the nonce is held, used,
   * or spent. A write that fails before it is sent gives its nonce back; one
   * whose submission failed in transport keeps it until its hold runs out.
   * A transport failure or a refusal throws a `BROADCAST_FAILED`
   * {@link TransactionSubmitError} carrying the DID, the nonce, the signed
   * body, and (for a refusal) the chain's answer, so the write can be posted
   * again under the same nonce (`ConsensusClient.resubmit(error)`).
   *
   * Encoding (snake_case keys, hex signature -> byte array) is owned by
   * `createTransactionWrapper`, the single place the SDK shapes the wire
   * format the Rust `Transaction` enum deserializes.
   */
  private async submitWithNonce(
    did: string,
    txType: string,
    build: (nonce: number) => Transaction,
  ): Promise<BroadcastResult> {
    const nonce = await this.getNextNonce(did);

    let txWrapper: ReturnType<typeof createTransactionWrapper>;
    let headers: Record<string, string>;
    try {
      txWrapper = createTransactionWrapper(txType, build(nonce));
      headers = this.auth.getAuthHeaders("POST", "/tx/submit");
    } catch (error) {
      this.nonces.release(did, nonce);
      throw error;
    }

    // Held from the send, so no other write takes it while this one is in flight.
    this.nonces.hold(did, nonce);
    let result: BroadcastResult;
    try {
      result = await submitTxToApi(this.apiUrl, txWrapper, { headers });
    } catch (error) {
      throw new TransactionSubmitError(
        `Failed to broadcast transaction: ${error instanceof Error ? error.message : String(error)}`,
        "BROADCAST_FAILED",
        { did, nonce, transaction: txWrapper },
      );
    }
    this.nonces.settle(did, nonce, result);

    if (!result.success) {
      throw new TransactionSubmitError(
        `Transaction rejected: ${result.rawLog || result.errorMessage || "unknown error"}`,
        "BROADCAST_FAILED",
        { did, nonce, transaction: txWrapper, result },
      );
    }

    return result;
  }
}

/**
 * Translate an error thrown by {@link HttpClient} into the typed
 * {@link WillowError} a read method documents. `HttpClient.get` throws
 * `HttpError` on any non-2xx (the post-fetch behaviour), so a 404/500 must be
 * mapped here rather than surfacing as an untyped transport error. Re-thrown
 * WillowErrors pass through unchanged.
 */
function toWillowError(
  err: unknown,
  fallbackMessage: string,
  code: string,
): WillowError {
  if (err instanceof WillowError) return err;
  if (err instanceof HttpError) {
    // Report the real HTTP status (so a 404 stays a 404 and a 500 isn't
    // masked) while keeping the method's documented WillowError code.
    return new WillowError(
      `${fallbackMessage}: ${err.apiError ?? err.message}`,
      code,
      err.status,
    );
  }
  return new WillowError(
    `${fallbackMessage}: ${err instanceof Error ? err.message : String(err)}`,
    code,
  );
}
