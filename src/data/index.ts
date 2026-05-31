import axios, { AxiosInstance } from "axios";
import {
  ApiResponse,
  WillowError,
  DataRecord,
  ProofResponse,
  RegisterDatasetRequest,
  DatasetRegistration,
  QueryRequest,
  QueryResponse,
  HistoricalQueryRequest,
  HistoricalQueryResponse,
  CheckpointInfo,
  SqlQueryResponse,
  GraphQLQueryResult,
  GraphQLQueryOptions,
  SqlQueryOptions,
  SqlQueryResult,
  QuerySource,
} from "../types";
import { WillowAuth } from "../auth";
import { verifyQueryProof, verifyItemProof } from "../proof";
import { LightClient, LightClientConfig } from "../light-client";
import {
  ComputedFieldRegistry,
  ComputedFieldSet,
  applyComputedFieldsToResponse,
} from "../computed-fields";
import {
  WillowIndexers,
  ApiIndexerInfo,
  effectiveQueryEndpoint,
} from "../indexers";

export class ValidatorHasNoDataError extends WillowError {
  constructor(subgroveId: string, reason: string) {
    super(
      `Validator cannot serve data for subgrove "${subgroveId}": ${reason}`,
      "VALIDATOR_HAS_NO_DATA",
    );
    this.name = "ValidatorHasNoDataError";
  }
}

export class NoIndexersReachableError extends WillowError {
  constructor(subgroveId: string, details: string) {
    super(
      `No indexer could serve subgrove "${subgroveId}": ${details}`,
      "NO_INDEXERS_REACHABLE",
    );
    this.name = "NoIndexersReachableError";
  }
}

export class WillowData {
  private api: AxiosInstance;
  private auth: WillowAuth;
  private apiUrl: string;
  private cometbftRpcUrl?: string;
  private lightClient?: LightClient;
  private lightClientInitPromise?: Promise<LightClient>;
  private computedFieldRegistry: ComputedFieldRegistry;
  private indexers: WillowIndexers;

  constructor(
    apiUrl: string,
    auth: WillowAuth,
    indexers: WillowIndexers,
    cometbftRpcUrl?: string,
  ) {
    this.apiUrl = apiUrl;
    this.cometbftRpcUrl = cometbftRpcUrl;
    this.indexers = indexers;
    this.api = axios.create({
      baseURL: apiUrl,
      headers: {
        "Content-Type": "application/json",
      },
    });
    this.auth = auth;
    this.computedFieldRegistry = new ComputedFieldRegistry();
  }

  /**
   * Register computed fields for a specific dataset.
   *
   * Computed fields are derived client-side from proven data. This enables
   * drop-in compatibility with The Graph's query interfaces by computing
   * values like price ratios from cryptographically proven reserves.
   *
   * @param datasetId - The dataset ID
   * @param fields - The computed field definitions
   *
   * @example
   * ```typescript
   * import { UNISWAP_V2_PAIR_FIELDS } from '@willow-network/sdk';
   *
   * client.data.registerComputedFields('pairs', UNISWAP_V2_PAIR_FIELDS);
   * ```
   */
  registerComputedFields(
    datasetId: string,
    fields: ComputedFieldSet,
  ): void {
    this.computedFieldRegistry.register(datasetId, fields);
  }

  /**
   * Get the computed field registry for direct manipulation.
   */
  getComputedFieldRegistry(): ComputedFieldRegistry {
    return this.computedFieldRegistry;
  }

  /**
   * Get or create a light client for trustless verification.
   *
   * Auto-initializes a light client using trust-on-first-use: the first
   * block received from validators is trusted, and every subsequent block
   * is verified against it. Pin a known-good checkpoint header instead
   * for production deployments.
   */
  private async getOrCreateLightClient(): Promise<LightClient> {
    if (this.lightClient) {
      return this.lightClient;
    }

    // Prevent concurrent initialization
    if (this.lightClientInitPromise) {
      return this.lightClientInitPromise;
    }

    this.lightClientInitPromise = (async () => {
      const config: LightClientConfig = {
        chainId: "willow-chain",
        validatorEndpoints: [this.cometbftRpcUrl ?? this.apiUrl.replace(":3031", ":26657")],
        trustThreshold: { numerator: 2, denominator: 3 },
        trustingPeriodSecs: 86400, // 24 hours
        maxClockDriftSecs: 30,
        autoSync: false,
        minValidatorsForConsensus: 1, // For single-node development
        requestTimeoutSecs: 30,
        syncIntervalSecs: 60,
      };

      const lc = new LightClient(config);
      await lc.initializeWithTrustOnFirstUse();
      this.lightClient = lc;
      return lc;
    })();

    try {
      const lc = await this.lightClientInitPromise;
      this.lightClientInitPromise = undefined;
      return lc;
    } catch (error) {
      this.lightClientInitPromise = undefined;
      throw error;
    }
  }

  /**
   * Register a dataset/subgrove
   */
  async registerDataset(
    request: RegisterDatasetRequest,
  ): Promise<DatasetRegistration> {
    const headers = this.auth.getAuthHeaders('POST', '/register/subgrove');

    // Convert to the API's expected format (subgrove endpoint for compatibility)
    const subgroveRequest = {
      subgrove_id: request.dataset_id,
      name: request.name,
      schema: request.schema,
      owner_did: request.owner_did,
      writers: request.writers,
      readers: request.readers,
    };

    const response = await this.api.post<ApiResponse<DatasetRegistration>>(
      "/register/subgrove",
      subgroveRequest,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to register dataset",
        "DATASET_REGISTRATION_FAILED",
      );
    }

    return response.data.data!;
  }

  /**
   * Store data (batch operation)
   */
  async storeData(
    datasetId: string,
    data: Record<string, any>,
  ): Promise<void> {
    const headers = this.auth.getAuthHeaders('POST', `/data/${datasetId}`);
    const response = await this.api.post<ApiResponse>(
      `/data/${datasetId}`,
      data,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to store data",
        "STORE_FAILED",
      );
    }
  }

  /**
   * Get data by key with automatic proof verification (secure by default)
   */
  async getData(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    const headers = this.auth.getAuthHeaders('GET', `/data/${datasetId}/${key}`);

    // First get the data
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${datasetId}/${key}`,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Data not found",
        "DATA_NOT_FOUND",
        404,
      );
    }

    const data = response.data.data!;

    // Now get the proof for verification
    try {
      const proofHeaders = this.auth.getAuthHeaders('GET', `/proof/${datasetId}/${key}`);
      const proofResponse = await this.api.get<ApiResponse<ProofResponse>>(
        `/proof/${datasetId}/${key}`,
        { headers: proofHeaders },
      );

      if (proofResponse.data.success && proofResponse.data.data?.proof) {
        const proofData = proofResponse.data.data;

        // Verify the proof and compute root hash
        const path = ["subgroves", datasetId, "data"];
        const computedRootHash = await verifyItemProof(
          proofData.proof,
          key,
          data,
          path,
        );

        // Get verified root hash at the SAME block height as the proof.
        // This avoids the timing mismatch where the chain advances between
        // fetching the proof and fetching the latest verified header.
        const lightClient = await this.getOrCreateLightClient();
        const verifiedRootHash = proofData.height
          ? await lightClient.getVerifiedRootHashAtHeight(proofData.height)
          : await lightClient.getVerifiedRootHash();

        // Compare computed root with verified root
        if (computedRootHash.toLowerCase() !== verifiedRootHash.toLowerCase()) {
          console.error(
            `Root hash mismatch: computed=${computedRootHash}, verified=${verifiedRootHash}, height=${proofData.height}`,
          );
          throw new WillowError(
            "Proof verification failed: root hash mismatch",
            "PROOF_VERIFICATION_FAILED",
          );
        }
      } else {
        console.warn(`No proof available for key: ${key}`);
      }
    } catch (error) {
      if (error instanceof WillowError) {
        throw error;
      }
      // Any other error during proof fetch or verification is a verification
      // failure — a previous version swallowed these, which meant the caller
      // thought they had cryptographic verification when they didn't. If you
      // explicitly want data without verification, use `getDataUnverified`.
      throw new WillowError(
        `Proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
        "PROOF_VERIFICATION_FAILED",
      );
    }

    return data;
  }

  /**
   * Get data by key without proof verification (use with caution)
   */
  async getDataUnverified(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    const headers = this.auth.getAuthHeaders('GET', `/data/${datasetId}/${key}`);
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${datasetId}/${key}`,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Data not found",
        "DATA_NOT_FOUND",
        404,
      );
    }

    return response.data.data!;
  }

  /**
   * Update data by key
   */
  async updateData(
    datasetId: string,
    key: string,
    data: any,
  ): Promise<void> {
    const headers = this.auth.getAuthHeaders('PUT', `/data/${datasetId}/${key}`);
    const response = await this.api.put<ApiResponse>(
      `/data/${datasetId}/${key}`,
      data,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to update data",
        "UPDATE_FAILED",
      );
    }
  }

  /**
   * Delete data by key
   */
  async deleteData(
    datasetId: string,
    key: string,
  ): Promise<void> {
    const headers = this.auth.getAuthHeaders('DELETE', `/data/${datasetId}/${key}`);
    const response = await this.api.delete<ApiResponse>(
      `/data/${datasetId}/${key}`,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to delete data",
        "DELETE_FAILED",
      );
    }
  }

  /**
   * Get cryptographic proof for data
   */
  async getProof(
    datasetId: string,
    key: string,
  ): Promise<string> {
    const response = await this.api.get<ApiResponse<ProofResponse>>(
      `/proof/${datasetId}/${key}`,
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Failed to get proof",
        "PROOF_FAILED",
      );
    }

    return response.data.data!.proof;
  }

  /**
   * Batch operations helper
   */
  async batchStore(
    datasetId: string,
    records: Array<{ key: string; value: any }>,
  ): Promise<void> {
    const data: Record<string, any> = {};
    records.forEach(({ key, value }) => {
      data[key] = value;
    });

    await this.storeData(datasetId, data);
  }

  /**
   * Query helper - get multiple records with verification
   */
  async getMultiple(
    datasetId: string,
    keys: string[],
  ): Promise<Record<string, DataRecord>> {
    const results: Record<string, DataRecord> = {};

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          results[key] = await this.getData(datasetId, key);
        } catch (error) {
          // Ignore not found errors in bulk operations
          if (error instanceof WillowError && error.statusCode === 404) {
            return;
          }
          throw error;
        }
      }),
    );

    return results;
  }

  /**
   * Query helper - get multiple records without verification
   */
  async getMultipleUnverified(
    datasetId: string,
    keys: string[],
  ): Promise<Record<string, DataRecord>> {
    const results: Record<string, DataRecord> = {};

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          results[key] = await this.getDataUnverified(datasetId, key);
        } catch (error) {
          // Ignore not found errors in bulk operations
          if (error instanceof WillowError && error.statusCode === 404) {
            return;
          }
          throw error;
        }
      }),
    );

    return results;
  }

  /**
   * Get the verified root hash using the light client.
   *
   * Uses the light client for trustless verification. Auto-initializes
   * with trust-on-first-use if no light client is configured.
   *
   * @private
   */
  private async getVerifiedRootHash(): Promise<string> {
    const lightClient = await this.getOrCreateLightClient();
    return lightClient.getVerifiedRootHash();
  }

  /**
   * Query indexed data with automatic proof verification (secure by default)
   */
  async query(
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    // Always include proof by default for security
    const queryWithProof: QueryRequest = {
      ...query,
      include_proof: true,
    };

    const headers = this.auth.getAuthHeaders('POST', `/query/${datasetId}`);
    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${datasetId}`,
      queryWithProof,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Query failed",
        "QUERY_FAILED",
      );
    }

    const result = response.data.data!;

    // Verify proof if present
    if (result.proof) {
      try {
        // Verify the proof and compute root hash
        const computedRootHash = await verifyQueryProof(
          result.proof,
          result.documents,
        );

        // Get verified root hash at the same block height as the proof
        // to avoid timing mismatches on live chains.
        const proofHeight = (result as any).height as number | undefined;
        const lightClient = await this.getOrCreateLightClient();
        const verifiedRootHash = proofHeight
          ? await lightClient.getVerifiedRootHashAtHeight(proofHeight)
          : await lightClient.getVerifiedRootHash();

        // Compare computed root with verified root
        if (computedRootHash.toLowerCase() !== verifiedRootHash.toLowerCase()) {
          console.error(
            `Query proof verification failed: computed=${computedRootHash}, verified=${verifiedRootHash}, height=${proofHeight}`,
          );
          throw new WillowError(
            "Proof verification failed: root hash mismatch",
            "PROOF_VERIFICATION_FAILED",
          );
        }

        // Add verified root hash to response
        (result as any).verifiedRootHash = verifiedRootHash;
      } catch (error) {
        if (error instanceof WillowError) {
          throw error;
        }
        throw new WillowError(
          `Proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
          "PROOF_VERIFICATION_FAILED",
        );
      }
    }

    // Apply computed fields if registered for this dataset
    const computedFields = this.computedFieldRegistry.get(datasetId);
    if (computedFields) {
      return applyComputedFieldsToResponse(result, computedFields);
    }

    return result;
  }

  /**
   * Query indexed data without proof verification (use with caution)
   */
  async queryUnverified(
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    // Explicitly disable proof for performance
    const queryWithoutProof: QueryRequest = {
      ...query,
      include_proof: false,
    };

    const headers = this.auth.getAuthHeaders('POST', `/query/${datasetId}`);
    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${datasetId}`,
      queryWithoutProof,
      { headers },
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Query failed",
        "QUERY_FAILED",
      );
    }

    let result = response.data.data!;

    // Apply computed fields if registered for this dataset
    const computedFields = this.computedFieldRegistry.get(datasetId);
    if (computedFields) {
      result = applyComputedFieldsToResponse(result, computedFields);
    }

    return result;
  }

  // ============================================================================
  // Historical Data Queries (Checkpoint-based)
  // ============================================================================

  /**
   * Get checkpoint state root for proof verification.
   *
   * @param subgroveId - The subgrove ID
   * @param checkpointId - The checkpoint ID (hex string)
   * @returns Checkpoint info including state root
   */
  async getCheckpointStateRoot(
    subgroveId: string,
    checkpointId: string,
  ): Promise<CheckpointInfo> {
    const response = await this.api.get<ApiResponse<CheckpointInfo>>(
      `/checkpoints/${subgroveId}/${checkpointId}/state-root`,
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || "Checkpoint not found",
        "CHECKPOINT_NOT_FOUND",
        404,
      );
    }

    return response.data.data!;
  }

  /**
   * Query historical indexed data from a verified checkpoint.
   *
   * This method queries historical data from indexer nodes that have preserved
   * checkpoint data. The response includes proof information that can be
   * verified against the checkpoint's state root.
   *
   * @param subgroveId - The subgrove ID
   * @param checkpointId - The checkpoint ID (hex string)
   * @param query - The query parameters
   * @returns Historical query response with provider info and verification data
   *
   * @example
   * ```typescript
   * // Query historical data
   * const response = await client.data.queryHistorical(
   *   'my-subgrove',
   *   '0abc...', // checkpoint ID
   *   {
   *     path: [[97, 112, 112], [100, 97, 116, 97]], // UTF-8 bytes for path segments
   *     key: [107, 101, 121], // UTF-8 bytes for key
   *     include_proof: true
   *   }
   * );
   *
   * // Verify the response
   * if (response.success) {
   *   // Use response.state_root to verify the proof client-side
   *   console.log('Provider:', response.provider_did);
   *   console.log('State root:', response.state_root);
   * } else if (response.can_reindex) {
   *   console.log('Data unavailable, can request re-indexing');
   * }
   * ```
   */
  async queryHistorical(
    subgroveId: string,
    checkpointId: string,
    query: HistoricalQueryRequest,
  ): Promise<HistoricalQueryResponse> {
    // First, verify the checkpoint exists and get its state root
    const checkpoint = await this.getCheckpointStateRoot(
      subgroveId,
      checkpointId,
    );

    // Make the historical query
    const response = await this.api.post<HistoricalQueryResponse>(
      `/historical/query/${subgroveId}/${checkpointId}`,
      query,
    );

    const result = response.data;

    // If query failed due to no providers, throw with can_reindex info
    if (!result.success) {
      const error = new WillowError(
        result.error || "Historical query failed",
        result.can_reindex
          ? "HISTORICAL_DATA_UNAVAILABLE"
          : "HISTORICAL_QUERY_FAILED",
        result.can_reindex ? 503 : 400,
      );
      (error as any).can_reindex = result.can_reindex;
      throw error;
    }

    // Verify the returned state root matches the checkpoint
    if (result.state_root !== checkpoint.state_root) {
      throw new WillowError(
        "State root mismatch: query response does not match checkpoint",
        "STATE_ROOT_MISMATCH",
      );
    }

    return result;
  }

  /**
   * Query historical data and verify the proof against checkpoint state root.
   *
   * This is the fully secure method for historical queries. It:
   * 1. Gets the checkpoint state root from consensus
   * 2. Executes the query through an indexer
   * 3. Verifies the returned proof against the checkpoint state root
   *
   * @param subgroveId - The subgrove ID
   * @param checkpointId - The checkpoint ID (hex string)
   * @param query - The query parameters (include_proof is forced to true)
   * @returns Verified historical data
   *
   * @throws {WillowError} If proof verification fails
   */
  async queryHistoricalVerified(
    subgroveId: string,
    checkpointId: string,
    query: HistoricalQueryRequest,
  ): Promise<HistoricalQueryResponse> {
    // Force proof inclusion for verification
    const queryWithProof: HistoricalQueryRequest = {
      ...query,
      include_proof: true,
    };

    const result = await this.queryHistorical(
      subgroveId,
      checkpointId,
      queryWithProof,
    );

    // Verify the proof against the checkpoint state root
    if (result.proof) {
      // Convert data to DataRecord[] format for verification
      const documents = Array.isArray(result.data)
        ? result.data
        : [result.data];

      // Verify proof and get computed root hash
      const computedRoot = await verifyQueryProof(result.proof, documents);

      // Compare with the checkpoint's state root (both should be hex strings)
      const normalizedComputed = computedRoot.toLowerCase().replace(/^0x/, "");
      const normalizedExpected = result.state_root
        .toLowerCase()
        .replace(/^0x/, "");

      if (normalizedComputed !== normalizedExpected) {
        throw new WillowError(
          `Historical proof verification failed: computed root ${computedRoot} does not match checkpoint state root ${result.state_root}`,
          "PROOF_VERIFICATION_FAILED",
        );
      }
    } else {
      // Proof was requested but not returned
      throw new WillowError(
        "Historical query did not return proof data despite include_proof=true",
        "MISSING_PROOF",
      );
    }

    return result;
  }

  /**
   * Execute a SQL query against a subgrove with optional Merkle proof.
   *
   * Routes to the validator (chain-tip) or an indexer (full history) based
   * on `options.source`. Defaults to `'auto'`: prefers an indexer when one
   * serves this subgrove, falling back to the validator's chain-tip data.
   *
   * @param subgroveId - Subgrove ID to query
   * @param sql - SQL SELECT query string
   * @param options - Query options including source selection
   * @returns SQL query response plus routing metadata (`source`, `fallback`)
   */
  async sqlQuery(
    subgroveId: string,
    sql: string,
    options?: SqlQueryOptions,
  ): Promise<SqlQueryResult> {
    const body = {
      query: sql,
      include_proof: options?.includeProof ?? false,
    };

    return this.routeQuery<SqlQueryResponse>(
      subgroveId,
      "sql",
      body,
      options?.source ?? "auto",
    );
  }

  /**
   * Execute a GraphQL query against a subgrove.
   *
   * Routes to the validator (chain-tip, consensus-verified) or an indexer
   * (full history, analytics-friendly) based on `options.source`. Defaults
   * to `'auto'`.
   *
   * @param subgroveId - Subgrove ID to query
   * @param query - GraphQL query string
   * @param options - Query options including source selection and variables
   * @returns GraphQL response plus routing metadata (`source`, `fallback`)
   */
  async graphqlQuery(
    subgroveId: string,
    query: string,
    options?: GraphQLQueryOptions,
  ): Promise<GraphQLQueryResult> {
    const body: Record<string, unknown> = { query };
    if (options?.variables) body.variables = options.variables;
    if (options?.operationName) body.operationName = options.operationName;

    return this.routeQuery(
      subgroveId,
      "graphql",
      body,
      options?.source ?? "auto",
    );
  }

  /**
   * Shared routing helper for `/graphql/:subgrove` and `/sql/:subgrove`.
   *
   * Behaviour by source:
   * - `'validator'`: POST to `{apiUrl}/{path}/:sg`; surface errors as-is.
   *   When the validator has no data (VerifyOnly subgrove, pruned retention),
   *   throws `ValidatorHasNoDataError` instead of silently falling back.
   * - `'indexer'`: walk the discovery-cached indexer list (or a synthetic
   *   single-entry list when `indexerUrl` was configured), try each in
   *   performance order, and throw `NoIndexersReachableError` if all fail.
   * - `'auto'` (default): try an indexer first if any serves the subgrove;
   *   fall back to the validator on any indexer failure, annotating the
   *   result with `fallback: true`.
   */
  private async routeQuery<T>(
    subgroveId: string,
    path: "graphql" | "sql",
    body: unknown,
    source: QuerySource,
  ): Promise<{ result: T; source: "validator" | "indexer"; indexerDid?: string; fallback: boolean }> {
    const httpPath = `/${path}/${subgroveId}`;
    const headers = this.auth.getAuthHeaders("POST", httpPath);

    const callValidator = async (): Promise<T> => {
      try {
        const resp = await this.api.post<T>(httpPath, body, { headers });
        return resp.data;
      } catch (err: any) {
        // When the validator refuses because the data isn't available
        // here (VerifyOnly retention, pruned, not indexed by consensus),
        // surface a typed error rather than a raw axios failure so
        // callers can react programmatically.
        const status = err?.response?.status as number | undefined;
        const msg = err?.response?.data?.error ?? err?.message ?? "unknown error";
        if (status === 403 || status === 404 || /VerifyOnly|not indexed|not available/i.test(String(msg))) {
          throw new ValidatorHasNoDataError(subgroveId, String(msg));
        }
        throw err;
      }
    };

    const callIndexer = async (info: ApiIndexerInfo): Promise<T> => {
      const url = `${effectiveQueryEndpoint(info).replace(/\/$/, "")}${httpPath}`;
      const resp = await axios.post<T>(url, body, { headers });
      return resp.data;
    };

    if (source === "validator") {
      const result = await callValidator();
      return { result, source: "validator", fallback: false };
    }

    if (source === "indexer") {
      const candidates = await this.indexers.forSubgrove(subgroveId);
      if (candidates.length === 0) {
        throw new NoIndexersReachableError(
          subgroveId,
          "no indexer in the registry serves this subgrove",
        );
      }
      const errors: string[] = [];
      for (const info of candidates) {
        try {
          const result = await callIndexer(info);
          return { result, source: "indexer", indexerDid: info.indexer_did, fallback: false };
        } catch (err: any) {
          const status = err?.response?.status as number | undefined;
          if (status && status >= 500) this.indexers.evict(info.indexer_did);
          errors.push(`${info.indexer_did}: ${err?.message ?? err}`);
        }
      }
      throw new NoIndexersReachableError(subgroveId, errors.join("; "));
    }

    // source === 'auto'
    const candidates = await this.indexers.forSubgrove(subgroveId);
    for (const info of candidates) {
      try {
        const result = await callIndexer(info);
        return { result, source: "indexer", indexerDid: info.indexer_did, fallback: false };
      } catch (err: any) {
        const status = err?.response?.status as number | undefined;
        if (status && status >= 500) this.indexers.evict(info.indexer_did);
        // continue to next indexer / fall back to validator
      }
    }
    const result = await callValidator();
    return { result, source: "validator", fallback: candidates.length > 0 };
  }
}

/**
 * Extension methods for QueryResponse
 */
export interface QueryResponseExt extends QueryResponse {
  verifyProof(): Promise<string>;
}

/**
 * Add verification method to QueryResponse
 */
export function extendQueryResponse(response: QueryResponse): QueryResponseExt {
  return {
    ...response,
    async verifyProof(): Promise<string> {
      if (!response.proof) {
        throw new WillowError(
          "Query response does not contain proof data",
          "NO_PROOF",
        );
      }
      return verifyQueryProof(response.proof, response.documents);
    },
  };
}
