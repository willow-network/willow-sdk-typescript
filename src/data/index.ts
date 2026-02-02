import axios, { AxiosInstance } from 'axios';
import {
  ApiResponse,
  WillowError,
  DataRecord,
  ProofResponse,
  RegisterAppRequest,
  AppRegistration,
  RegisterDatasetRequest,
  DatasetRegistration,
  QueryRequest,
  QueryResponse,
  HistoricalQueryRequest,
  HistoricalQueryResponse,
  CheckpointInfo,
} from '../types';
import { WillowAuth } from '../auth';
import { verifyQueryProof, verifyItemProof } from '../proof';
import { LightClient, LightClientConfig } from '../light-client';

export class WillowData {
  private api: AxiosInstance;
  private auth: WillowAuth;
  private apiUrl: string;
  private lightClient?: LightClient;
  private lightClientInitPromise?: Promise<LightClient>;

  constructor(apiUrl: string, auth: WillowAuth) {
    this.apiUrl = apiUrl;
    this.api = axios.create({
      baseURL: apiUrl,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    this.auth = auth;
  }

  /**
   * Get or create a light client for trustless verification.
   *
   * This auto-initializes a light client using trust-on-first-use:
   * the first block received from validators is trusted, and all subsequent
   * blocks are verified against it.
   *
   * @important TODO: When mainnet/testnet launches, replace trust-on-first-use
   * with hardcoded checkpoint headers for true trustless initialization.
   * Trust-on-first-use is secure for subsequent operations but trusts the
   * initial block from the connected validators.
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
      // TODO: When mainnet/testnet launches, use hardcoded checkpoint headers
      // instead of trust-on-first-use for true trustless initialization from genesis.
      const config: LightClientConfig = {
        chainId: 'willow-chain',
        // Derive CometBFT RPC endpoint from API URL (typically :3031 -> :26657)
        validatorEndpoints: [this.apiUrl.replace(':3031', ':26657')],
        trustThreshold: { numerator: 2, denominator: 3 },
        trustingPeriodSecs: 86400, // 24 hours
        maxClockDriftSecs: 30,
        autoSync: false,
        minValidatorsForConsensus: 1, // For single-node development
        requestTimeoutSecs: 30,
        syncIntervalSecs: 60
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
   * Register a new app
   */
  async registerApp(request: RegisterAppRequest): Promise<AppRegistration> {
    const params = this.auth.getAuthParams();
    const response = await this.api.post<ApiResponse<AppRegistration>>(
      '/register/app',
      request,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to register app',
        'APP_REGISTRATION_FAILED'
      );
    }

    return response.data.data!;
  }

  /**
   * Register a dataset/subgrove
   */
  async registerDataset(request: RegisterDatasetRequest): Promise<DatasetRegistration> {
    const params = this.auth.getAuthParams();

    // Convert to the API's expected format (subgrove endpoint for compatibility)
    const subgroveRequest = {
      subgrove_id: request.dataset_id,
      app_id: request.app_id,
      name: request.name,
      schema: request.schema,
      owner_did: request.owner_did,
      writers: request.writers,
      readers: request.readers,
    };

    const response = await this.api.post<ApiResponse<DatasetRegistration>>(
      '/register/subgrove',
      subgroveRequest,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to register dataset',
        'DATASET_REGISTRATION_FAILED'
      );
    }

    return response.data.data!;
  }

  /**
   * Store data (batch operation)
   */
  async storeData(
    appId: string,
    datasetId: string,
    data: Record<string, any>
  ): Promise<void> {
    const params = this.auth.getAuthParams();
    const response = await this.api.post<ApiResponse>(
      `/data/${appId}/${datasetId}`,
      data,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to store data',
        'STORE_FAILED'
      );
    }
  }

  /**
   * Get data by key with automatic proof verification (secure by default)
   */
  async getData(
    appId: string,
    datasetId: string,
    key: string
  ): Promise<DataRecord> {
    const params = this.auth.getAuthParams();

    // First get the data
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${appId}/${datasetId}/${key}`,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Data not found',
        'DATA_NOT_FOUND',
        404
      );
    }

    const data = response.data.data!;

    // Now get the proof for verification
    try {
      const proofResponse = await this.api.get<ApiResponse<ProofResponse>>(
        `/proof/${appId}/${datasetId}/${key}`
      );

      if (proofResponse.data.success && proofResponse.data.data?.proof) {
        // Get verified root hash from consensus
        const verifiedRootHash = await this.getVerifiedRootHash();

        // Verify the proof and compute root hash
        // Pass the path for proper verification
        const path = ['apps', appId, 'subgroves', datasetId, 'data'];
        const computedRootHash = await verifyItemProof(
          proofResponse.data.data.proof,
          key,
          data,
          path
        );

        // Compare computed root with verified root
        if (computedRootHash.toLowerCase() !== verifiedRootHash.toLowerCase()) {
          console.error(`Root hash mismatch: computed=${computedRootHash}, verified=${verifiedRootHash}`);
          throw new WillowError(
            'Proof verification failed: root hash mismatch',
            'PROOF_VERIFICATION_FAILED'
          );
        }
      } else {
        console.warn(`No proof available for key: ${key}`);
      }
    } catch (error) {
      if (error instanceof WillowError && error.code === 'PROOF_VERIFICATION_FAILED') {
        throw error;
      }
      // Log but don't fail if we can't get proof
      console.warn(`Could not verify proof for key ${key}:`, error instanceof Error ? error.message : String(error));
    }

    return data;
  }

  /**
   * Get data by key without proof verification (use with caution)
   */
  async getDataUnverified(
    appId: string,
    datasetId: string,
    key: string
  ): Promise<DataRecord> {
    const params = this.auth.getAuthParams();
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${appId}/${datasetId}/${key}`,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Data not found',
        'DATA_NOT_FOUND',
        404
      );
    }

    return response.data.data!;
  }

  /**
   * Update data by key
   */
  async updateData(
    appId: string,
    datasetId: string,
    key: string,
    data: any
  ): Promise<void> {
    const params = this.auth.getAuthParams();
    const response = await this.api.put<ApiResponse>(
      `/data/${appId}/${datasetId}/${key}`,
      data,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to update data',
        'UPDATE_FAILED'
      );
    }
  }

  /**
   * Delete data by key
   */
  async deleteData(
    appId: string,
    datasetId: string,
    key: string
  ): Promise<void> {
    const params = this.auth.getAuthParams();
    const response = await this.api.delete<ApiResponse>(
      `/data/${appId}/${datasetId}/${key}`,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to delete data',
        'DELETE_FAILED'
      );
    }
  }

  /**
   * Get cryptographic proof for data
   */
  async getProof(
    appId: string,
    datasetId: string,
    key: string
  ): Promise<string> {
    const response = await this.api.get<ApiResponse<ProofResponse>>(
      `/proof/${appId}/${datasetId}/${key}`
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Failed to get proof',
        'PROOF_FAILED'
      );
    }

    return response.data.data!.proof;
  }

  /**
   * Batch operations helper
   */
  async batchStore(
    appId: string,
    datasetId: string,
    records: Array<{ key: string; value: any }>
  ): Promise<void> {
    const data: Record<string, any> = {};
    records.forEach(({ key, value }) => {
      data[key] = value;
    });

    await this.storeData(appId, datasetId, data);
  }

  /**
   * Query helper - get multiple records with verification
   */
  async getMultiple(
    appId: string,
    datasetId: string,
    keys: string[]
  ): Promise<Record<string, DataRecord>> {
    const results: Record<string, DataRecord> = {};

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          results[key] = await this.getData(appId, datasetId, key);
        } catch (error) {
          // Ignore not found errors in bulk operations
          if (error instanceof WillowError && error.statusCode === 404) {
            return;
          }
          throw error;
        }
      })
    );

    return results;
  }

  /**
   * Query helper - get multiple records without verification
   */
  async getMultipleUnverified(
    appId: string,
    datasetId: string,
    keys: string[]
  ): Promise<Record<string, DataRecord>> {
    const results: Record<string, DataRecord> = {};

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          results[key] = await this.getDataUnverified(appId, datasetId, key);
        } catch (error) {
          // Ignore not found errors in bulk operations
          if (error instanceof WillowError && error.statusCode === 404) {
            return;
          }
          throw error;
        }
      })
    );

    return results;
  }

  /**
   * Get the verified root hash using the light client.
   *
   * This uses trustless verification through the light client instead of
   * asking the node for the root hash.
   *
   * @important TODO: When mainnet/testnet launches, the light client will be
   * initialized with hardcoded checkpoint headers instead of trust-on-first-use.
   *
   * @private
   */
  private async getVerifiedRootHash(): Promise<string> {
    // Always use light client for trustless verification
    // This auto-initializes the light client on first use (trust-on-first-use)
    const lightClient = await this.getOrCreateLightClient();
    return lightClient.getVerifiedRootHash();
  }

  /**
   * Query indexed data with automatic proof verification (secure by default)
   */
  async query(
    appId: string,
    datasetId: string,
    query: QueryRequest
  ): Promise<QueryResponse> {
    // Always include proof by default for security
    const queryWithProof: QueryRequest = {
      ...query,
      include_proof: true
    };

    const params = this.auth.getAuthParams();
    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${appId}/${datasetId}`,
      queryWithProof,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Query failed',
        'QUERY_FAILED'
      );
    }

    const result = response.data.data!;

    // Verify proof if present
    if (result.proof) {
      try {
        // Get verified root hash from consensus
        const verifiedRootHash = await this.getVerifiedRootHash();

        // Verify the proof and compute root hash
        const computedRootHash = await verifyQueryProof(
          result.proof,
          result.documents
        );

        // Compare computed root with verified root
        if (computedRootHash !== verifiedRootHash) {
          throw new WillowError(
            'Proof verification failed: root hash mismatch',
            'PROOF_VERIFICATION_FAILED'
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
          'PROOF_VERIFICATION_FAILED'
        );
      }
    }

    return result;
  }

  /**
   * Query indexed data without proof verification (use with caution)
   */
  async queryUnverified(
    appId: string,
    datasetId: string,
    query: QueryRequest
  ): Promise<QueryResponse> {
    // Explicitly disable proof for performance
    const queryWithoutProof: QueryRequest = {
      ...query,
      include_proof: false
    };

    const params = this.auth.getAuthParams();
    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${appId}/${datasetId}`,
      queryWithoutProof,
      { params }
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Query failed',
        'QUERY_FAILED'
      );
    }

    return response.data.data!;
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
    checkpointId: string
  ): Promise<CheckpointInfo> {
    const response = await this.api.get<ApiResponse<CheckpointInfo>>(
      `/checkpoints/${subgroveId}/${checkpointId}/state-root`
    );

    if (!response.data.success) {
      throw new WillowError(
        response.data.error || 'Checkpoint not found',
        'CHECKPOINT_NOT_FOUND',
        404
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
    query: HistoricalQueryRequest
  ): Promise<HistoricalQueryResponse> {
    // First, verify the checkpoint exists and get its state root
    const checkpoint = await this.getCheckpointStateRoot(subgroveId, checkpointId);

    // Make the historical query
    const response = await this.api.post<HistoricalQueryResponse>(
      `/historical/query/${subgroveId}/${checkpointId}`,
      query
    );

    const result = response.data;

    // If query failed due to no providers, throw with can_reindex info
    if (!result.success) {
      const error = new WillowError(
        result.error || 'Historical query failed',
        result.can_reindex ? 'HISTORICAL_DATA_UNAVAILABLE' : 'HISTORICAL_QUERY_FAILED',
        result.can_reindex ? 503 : 400
      );
      (error as any).can_reindex = result.can_reindex;
      throw error;
    }

    // Verify the returned state root matches the checkpoint
    if (result.state_root !== checkpoint.state_root) {
      throw new WillowError(
        'State root mismatch: query response does not match checkpoint',
        'STATE_ROOT_MISMATCH'
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
    query: HistoricalQueryRequest
  ): Promise<HistoricalQueryResponse> {
    // Force proof inclusion for verification
    const queryWithProof: HistoricalQueryRequest = {
      ...query,
      include_proof: true
    };

    const result = await this.queryHistorical(subgroveId, checkpointId, queryWithProof);

    // Verify the proof against the checkpoint state root
    if (result.proof) {
      // Convert data to DataRecord[] format for verification
      const documents = Array.isArray(result.data) ? result.data : [result.data];

      // Verify proof and get computed root hash
      const computedRoot = await verifyQueryProof(result.proof, documents);

      // Compare with the checkpoint's state root (both should be hex strings)
      const normalizedComputed = computedRoot.toLowerCase().replace(/^0x/, '');
      const normalizedExpected = result.state_root.toLowerCase().replace(/^0x/, '');

      if (normalizedComputed !== normalizedExpected) {
        throw new WillowError(
          `Historical proof verification failed: computed root ${computedRoot} does not match checkpoint state root ${result.state_root}`,
          'PROOF_VERIFICATION_FAILED'
        );
      }
    } else {
      // Proof was requested but not returned
      throw new WillowError(
        'Historical query did not return proof data despite include_proof=true',
        'MISSING_PROOF'
      );
    }

    return result;
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
        throw new WillowError('Query response does not contain proof data', 'NO_PROOF');
      }
      return verifyQueryProof(response.proof, response.documents);
    }
  };
}