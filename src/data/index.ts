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
} from '../types';
import { WillowAuth } from '../auth';
import { verifyQueryProof, verifyItemProof } from '../proof';

export class WillowData {
  private api: AxiosInstance;
  private auth: WillowAuth;
  private apiUrl: string;

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
   * Get the verified root hash from the blockchain consensus
   * @private
   */
  private async getVerifiedRootHash(): Promise<string> {
    const response = await this.api.get<ApiResponse<{ root_hash: string }>>(
      '/state/root-hash/verified'
    );

    if (!response.data.success || !response.data.data?.root_hash) {
      throw new WillowError(
        'Failed to get verified root hash',
        'ROOT_HASH_FAILED'
      );
    }

    return response.data.data.root_hash;
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