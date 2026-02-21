import { WillowAuth } from "./auth";
import { WillowData } from "./data";
import {
  WillowConfig,
  DidDocument,
  Session,
  RegisterAppRequest,
  AppRegistration,
  RegisterDatasetRequest,
  DatasetRegistration,
  DataRecord,
  QueryRequest,
  QueryResponse,
} from "./types";
import { configureProofVerification, ProofVerificationOptions } from "./proof";
import { ComputedFieldSet } from "./computed-fields";

/**
 * Main Willow SDK client
 */
export class WillowClient {
  private config: WillowConfig;
  public auth: WillowAuth;
  public data: WillowData;

  constructor(config: WillowConfig) {
    this.config = config;
    this.auth = new WillowAuth(config.apiUrl);
    this.data = new WillowData(config.apiUrl, this.auth);

    // Configure proof verification if options provided
    if (config.proofVerificationOptions) {
      configureProofVerification(config.proofVerificationOptions);
    }
  }

  /**
   * Initialize the client with authentication
   */
  async init(privateKey?: string, publicKeyId?: string): Promise<void> {
    if (!this.config.did) {
      throw new Error("DID is required for initialization");
    }

    const key = privateKey || this.config.privateKey;
    if (!key) {
      throw new Error("Private key is required for authentication");
    }

    if (!publicKeyId) {
      // Try to guess the public key ID from the DID document
      const didDoc = await this.auth.getDid(this.config.did);
      if (didDoc.publicKeys.length === 0) {
        throw new Error("No public keys found in DID document");
      }
      publicKeyId = didDoc.publicKeys[0].id;
    }

    await this.auth.login(this.config.did, key, publicKeyId);
  }

  /**
   * Register a new DID
   */
  async registerDid(didDocument: DidDocument): Promise<DidDocument> {
    return this.auth.registerDid(didDocument);
  }

  /**
   * Get current session
   */
  getSession(): Session | undefined {
    return this.auth.getSession();
  }

  /**
   * Register a new app
   */
  async registerApp(request: RegisterAppRequest): Promise<AppRegistration> {
    return this.data.registerApp(request);
  }

  /**
   * Register a dataset
   */
  async registerDataset(
    request: RegisterDatasetRequest,
  ): Promise<DatasetRegistration> {
    return this.data.registerDataset(request);
  }

  /**
   * Store data
   */
  async store(
    appId: string,
    datasetId: string,
    key: string,
    value: any,
  ): Promise<void> {
    await this.data.storeData(appId, datasetId, { [key]: value });
  }

  /**
   * Get data with automatic proof verification (secure by default)
   */
  async get(
    appId: string,
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    return this.data.getData(appId, datasetId, key);
  }

  /**
   * Get data without proof verification (use with caution)
   */
  async getUnverified(
    appId: string,
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    return this.data.getDataUnverified(appId, datasetId, key);
  }

  /**
   * Update data
   */
  async update(
    appId: string,
    datasetId: string,
    key: string,
    value: any,
  ): Promise<void> {
    return this.data.updateData(appId, datasetId, key, value);
  }

  /**
   * Delete data
   */
  async delete(appId: string, datasetId: string, key: string): Promise<void> {
    return this.data.deleteData(appId, datasetId, key);
  }

  /**
   * Get proof
   */
  async getProof(
    appId: string,
    datasetId: string,
    key: string,
  ): Promise<string> {
    return this.data.getProof(appId, datasetId, key);
  }

  /**
   * Get the verified root hash from the blockchain consensus
   *
   * This method retrieves the root hash that has been committed to the blockchain
   * and verified by the consensus mechanism. This is the most secure way to get
   * the root hash as it ensures the state has been agreed upon by the network.
   *
   * @returns The verified root hash from the blockchain
   * @throws Error if the root hash cannot be retrieved
   */
  async getRootHash(): Promise<string> {
    const response = await fetch(
      `${this.config.apiUrl}/state/root-hash/verified`,
    );
    if (!response.ok) {
      throw new Error(
        `Failed to get verified root hash: ${response.statusText}`,
      );
    }
    const data = (await response.json()) as {
      success: boolean;
      data?: { root_hash: string };
    };
    if (!data.success || !data.data?.root_hash) {
      throw new Error("No root hash in response");
    }
    return data.data.root_hash;
  }

  /**
   * Get the local root hash from the node's current state
   *
   * This method retrieves the root hash from the node's local state tree.
   * This may be more recent than the verified root hash but has not yet been
   * committed to the blockchain. Use this only when you need the absolute
   * latest state and understand the security implications.
   *
   * @returns The local root hash from the node's state
   * @throws Error if the root hash cannot be retrieved
   */
  async getRootHashLocal(): Promise<string> {
    const response = await fetch(`${this.config.apiUrl}/state/root-hash`);
    if (!response.ok) {
      throw new Error(`Failed to get local root hash: ${response.statusText}`);
    }
    const data = (await response.json()) as {
      success: boolean;
      data?: { root_hash: string };
    };
    if (!data.success || !data.data?.root_hash) {
      throw new Error("No root hash in response");
    }
    return data.data.root_hash;
  }

  /**
   * Query indexed data with automatic proof verification (secure by default)
   */
  async query(
    appId: string,
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    return this.data.query(appId, datasetId, query);
  }

  /**
   * Query indexed data without proof verification (use with caution)
   */
  async queryUnverified(
    appId: string,
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    return this.data.queryUnverified(appId, datasetId, query);
  }

  /**
   * Register computed fields for a specific app/dataset.
   *
   * Computed fields are derived client-side from proven data. This enables
   * drop-in compatibility with The Graph's query interfaces by computing
   * values like price ratios from cryptographically proven reserves.
   *
   * @param appId - The application ID
   * @param datasetId - The dataset ID
   * @param fields - The computed field definitions
   *
   * @example
   * ```typescript
   * import { WillowClient, UNISWAP_V2_PAIR_FIELDS } from '@willow/sdk';
   *
   * const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
   * client.registerComputedFields('uniswap-v2', 'pairs', UNISWAP_V2_PAIR_FIELDS);
   *
   * // Queries now return computed prices alongside proven reserves
   * const result = await client.query('uniswap-v2', 'pairs', { filters: { id: '0x...' } });
   * console.log(result.documents[0].token0Price); // Computed from proven reserves
   * ```
   */
  registerComputedFields(
    appId: string,
    datasetId: string,
    fields: ComputedFieldSet,
  ): void {
    this.data.registerComputedFields(appId, datasetId, fields);
  }

  /**
   * Create a helper for a specific app/dataset
   */
  collection(appId: string, datasetId: string) {
    return {
      store: (key: string, value: any) =>
        this.store(appId, datasetId, key, value),
      get: (key: string) => this.get(appId, datasetId, key),
      getUnverified: (key: string) =>
        this.data.getDataUnverified(appId, datasetId, key),
      update: (key: string, value: any) =>
        this.update(appId, datasetId, key, value),
      delete: (key: string) => this.delete(appId, datasetId, key),
      getProof: (key: string) => this.getProof(appId, datasetId, key),
      batchStore: (records: Array<{ key: string; value: any }>) =>
        this.data.batchStore(appId, datasetId, records),
      getMultiple: (keys: string[]) =>
        this.data.getMultiple(appId, datasetId, keys),
      getMultipleUnverified: (keys: string[]) =>
        this.data.getMultipleUnverified(appId, datasetId, keys),
      query: (query: any) => this.data.query(appId, datasetId, query),
      queryUnverified: (query: any) =>
        this.data.queryUnverified(appId, datasetId, query),
    };
  }
}
