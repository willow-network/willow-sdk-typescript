import { WillowAuth } from "./auth";
import { WillowData } from "./data";
import { FileOperations } from "./files";
import { EthOperations } from "./eth-state";
import { VerifiableRpcOperations } from "./verifiable-rpc";
import { ConsensusClient } from "./consensus";
import { BroadcastResult, RegisterSubgroveOptions, Signer, SubgroveMode } from "./consensus/types";
import { WillowIndexers } from "./indexers";
import { WillowSubscriptions } from "./subscriptions";
import {
  WillowConfig,
  DidDocument,
  RegisterSubgroveRequest,
  DataRecord,
  QueryRequest,
  QueryResponse,
  SqlQueryResult,
  SqlQueryOptions,
  GraphQLQueryResult,
  GraphQLQueryOptions,
} from "./types";
import { ComputedFieldSet } from "./computed-fields";

/**
 * Derive the CometBFT RPC URL from the API URL for local devnets only
 * (API port 3030+N → RPC port 26557+N*100). For any non-localhost host the
 * mapping is deployment-specific, so no URL is derived — operations that
 * need CometBFT RPC then throw `CONSENSUS_RPC_URL_REQUIRED` until the
 * caller sets `consensusRpcUrl` in the config.
 */
function deriveCometBftUrl(apiUrl: string): string | undefined {
  let hostname: string;
  try {
    hostname = new URL(apiUrl).hostname;
  } catch {
    return undefined;
  }
  if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
    return undefined;
  }
  const match = apiUrl.match(/:(\d+)(\/)?$/);
  if (match) {
    const apiPort = parseInt(match[1]);
    const nodeN = apiPort - 3030;
    if (nodeN >= 1 && nodeN <= 10) {
      const rpcPort = 26557 + nodeN * 100;
      return apiUrl.replace(`:${apiPort}`, `:${rpcPort}`);
    }
  }
  return undefined;
}

/**
 * Main Willow SDK client
 */
export class WillowClient {
  private config: WillowConfig;
  public auth: WillowAuth;
  public data: WillowData;
  public files: FileOperations;
  public consensus: ConsensusClient;
  /** Indexer discovery client (reads validator's `/indexers` with 30s cache). */
  public indexers: WillowIndexers;
  /** GraphQL subscription client (WebSocket → validator `/graphql/ws`). */
  public subscriptions: WillowSubscriptions;
  /** Verifiable Ethereum state-read operations (`/verifiable-rpc/eth/*`). */
  public eth: EthOperations;
  /** Direct indexer→client verifiable reads (inclusion + transformation proofs). */
  public verifiableRpc: VerifiableRpcOperations;

  constructor(config: WillowConfig) {
    this.config = config;
    this.auth = new WillowAuth(config.apiUrl, config.apiKey);
    const cometUrl = config.consensusRpcUrl ?? deriveCometBftUrl(config.apiUrl);

    // Discovery layer. When the caller set `indexerUrl` explicitly, the
    // instance short-circuits discovery and returns a synthetic single-
    // entry list so the data-layer routing code stays uniform.
    this.indexers = new WillowIndexers(config.apiUrl, {
      indexerUrl: config.indexerUrl,
    });

    this.data = new WillowData(
      config.apiUrl,
      this.auth,
      this.indexers,
      cometUrl,
      config.proofVerificationOptions,
      { logger: config.logger, lightClient: config.lightClient },
    );
    this.subscriptions = new WillowSubscriptions(config.apiUrl, this.indexers, {
      webSocket: config.webSocket,
    });

    this.files = new FileOperations(config.apiUrl, (method, path) =>
      this.auth.getAuthHeaders(method, path),
    );
    this.eth = new EthOperations(config.indexerUrl ?? config.apiUrl, undefined, config.apiKey);
    this.verifiableRpc = new VerifiableRpcOperations(config.indexerUrl ?? config.apiUrl);

    this.consensus = new ConsensusClient({
      consensusRpcUrl: cometUrl,
      apiUrl: config.apiUrl,
      apiKey: config.apiKey,
      logger: config.logger,
    });

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
      const didDoc = await this.auth.getDidDocument(this.config.did);
      if (didDoc.publicKeys.length === 0) {
        throw new Error("No public keys found in DID document");
      }
      publicKeyId = didDoc.publicKeys[0].id;
    }

    this.auth.setIdentity(this.config.did, key, publicKeyId);
  }

  /**
   * Register a new DID
   */
  async registerDid(didDocument: DidDocument): Promise<DidDocument> {
    return this.auth.registerDid(didDocument);
  }

  /**
   * Register a subgrove via a consensus transaction.
   *
   * The request's `name`, `writers`, and `readers` become a `DataStorage`
   * subgrove mode (`readers` maps to the on-chain `free_readers`). Pass
   * `options.mode` to register a non-DataStorage subgrove (FileStorage,
   * BlockchainIndexing) — an explicit mode takes precedence over the
   * request's access lists. `options` also carries `retentionWindow` and
   * `initialFunding`.
   *
   * Returns the consensus `BroadcastResult` (tx hash, height, raw log) —
   * the SDK does not synthesize a registration record; read the subgrove
   * back from the chain if you need its stored state.
   */
  async registerSubgrove(
    request: RegisterSubgroveRequest,
    options?: RegisterSubgroveOptions,
  ): Promise<BroadcastResult> {
    this.requireIdentity();
    const mode: SubgroveMode =
      options?.mode ?? {
        DataStorage: {
          name: request.name,
          writers: request.writers,
          free_readers: request.readers,
        },
      };
    const result = await this.consensus.registerSubgrove(
      request.dataset_id,
      JSON.stringify(request.schema ?? {}),
      this.auth.getDid()!,
      this.signer(),
      { name: request.name, ...options, mode },
    );
    if (!result.success) {
      throw new Error(
        `registerSubgrove failed: ${result.errorMessage ?? result.rawLog ?? 'unknown'}`,
      );
    }
    return result;
  }

  /** @deprecated Use {@link registerSubgrove} — "subgrove" is the on-chain term. */
  async registerDataset(
    request: RegisterSubgroveRequest,
    options?: RegisterSubgroveOptions,
  ): Promise<BroadcastResult> {
    return this.registerSubgrove(request, options);
  }

  /**
   * Deregister a subgrove. Remaining funding is refunded to the owner.
   *
   * Re-registering with a different start_block or schema requires
   * deregistering first — RegisterSubgroveTx is idempotent on the server,
   * so a second register of the same subgrove_id is a no-op. The server
   * bumps `deployment_epoch` on deregister, which indexers watch for to
   * restart their pipelines on the next loop tick.
   */
  async deregisterSubgrove(subgroveId: string): Promise<BroadcastResult> {
    this.requireIdentity();
    return this.consensus.deregisterSubgrove(
      subgroveId,
      this.auth.getDid()!,
      this.signer(),
    );
  }

  /**
   * Store data via a consensus transaction.
   */
  async store(
    datasetId: string,
    key: string,
    value: any,
  ): Promise<void> {
    this.requireIdentity();
    const result = await this.consensus.storeData(
      datasetId,
      key,
      value,
      this.auth.getDid()!,
      this.signer(),
    );
    if (!result.success) {
      throw new Error(
        `store failed: ${result.errorMessage ?? result.rawLog ?? 'unknown'}`,
      );
    }
  }

  /**
   * Get data with automatic proof verification (secure by default)
   */
  async get(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    return this.data.getData(datasetId, key);
  }

  /**
   * Get data without proof verification (use with caution)
   */
  async getUnverified(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    return this.data.getDataUnverified(datasetId, key);
  }

  /**
   * Update data via a consensus transaction (same as store — idempotent upsert).
   */
  async update(
    datasetId: string,
    key: string,
    value: any,
  ): Promise<void> {
    return this.store(datasetId, key, value);
  }

  /**
   * Delete data by key.
   */
  async delete(datasetId: string, key: string): Promise<void> {
    return this.data.deleteData(datasetId, key);
  }

  /**
   * Get proof
   */
  async getProof(
    datasetId: string,
    key: string,
  ): Promise<string> {
    return this.data.getProof(datasetId, key);
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
      this.config.apiKey ? { headers: { 'X-API-Key': this.config.apiKey } } : undefined,
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
    const response = await fetch(
      `${this.config.apiUrl}/state/root-hash`,
      this.config.apiKey ? { headers: { 'X-API-Key': this.config.apiKey } } : undefined,
    );
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
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    return this.data.query(datasetId, query);
  }

  /**
   * Query indexed data without proof verification (use with caution)
   */
  async queryUnverified(
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    return this.data.queryUnverified(datasetId, query);
  }

  /**
   * Execute a SQL query against a subgrove.
   *
   * Routes to an indexer (history + analytics) or the validator (chain-tip,
   * consensus-verified) based on `options.source`. See `QuerySource` in
   * `./types` for details.
   */
  async sqlQuery(
    subgroveId: string,
    sql: string,
    options?: SqlQueryOptions,
  ): Promise<SqlQueryResult> {
    return this.data.sqlQuery(subgroveId, sql, options);
  }

  /**
   * Execute a GraphQL query against a subgrove.
   *
   * Routes to an indexer (history + analytics) or the validator (chain-tip,
   * consensus-verified) based on `options.source`. See `QuerySource` in
   * `./types` for details.
   */
  async graphqlQuery(
    subgroveId: string,
    query: string,
    options?: GraphQLQueryOptions,
  ): Promise<GraphQLQueryResult> {
    return this.data.graphqlQuery(subgroveId, query, options);
  }

  private requireIdentity(): void {
    if (!this.auth.getDid() || !this.auth.getPrivateKey() || !this.auth.getPublicKeyId()) {
      throw new Error(
        'Identity not set. Call client.auth.setIdentity(did, privateKey, publicKeyId) before write operations.',
      );
    }
  }

  /** Builds a consensus Signer from the configured identity. Call requireIdentity() first. */
  private signer(): Signer {
    return {
      privateKey: this.auth.getPrivateKey()!,
      publicKeyId: this.auth.getPublicKeyId()!,
    };
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
   * import { WillowClient, UNISWAP_V2_PAIR_FIELDS } from '@willow-network/sdk';
   *
   * const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
   * client.registerComputedFields('pairs', UNISWAP_V2_PAIR_FIELDS);
   *
   * // Queries now return computed prices alongside proven reserves
   * const result = await client.query('pairs', { filters: { id: '0x...' } });
   * console.log(result.documents[0].token0Price); // Computed from proven reserves
   * ```
   */
  registerComputedFields(
    datasetId: string,
    fields: ComputedFieldSet,
  ): void {
    this.data.registerComputedFields(datasetId, fields);
  }

  /**
   * Create a helper for a specific dataset
   */
  collection(datasetId: string) {
    return {
      store: (key: string, value: any) =>
        this.store(datasetId, key, value),
      get: (key: string) => this.get(datasetId, key),
      getUnverified: (key: string) =>
        this.data.getDataUnverified(datasetId, key),
      update: (key: string, value: any) =>
        this.update(datasetId, key, value),
      delete: (key: string) => this.delete(datasetId, key),
      getProof: (key: string) => this.getProof(datasetId, key),
      batchStore: (records: Array<{ key: string; value: any }>) =>
        this.data.batchStore(datasetId, records),
      getMultiple: (keys: string[]) =>
        this.data.getMultiple(datasetId, keys),
      getMultipleUnverified: (keys: string[]) =>
        this.data.getMultipleUnverified(datasetId, keys),
      query: (query: any) => this.data.query(datasetId, query),
      queryUnverified: (query: any) =>
        this.data.queryUnverified(datasetId, query),
    };
  }
}
