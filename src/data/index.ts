import {
  ApiResponse,
  WillowError,
  DataRecord,
  ProofResponse,
  RegisterSubgroveRequest,
  WillowLightClientOptions,
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
  VerifiedData,
} from "../types";
import { WillowAuth } from "../auth";
import {
  verifyQueryProof,
  subgroveDataPath,
  ProofVerificationOptions,
} from "../proof";
import { verifySubgroveItem } from "../proof/binding";
import {
  checkQueryResult,
  provenQueryData,
  querySelection,
} from "../proof/query-selection";
import { enforceExpectedRoot } from "../proof/shared";
import { verifyKeyAbsence, hashToHex, hexToBytes } from "../grovedb";
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
import { HttpClient, HttpError, RequestSigner } from "../internal/http";
import { WillowLogger, silentLogger } from "../internal/logger";
import { ConsensusClient } from "../consensus/client";
import { serializeSchema } from "../consensus/schema";
import { writeNotAccepted } from "../internal/tx";
import type {
  BroadcastResult,
  RegisterSubgroveOptions,
  SubgroveMode,
} from "../consensus/types";

/**
 * Register a subgrove from a {@link RegisterSubgroveRequest} by a
 * RegisterSubgrove transaction signed by `auth`'s identity, which owns it.
 *
 * The request's `name`, `writers`, and `readers` become a `DataStorage` mode
 * (`readers` maps to the on-chain `free_readers`) unless `options.mode` is
 * given. A DataStorage or FileStorage schema is sent in the chain's shape
 * ({@link serializeSchema}), and one the chain can't take is refused before
 * anything is signed. Throws `IDENTITY_MISMATCH` when the request's
 * `owner_did` is not the identity. A registration refused at CheckTx, or
 * whose outcome is pending, throws a `TransactionSubmitError`
 * (`TX_SUBMIT_FAILED`) carrying the DID, nonce, signed body, and `result`.
 */
export async function registerSubgroveRequest(
  consensus: Pick<ConsensusClient, "registerSubgrove">,
  auth: WillowAuth,
  request: RegisterSubgroveRequest,
  options?: RegisterSubgroveOptions,
): Promise<BroadcastResult> {
  const signer = auth.transactionSigner();
  if (request.owner_did && request.owner_did !== auth.getDid()) {
    throw new WillowError(
      `The request's owner (${request.owner_did}) is not the identity (${auth.getDid()}), ` +
        "which owns the subgrove it registers; set the owner's identity first.",
      "IDENTITY_MISMATCH",
    );
  }
  const mode: SubgroveMode =
    options?.mode ?? {
      DataStorage: {
        name: request.name,
        writers: request.writers,
        free_readers: request.readers,
      },
    };
  // A data or file subgrove's schema goes in the chain's shape; the chain
  // reads no other mode's schema, which goes as it is.
  const storage =
    typeof mode === "object" &&
    mode !== null &&
    ("DataStorage" in mode || "FileStorage" in mode);
  const schema = storage
    ? serializeSchema(request.schema)
    : JSON.stringify(request.schema ?? {});
  const result = await consensus.registerSubgrove(
    request.dataset_id,
    schema,
    auth.getDid()!,
    signer,
    { name: request.name, ...options, mode },
  );
  if (!result.success) throw writeNotAccepted("registerSubgrove", result);
  return result;
}

/**
 * The API takes no data writes over REST (its data-write routes answer 501):
 * each is a transaction sent through `POST /tx/submit`.
 */
function noDataWriteRoute(what: string, instead: string): WillowError {
  return new WillowError(
    `The API does not take data writes over REST (its ${what} route answers 501); data is ` +
      `written by transactions sent through POST /tx/submit. ${instead}`,
    "UNSUPPORTED_OPERATION",
  );
}

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

/**
 * How many blocks a verified read's proof may be behind the chain's latest
 * height, unless `lightClient.maxProofLagBlocks` says otherwise.
 */
export const DEFAULT_MAX_PROOF_LAG_BLOCKS = 20;

/** A proof verification failure, as the verified reads report it. */
function verificationFailed(error: unknown): WillowError {
  if (error instanceof WillowError) return error;
  return new WillowError(
    `Proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
    "PROOF_VERIFICATION_FAILED",
  );
}

/**
 * An object to return values by key in, with no prototype: no key a caller
 * reads in it is inherited, and a key named `__proto__` is set as a key.
 */
function keyedResults(): Record<string, DataRecord> {
  return Object.create(null) as Record<string, DataRecord>;
}

/** Set `key` to `value` as an own property, whatever the key's name. */
function setResult(results: Record<string, DataRecord>, key: string, value: DataRecord): void {
  Object.defineProperty(results, key, { value, enumerable: true, writable: true, configurable: true });
}

export interface WillowDataOptions {
  /** Logger for verification diagnostics. Defaults to `silentLogger`. */
  logger?: WillowLogger;
  /** Overrides for the auto-created light client (chain ID, endpoints, …). */
  lightClient?: WillowLightClientOptions;
  /**
   * The consensus client that sends this client's transactions
   * (`registerSubgrove`). `WillowClient` passes its own; without one, one is
   * made for `apiUrl`.
   */
  consensus?: ConsensusClient;
}

export class WillowData {
  private api: HttpClient;
  private auth: WillowAuth;
  private apiUrl: string;
  private cometbftRpcUrl?: string;
  private lightClient?: LightClient;
  private lightClientInitPromise?: Promise<LightClient>;
  private computedFieldRegistry: ComputedFieldRegistry;
  private indexers: WillowIndexers;
  private proofOptions?: ProofVerificationOptions;
  private logger: WillowLogger;
  private lightClientOptions?: WillowLightClientOptions;
  private consensus?: ConsensusClient;
  /**
   * Signs a read of subgrove data (`/data`, `/proof`, `/query`, `/sql`,
   * `/graphql`): X-API-Key, plus the nonce form with an identity set. Only
   * that form carries the DID's read rights.
   */
  private signRead: RequestSigner;

  constructor(
    apiUrl: string,
    auth: WillowAuth,
    indexers: WillowIndexers,
    cometbftRpcUrl?: string,
    proofVerificationOptions?: ProofVerificationOptions,
    options?: WillowDataOptions,
  ) {
    this.apiUrl = apiUrl;
    this.cometbftRpcUrl = cometbftRpcUrl;
    this.indexers = indexers;
    this.proofOptions = proofVerificationOptions;
    this.api = new HttpClient({ baseURL: apiUrl });
    this.auth = auth;
    this.signRead = (method, target, body) => auth.getSignedHeaders(method, target, body);
    this.computedFieldRegistry = new ComputedFieldRegistry();
    this.logger = options?.logger ?? silentLogger;
    this.lightClientOptions = options?.lightClient;
    this.consensus = options?.consensus;
  }

  private consensusClient(): ConsensusClient {
    this.consensus ??= new ConsensusClient({
      apiUrl: this.apiUrl,
      apiKey: this.auth.getApiKey(),
      consensusRpcUrl: this.cometbftRpcUrl,
      logger: this.logger,
    });
    return this.consensus;
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
   * Get or create a light client for root-hash lookups.
   *
   * Auto-initializes a light client using trust-on-first-use: the first
   * block received from validators is trusted. The fallback settings
   * (chainId `"willow-chain"`, the single configured RPC endpoint,
   * `minValidatorsForConsensus: 1`) are DEVELOPMENT defaults sized for a
   * local single-node devnet — override them via the `lightClient` section
   * of the client config for anything else. Note the light client's
   * root-hash path currently trusts the configured RPC endpoint (see
   * `LightClient` docs).
   */
  private async getOrCreateLightClient(): Promise<LightClient> {
    if (this.lightClient) {
      return this.lightClient;
    }

    // Prevent concurrent initialization
    if (this.lightClientInitPromise) {
      return this.lightClientInitPromise;
    }

    if (!this.cometbftRpcUrl) {
      throw new WillowError(
        "CometBFT RPC URL is not configured, so the light client cannot verify headers. Set `consensusRpcUrl` in the WillowClient config to your validator's CometBFT RPC endpoint.",
        "CONSENSUS_RPC_URL_REQUIRED",
      );
    }
    const cometbftRpcUrl = this.cometbftRpcUrl;

    this.lightClientInitPromise = (async () => {
      const overrides = this.lightClientOptions;
      const config: LightClientConfig = {
        chainId: overrides?.chainId ?? "willow-chain",
        validatorEndpoints: overrides?.validatorEndpoints ?? [cometbftRpcUrl],
        trustThreshold: overrides?.trustThreshold ?? { numerator: 2, denominator: 3 },
        trustingPeriodSecs: overrides?.trustingPeriodSecs ?? 86400, // 24 hours
        maxClockDriftSecs: overrides?.maxClockDriftSecs ?? 30,
        autoSync: false,
        minValidatorsForConsensus: overrides?.minValidatorsForConsensus ?? 1, // For single-node development
        requestTimeoutSecs: overrides?.requestTimeoutSecs ?? 30,
        syncIntervalSecs: 60,
        logger: this.logger,
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
   * Register a subgrove by a RegisterSubgrove transaction signed by the
   * auth identity, which owns it (see {@link registerSubgroveRequest}).
   * Returns the consensus `BroadcastResult`; throws when it is refused.
   */
  async registerSubgrove(
    request: RegisterSubgroveRequest,
    options?: RegisterSubgroveOptions,
  ): Promise<BroadcastResult> {
    return registerSubgroveRequest(this.consensusClient(), this.auth, request, options);
  }

  /** @deprecated Use {@link registerSubgrove} — "subgrove" is the on-chain term. */
  async registerDataset(
    request: RegisterSubgroveRequest,
    options?: RegisterSubgroveOptions,
  ): Promise<BroadcastResult> {
    return this.registerSubgrove(request, options);
  }

  /**
   * The API's `POST /data/:subgrove` answers 501: data is written by a StoreData
   * transaction per key. Use `WillowClient.store(subgroveId, key, value)` (or
   * `ConsensusClient.storeData`) for each key.
   *
   * @deprecated Always throws `UNSUPPORTED_OPERATION`.
   */
  async storeData(
    _datasetId: string,
    _data: Record<string, any>,
  ): Promise<void> {
    throw noDataWriteRoute(
      "POST /data/:subgrove",
      "Store each key with WillowClient.store(subgroveId, key, value), one StoreData " +
        "transaction per key, and send a write that depends on another only after the " +
        "first has landed.",
    );
  }

  /**
   * Get data by key with automatic proof verification (secure by default):
   * the value must be the one the proof proves at the key, and the proof's
   * root the light client's root for the proof's block height, which must be
   * at most `lightClient.maxProofLagBlocks` behind the chain's latest and at
   * most one block ahead of it. An answer
   * that carries no value is refused (`PROOF_VERIFICATION_FAILED`). See
   * {@link getVerifiedData} for the root and height.
   */
  async getData(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    return (await this.getVerifiedData(datasetId, key)).data;
  }

  /**
   * {@link getData}, with the root and block height the value was verified
   * against.
   */
  async getVerifiedData(
    datasetId: string,
    key: string,
  ): Promise<VerifiedData> {
    // First get the data
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${datasetId}/${key}`,
      { sign: this.signRead },
    );

    if (!response.success) {
      throw new WillowError(
        response.error || "Data not found",
        "DATA_NOT_FOUND",
        404,
      );
    }

    const data = response.data;

    try {
      // A success that carries no value has nothing to bind to the proof: it
      // is refused, not returned as `undefined` or read as an absent key.
      if (data === undefined) {
        throw new Error(`The API's answer for key "${key}" carries no value`);
      }
      const proofData = await this.fetchProof(datasetId, key);
      // Verify the proof, binding the returned value to the Item it proves at
      // the key, and compute the root hash.
      const computedRootHash = verifySubgroveItem(
        proofData.proof,
        datasetId,
        key,
        data,
        this.proofOptions?.expectedRootHash,
      );
      const verified = await this.verifyRootAtHeight(computedRootHash, proofData.height);
      return { data, rootHash: verified.rootHash, height: verified.height };
    } catch (error) {
      // Any error during proof fetch or verification is a verification
      // failure. If you explicitly want data without verification, use
      // `getDataUnverified`.
      throw verificationFailed(error);
    }
  }

  /**
   * `GET /proof/:subgrove/:key`. Fails closed: a response without a proof
   * can't verify anything, so it throws `MISSING_PROOF` (use
   * `getDataUnverified` to read without verification).
   */
  private async fetchProof(datasetId: string, key: string): Promise<ProofResponse> {
    const proofResponse = await this.api.get<ApiResponse<ProofResponse>>(
      `/proof/${datasetId}/${key}`,
      { sign: this.signRead },
    );
    if (!proofResponse.success || !proofResponse.data?.proof) {
      throw new WillowError(
        `No proof returned for key "${key}" — cannot verify the data. ` +
          "Use `getDataUnverified` to fetch without verification.",
        "MISSING_PROOF",
      );
    }
    return proofResponse.data;
  }

  /**
   * Check a proof's root against the light client's root for the proof's
   * block height, and return both. The API chooses the height it proves at,
   * so a height more than `lightClient.maxProofLagBlocks` behind the chain's
   * latest (as the light client's endpoints report it), or more than one
   * block ahead of it, is refused (`PROOF_HEIGHT_OUT_OF_RANGE`), as is a
   * proof that names no height. A root is read from the header after the
   * proof's height, which the light client waits for: a height further ahead
   * would hold each read until that wait times out on every endpoint.
   */
  private async verifyRootAtHeight(
    computedRootHash: string,
    height: unknown,
  ): Promise<{ rootHash: string; height: number }> {
    if (typeof height !== "number" || !Number.isSafeInteger(height) || height <= 0) {
      throw new WillowError(
        `The proof names no block height (${JSON.stringify(height)}), so its root can't be checked ` +
          "against the chain's",
        "PROOF_VERIFICATION_FAILED",
      );
    }
    const lightClient = await this.getOrCreateLightClient();
    const maxLag = this.maxProofLagBlocks();
    const latest = await lightClient.getLatestChainHeight();
    if (height - latest > 1) {
      throw new WillowError(
        `The proof is of the state at height ${height}, ${height - latest} blocks ahead of the ` +
          `chain's latest (${latest}); at most 1 is accepted`,
        "PROOF_HEIGHT_OUT_OF_RANGE",
      );
    }
    if (latest - height > maxLag) {
      throw new WillowError(
        `The proof is of the state at height ${height}, ${latest - height} blocks behind the ` +
          `chain's latest (${latest}); at most ${maxLag} is accepted (lightClient.maxProofLagBlocks)`,
        "PROOF_HEIGHT_OUT_OF_RANGE",
      );
    }
    const verifiedRootHash = await lightClient.getVerifiedRootHashAtHeight(height);
    if (computedRootHash.toLowerCase() !== verifiedRootHash.toLowerCase()) {
      this.logger.error(
        `Root hash mismatch: computed=${computedRootHash}, verified=${verifiedRootHash}, height=${height}`,
      );
      throw new WillowError(
        "Proof verification failed: root hash mismatch",
        "PROOF_VERIFICATION_FAILED",
      );
    }
    return { rootHash: verifiedRootHash, height };
  }

  private maxProofLagBlocks(): number {
    const configured = this.lightClientOptions?.maxProofLagBlocks;
    if (configured === undefined) return DEFAULT_MAX_PROOF_LAG_BLOCKS;
    if (!Number.isSafeInteger(configured) || configured < 0) {
      throw new WillowError(
        `lightClient.maxProofLagBlocks must be a non-negative integer, not ${configured}`,
        "INVALID_CONFIG",
      );
    }
    return configured;
  }

  /**
   * Verify that `key` is absent from the subgrove's data: the API's proof of
   * the key must prove it absent, at a root the light client verifies.
   */
  private async verifyAbsent(datasetId: string, key: string): Promise<void> {
    try {
      const proofData = await this.fetchProof(datasetId, key);
      const encoder = new TextEncoder();
      const rootHash = hashToHex(
        verifyKeyAbsence(
          hexToBytes(proofData.proof),
          subgroveDataPath(datasetId).map((segment) => encoder.encode(segment)),
          encoder.encode(key),
        ),
      );
      const expected = this.proofOptions?.expectedRootHash;
      if (expected && expected.toLowerCase().replace(/^0x/, "") !== rootHash) {
        throw new Error(`Root hash mismatch: computed=${rootHash}, expected=${expected}`);
      }
      await this.verifyRootAtHeight(rootHash, proofData.height);
    } catch (error) {
      throw verificationFailed(error);
    }
  }

  /**
   * Get data by key without proof verification (use with caution)
   */
  async getDataUnverified(
    datasetId: string,
    key: string,
  ): Promise<DataRecord> {
    const response = await this.api.get<ApiResponse<DataRecord>>(
      `/data/${datasetId}/${key}`,
      { sign: this.signRead },
    );

    if (!response.success) {
      throw new WillowError(
        response.error || "Data not found",
        "DATA_NOT_FOUND",
        404,
      );
    }

    return response.data!;
  }

  /**
   * The API's `PUT /data/:subgrove/:key` answers 501: an existing key is changed
   * by an UpdateData transaction, which this SDK does not build.
   *
   * @deprecated Always throws `UNSUPPORTED_OPERATION`.
   */
  async updateData(
    _datasetId: string,
    _key: string,
    _data: any,
  ): Promise<void> {
    throw noDataWriteRoute(
      "PUT /data/:subgrove/:key",
      "An existing key is changed by an UpdateData transaction, which this SDK does " +
        "not build.",
    );
  }

  /**
   * The API's `DELETE /data/:subgrove/:key` answers 501: a key is deleted by a
   * DeleteData transaction, which this SDK does not build.
   *
   * @deprecated Always throws `UNSUPPORTED_OPERATION`.
   */
  async deleteData(
    _datasetId: string,
    _key: string,
  ): Promise<void> {
    throw noDataWriteRoute(
      "DELETE /data/:subgrove/:key",
      "A key is deleted by a DeleteData transaction, which this SDK does not build.",
    );
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
      { sign: this.signRead },
    );

    if (!response.success) {
      throw new WillowError(
        response.error || "Failed to get proof",
        "PROOF_FAILED",
      );
    }

    return response.data!.proof;
  }

  /**
   * The API serves no batch write: data is written by a StoreData
   * transaction per key. Use `WillowClient.store(subgroveId, key, value)` for
   * each record.
   *
   * @deprecated Always throws `UNSUPPORTED_OPERATION`.
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
   * Get several keys, each verified as {@link getData} verifies it. A key the
   * API reports absent is left out of the result only when its proof proves
   * it absent at a root the light client verifies; otherwise this throws.
   *
   * The result has no prototype: each key is an own property, so a key named
   * `__proto__` is returned as a key, and a key left out reads as
   * `undefined` (`"toString" in result` is false).
   */
  async getMultiple(
    datasetId: string,
    keys: string[],
  ): Promise<Record<string, DataRecord>> {
    const results = keyedResults();

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          setResult(results, key, await this.getData(datasetId, key));
        } catch (error) {
          if (error instanceof WillowError && error.code === "DATA_NOT_FOUND") {
            await this.verifyAbsent(datasetId, key);
            return;
          }
          throw error;
        }
      }),
    );

    return results;
  }

  /**
   * Query helper - get multiple records without verification. The result
   * has no prototype, as {@link getMultiple}'s.
   */
  async getMultipleUnverified(
    datasetId: string,
    keys: string[],
  ): Promise<Record<string, DataRecord>> {
    const results = keyedResults();

    // In production, we'd want to batch these or have a bulk endpoint
    await Promise.all(
      keys.map(async (key) => {
        try {
          setResult(results, key, await this.getDataUnverified(datasetId, key));
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
   * Query indexed data with automatic proof verification (secure by default).
   *
   * The result is verified as the query's whole result: the API proves the
   * subgrove's entire data tree, and the SDK runs the API's selection over it
   * (the one exact-match filter, the sort, `offset`, and `limit`, default
   * 100) and requires the returned `documents` and `total` to be exactly that
   * (see `verifyQuerySelection`). The selection is the one in the body sent,
   * read when it is sent, so changing `query` afterwards does not change what
   * the result is checked against. The proof must reveal the whole data
   * tree, and its root must be the light client's root for the proof's block
   * height, which must be at most `lightClient.maxProofLagBlocks` behind
   * the chain's latest and at most one block ahead of it, before the
   * selection is run; the result carries
   * `verifiedRootHash` and `verifiedHeight`.
   *
   * A query whose selection can't be verified throws `QUERY_NOT_VERIFIABLE`
   * before anything is sent: a filter on more than one field (the API
   * applies only one), a filter operator such as `$gt` (the API applies
   * none), or `search`. Use `queryUnverified` for those. Data at the verified
   * root whose selection the SDK can't reproduce (a sort over values that are
   * not all numbers or all strings, say) throws `QUERY_RESULT_NOT_VERIFIABLE`
   * (a `QueryResultNotVerifiableError` carrying the root). The API's sort
   * calls a missing field, `null`, a boolean, an array, or an object equal to
   * anything, so a sort on a field some selected document lacks (or holds as
   * one of those) throws on every page, unless the selected documents hold
   * at most one number and one string there: filter on a field that selects
   * only documents holding the sort field as a number (or all as a string),
   * or use `queryUnverified`.
   */
  async query(
    datasetId: string,
    query: QueryRequest,
  ): Promise<QueryResponse> {
    // The body as it is sent (with the proof always asked for), read once:
    // the selection is checked against it, not the caller's object later.
    const sent = JSON.parse(JSON.stringify({ ...query, include_proof: true })) as QueryRequest;
    // Refuse a query whose result can't be verified before sending it.
    const selection = querySelection(sent);

    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${datasetId}`,
      sent,
      { sign: this.signRead },
    );

    if (!response.success) {
      throw new WillowError(
        response.error || "Query failed",
        "QUERY_FAILED",
      );
    }

    const result = response.data!;
    if (!result.proof) {
      // Fail closed: include_proof was requested but the server returned no
      // proof, so the documents are unverified. Use `queryUnverified` to opt
      // out of verification explicitly.
      throw new WillowError(
        `Query for "${datasetId}" returned no proof — cannot verify the results. ` +
          "Use `queryUnverified` to query without verification.",
        "MISSING_PROOF",
      );
    }

    let verified: QueryResponse;
    try {
      // The whole data tree and its root first; the selection runs only over
      // data at a verified root.
      const data = provenQueryData(datasetId, result);
      enforceExpectedRoot(data.rootHash, this.proofOptions?.expectedRootHash);
      const { rootHash, height } = await this.verifyRootAtHeight(
        data.rootHash,
        (result as { height?: unknown }).height,
      );
      checkQueryResult(data, selection, result);
      // Only what was verified: the API's other fields are left out.
      verified = {
        documents: result.documents,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
        proof: result.proof,
        verifiedRootHash: rootHash,
        verifiedHeight: height,
      };
    } catch (error) {
      throw verificationFailed(error);
    }

    // Apply computed fields if registered for this dataset
    const computedFields = this.computedFieldRegistry.get(datasetId);
    if (computedFields) {
      return applyComputedFieldsToResponse(verified, computedFields);
    }

    return verified;
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

    const response = await this.api.post<ApiResponse<QueryResponse>>(
      `/query/${datasetId}`,
      queryWithoutProof,
      { sign: this.signRead },
    );

    if (!response.success) {
      throw new WillowError(
        response.error || "Query failed",
        "QUERY_FAILED",
      );
    }

    let result = response.data!;

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
   * The state root the API reports for a checkpoint. The SDK does not verify
   * it: it is the API's own record of what an indexer submitted, not a root
   * from consensus.
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

    if (!response.success) {
      throw new WillowError(
        response.error || "Checkpoint not found",
        "CHECKPOINT_NOT_FOUND",
        404,
      );
    }

    return response.data!;
  }

  /**
   * Query historical indexed data at a checkpoint, unverified.
   *
   * The API forwards the query to indexer nodes that keep the checkpoint's
   * data and returns what one of them answers. Nothing in the result is
   * verified: the checkpoint's state root and the data both come from the
   * API, and the response carries no proof the SDK can check. The method
   * only checks that the response's `state_root` is the one the API reports
   * for the checkpoint.
   *
   * @param subgroveId - The subgrove ID
   * @param checkpointId - The checkpoint ID (hex string)
   * @param query - The query parameters
   * @returns Historical query response with provider info
   *
   * @example
   * ```typescript
   * const response = await client.data.queryHistorical(
   *   'my-subgrove',
   *   '0abc...', // checkpoint ID
   *   {
   *     path: [[97, 112, 112], [100, 97, 116, 97]], // UTF-8 bytes for path segments
   *     key: [107, 101, 121], // UTF-8 bytes for key
   *   }
   * );
   *
   * if (response.success) {
   *   console.log('Provider:', response.provider_did);
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
    const checkpoint = await this.getCheckpointStateRoot(
      subgroveId,
      checkpointId,
    );

    // Make the historical query
    const result = await this.api.post<HistoricalQueryResponse>(
      `/historical/query/${subgroveId}/${checkpointId}`,
      query,
    );

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

    // The response's state root must be the one the API reports for the
    // checkpoint (both come from the API; this is a consistency check).
    if (result.state_root !== checkpoint.state_root) {
      throw new WillowError(
        "State root mismatch: query response does not match checkpoint",
        "STATE_ROOT_MISMATCH",
      );
    }

    return result;
  }

  /**
   * A historical query can't be verified, so this always throws
   * `UNSUPPORTED_OPERATION` without sending anything. The checkpoint's state
   * root comes from the same API that serves the result, not from consensus,
   * so a proof checked against it shows nothing; and the API returns no proof
   * for a historical query. Use {@link queryHistorical}, whose result is
   * unverified.
   *
   * @deprecated Always throws `UNSUPPORTED_OPERATION`.
   */
  async queryHistoricalVerified(
    _subgroveId: string,
    _checkpointId: string,
    _query: HistoricalQueryRequest,
  ): Promise<HistoricalQueryResponse> {
    throw new WillowError(
      "A historical query can't be verified: the checkpoint's state root comes from the API that " +
        "serves the result, not from consensus, and the API returns no proof for it. Use " +
        "queryHistorical, whose result is unverified.",
      "UNSUPPORTED_OPERATION",
    );
  }

  /**
   * Execute a SQL query against a subgrove. The result is unverified: the SDK
   * checks nothing on this path, and a `proof` the response carries
   * (`options.includeProof`) is returned as the API sent it, not checked.
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
   * Execute a GraphQL query against a subgrove. The result is unverified: the
   * SDK checks nothing on this path, and a proof the response carries
   * (`options.includeProof`) is returned as the API sent it, not checked.
   *
   * Routes to the validator (chain-tip) or an indexer (full history,
   * analytics-friendly) based on `options.source`. Defaults to `'auto'`.
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
    const body: Record<string, unknown> = {
      query,
      include_proof: options?.includeProof ?? false,
    };
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

    const callValidator = async (): Promise<T> => {
      try {
        return await this.api.post<T>(httpPath, body, { sign: this.signRead });
      } catch (err) {
        // When the validator refuses because the data isn't available
        // here (VerifyOnly retention, pruned, not indexed by consensus),
        // surface a typed error rather than a raw HTTP failure so
        // callers can react programmatically.
        const status = err instanceof HttpError ? err.status : undefined;
        const msg =
          err instanceof HttpError
            ? err.apiError ?? err.message
            : err instanceof Error
              ? err.message
              : "unknown error";
        if (status === 403 || status === 404 || /VerifyOnly|not indexed|not available/i.test(String(msg))) {
          throw new ValidatorHasNoDataError(subgroveId, String(msg));
        }
        throw err;
      }
    };

    // Indexers verify no request signature, and their CORS doesn't allow
    // X-Nonce, so they get the older form and X-API-Key, never the nonce form.
    // (A browser can send the nonce form to the API only when the API, or the
    // gateway in front of it, allows X-Nonce in its CORS headers.)
    const callIndexer = async (info: ApiIndexerInfo): Promise<T> => {
      const url = `${effectiveQueryEndpoint(info).replace(/\/$/, "")}${httpPath}`;
      return this.api.post<T>(url, body, {
        headers: this.auth.getAuthHeaders("POST", httpPath),
      });
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
        } catch (err) {
          if (err instanceof HttpError && err.status >= 500) this.indexers.evict(info.indexer_did);
          errors.push(`${info.indexer_did}: ${err instanceof Error ? err.message : String(err)}`);
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
      } catch (err) {
        if (err instanceof HttpError && err.status >= 500) this.indexers.evict(info.indexer_did);
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
 * Add a `verifyProof` method to a QueryResponse, which checks membership
 * only: each document is a value the proof proves (as `verifyQueryProof`),
 * not that the documents are the query's whole result. `client.query`
 * verifies the whole result (`verifyQuerySelection`). Pass the
 * subgrove the query was made against to bind the documents to that
 * subgrove's data ({@link subgroveDataPath}); without it they bind to a value
 * proven at any path in the proof.
 */
export function extendQueryResponse(
  response: QueryResponse,
  subgroveId?: string,
): QueryResponseExt {
  return {
    ...response,
    async verifyProof(): Promise<string> {
      if (!response.proof) {
        throw new WillowError(
          "Query response does not contain proof data",
          "NO_PROOF",
        );
      }
      return verifyQueryProof(
        response.proof,
        response.documents,
        subgroveId === undefined ? undefined : { path: subgroveDataPath(subgroveId) },
      );
    },
  };
}
