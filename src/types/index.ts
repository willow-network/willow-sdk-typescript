// Core types for Willow SDK

import { ProofVerificationOptions } from '../proof';

export interface WillowConfig {
  apiUrl: string;
  /**
   * Optional explicit indexer node URL. When set, `source: 'indexer'` and
   * `source: 'auto'` queries route directly to this URL and skip the
   * `GET /indexers` discovery round-trip. When unset (the common case), the
   * SDK discovers indexers automatically via the validator's registry.
   *
   * Use cases for the override:
   * - Local dev: avoid a tiny extra RTT on every query.
   * - Pinning: always hit the operator's own indexer (enterprise, paid).
   * - Debugging: isolate which indexer is serving a request.
   */
  indexerUrl?: string;
  /** Optional CometBFT RPC URL for consensus transactions. Derived from apiUrl if omitted. */
  consensusRpcUrl?: string;
  did?: string;
  privateKey?: string;
  /**
   * Managed-tier API key (`wk_…`). When set, the SDK sends
   * `X-API-Key: <apiKey>` on every authenticated request alongside any
   * DID-signature headers. Mint a key at https://dashboard.willow.tech/account.
   *
   * Required for queries and writes against `api.willow.tech` /
   * `indexer.willow.tech`. Public metadata reads work without a key but
   * are subject to stricter per-IP rate limits.
   */
  apiKey?: string;
  proofVerificationOptions?: ProofVerificationOptions;
}

/**
 * Which backend should serve a query.
 *
 * - `'validator'`: consensus-verified chain-tip. Every row comes with
 *   Merkle proofs. Fails fast for `VerifyOnly` subgroves (validator
 *   never stored the data).
 * - `'indexer'`: full history + analytics. Trust is sampling/dispute based.
 *   Fails if no indexer serves the subgrove or all reachable ones fail.
 * - `'auto'` (default): indexer if any serves this subgrove, otherwise
 *   validator. On indexer failure, falls back to validator and flags
 *   the result with `fallback: true`.
 */
export type QuerySource = "validator" | "indexer" | "auto";

export interface GraphQLQueryOptions {
  source?: QuerySource;
  variables?: Record<string, any>;
  operationName?: string;
}

export interface SqlQueryOptions {
  source?: QuerySource;
  includeProof?: boolean;
}

/** Result envelope surfacing which backend actually served a query. */
export interface RoutedQueryResult<T> {
  /** Raw response body from the backend. */
  result: T;
  /** Backend that served this query. */
  source: "validator" | "indexer";
  /** DID of the indexer that served (only present when `source === 'indexer'`). */
  indexerDid?: string;
  /** True when `'auto'` routing fell back from indexer → validator. */
  fallback: boolean;
}

export type GraphQLQueryResult = RoutedQueryResult<any>;
export type SqlQueryResult = RoutedQueryResult<SqlQueryResponse>;

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

// DID Types
export interface PublicKey {
  id: string;
  type: string;
  publicKeyHex?: string;
  publicKeyBase64?: string;
}

export interface DidDocument {
  id: string;
  publicKeys: PublicKey[];
  created: number;
  updated: number;
}

// Dataset Types
export interface FieldType {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'bytes';
  indexed?: boolean;
  required?: boolean;
}

export interface IndexDefinition {
  name: string;
  fields: string[];
  unique: boolean;
  type?: 'unique' | 'hash' | 'range' | 'fulltext' | 'compound';
}

export interface SchemaDefinition {
  version: number;
  fields: Record<string, FieldType>;
  indexes?: IndexDefinition[];
  required_fields?: string[];
}

export interface RegisterDatasetRequest {
  dataset_id: string;
  name: string;
  dataset_path: string[];
  schema: SchemaDefinition;
  owner_did: string;
  writers: string[];
  readers: string[];
}

export interface DatasetRegistration {
  dataset_id: string;
  name: string;
  schema: SchemaDefinition;
  owner_did: string;
  writers: string[];
  readers: string[];
  created_at: number;
  updated_at: number;
}

// Data Operation Types
export interface DataRecord {
  [key: string]: any;
}

export interface ProofResponse {
  proof: string; // Hex encoded proof
  height?: number; // Block height the proof was generated at
}

// Query Types
export interface QueryFilter {
  [field: string]: any | {
    $eq?: any;
    $ne?: any;
    $gt?: any;
    $gte?: any;
    $lt?: any;
    $lte?: any;
    $in?: any[];
    $contains?: string;
  };
}

export interface QuerySort {
  field: string;
  order: 'asc' | 'desc';
}

export interface QuerySearch {
  field: string;
  query: string;
}

export interface QueryRequest {
  filters?: QueryFilter;
  search?: QuerySearch;
  sort?: QuerySort;
  limit?: number;
  offset?: number;
  include_proof?: boolean;
}

export interface QueryResponse {
  documents: DataRecord[];
  total?: number;
  offset?: number;
  limit?: number;
  proof?: string;
  verifiedRootHash?: string; // Added when proof is successfully verified
}

// Token Types
export interface TokenInfo {
  name: string;
  symbol: string;
  decimals: number;
  genesis_supply: string;
  minted_supply: string;
  max_supply: string;
  circulating_supply: string;
}

export interface Balance {
  did: string;
  available: string;
  staked: string;
  locked: string;
}

export interface TransferRequest {
  from_did: string;
  to_did: string;
  amount: string;
  memo?: string;
}

// Historical Query Types (for checkpoint data)
export interface HistoricalQueryRequest {
  /** GroveDB path to query */
  path: number[][];
  /** Key to query (for single-key queries) */
  key?: number[];
  /** Query type: "get", "get_range", "get_path" */
  query_type?: string;
  /** Whether to include proof */
  include_proof?: boolean;
}

export interface HistoricalQueryResponse {
  /** Whether the query was successful */
  success: boolean;
  /** Provider DID that served this query */
  provider_did?: string;
  /** Provider endpoint */
  provider_endpoint?: string;
  /** Checkpoint state root for proof verification */
  state_root: string;
  /** Block range covered by the checkpoint */
  block_range: [number, number];
  /** Query results from the indexer */
  data: any;
  /** Merkle proof (hex-encoded) when include_proof was true */
  proof?: string;
  /** Whether this data can be re-indexed (only set on error) */
  can_reindex?: boolean;
  /** Error message if any */
  error?: string;
}

export interface CheckpointInfo {
  /** Checkpoint ID (hex) */
  checkpoint_id: string;
  /** Subgrove ID */
  subgrove_id: string;
  /** State root hash (hex) */
  state_root: string;
  /** Block range [start, end] */
  block_range: [number, number];
  /** DID of the indexer who submitted this checkpoint */
  indexer_did: string;
  /** Unix timestamp when the checkpoint was submitted */
  submitted_at: number;
  /** Whether the checkpoint is trusted */
  is_trusted: boolean;
}

// SQL Query Types
export interface SqlQueryRequest {
  query: string;
  include_proof?: boolean;
}

export interface SqlQueryResponse {
  columns: string[];
  rows: any[][];
  total?: number;
  warnings?: string[];
  proof?: QueryProof;
}

export interface QueryProof {
  merkle_proofs: MerkleProof[];
  state_root: number[];
  block_height: number;
  ethereum_anchor?: EthereumAnchor;
}

export interface MerkleProof {
  key: string;
  value_hash: number[];
  /** Bincode-serialized GroveDB proof bytes; pass to `verifyGroveDBProof`. */
  merkle_proof?: number[];
  /** Legacy field, always empty; older responses lacked `merkle_proof`. */
  siblings: number[][];
  path: string;
}

export interface EthereumAnchor {
  block_number: number;
  tx_hash: number[];
  contract: string;
}

// Error types
export class WillowError extends Error {
  constructor(
    message: string,
    public code?: string,
    public statusCode?: number
  ) {
    super(message);
    this.name = 'WillowError';
  }
}