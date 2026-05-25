/**
 * Consensus Client Types
 * 
 * Transaction structures and types for direct blockchain interaction.
 */

/**
 * Base exception for consensus client operations
 */
export class ConsensusError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConsensusError';
  }
}

/**
 * Transaction status enumeration
 */
export enum TransactionStatus {
  PENDING = 'pending',
  SUCCESS = 'success',
  FAILED = 'failed',
  NOT_FOUND = 'not_found'
}

/**
 * Configuration for consensus client
 */
export interface ConsensusConfig {
  consensusRpcUrl: string;
  apiUrl?: string; // REST API URL for account queries (nonce, etc.)
  chainId?: string;
  requestTimeoutSecs?: number;
  maxRetries?: number;
  retryDelaySecs?: number;
}

/**
 * Create consensus config with defaults
 */
export function createConsensusConfig(config: Partial<ConsensusConfig> & Pick<ConsensusConfig, 'consensusRpcUrl'>): ConsensusConfig {
  if (!config.consensusRpcUrl) {
    throw new Error('consensusRpcUrl is required');
  }

  return {
    consensusRpcUrl: config.consensusRpcUrl,
    chainId: config.chainId || 'willow-chain',
    requestTimeoutSecs: config.requestTimeoutSecs || 30,
    maxRetries: config.maxRetries || 3,
    retryDelaySecs: config.retryDelaySecs || 1.0
  };
}

/**
 * Result of transaction broadcast
 */
export interface BroadcastResult {
  success: boolean;
  txHash?: string;
  height?: number;
  errorCode?: number;
  errorMessage?: string;
  rawLog?: string;
}

/**
 * Create result from CometBFT response
 */
export function createBroadcastResult(data: any): BroadcastResult {
  if (data.error) {
    return {
      success: false,
      errorMessage: data.error.message || 'Unknown error'
    };
  }

  const result = data.result || {};
  const code = result.code || 0;

  return {
    success: code === 0,
    txHash: result.hash,
    height: result.height,
    errorCode: code !== 0 ? code : undefined,
    errorMessage: code !== 0 ? result.log : undefined,
    rawLog: result.log
  };
}

/**
 * DID registration transaction
 */
export interface RegisterDidTx {
  didDocument: any;
  signature: string; // hex-encoded
  publicKeyId: string;
  nonce: number;
}

/** How long real-time indexed data is retained on consensus nodes. */
export type RetentionWindow =
  | { type: 'Blocks'; value: number }
  | { type: 'Seconds'; value: number }
  | { type: 'Indefinite' }
  | { type: 'VerifyOnly' };

/**
 * Subgrove mode — determines what kind of data the subgrove holds and how
 * it's ingested. Three variants match the Rust `SubgroveMode` enum. When
 * omitted, the wire defaults to DataStorage with empty values.
 */
export type SubgroveMode =
  | { DataStorage: { name: string; writers?: string[]; free_readers?: string[]; read_pricing?: any } }
  | {
      FileStorage: {
        name: string;
        max_file_size: number;
        replication_factor: number;
        writers?: string[];
        free_readers?: string[];
        read_pricing?: any;
        retention_period?: number;
      };
    }
  | { BlockchainIndexing: { manifest_content?: number[]; wasm_modules?: any[]; execution_mode?: any; indexer_config?: any; retention_window?: RetentionWindow } };

/**
 * Subgrove registration transaction
 */
export interface RegisterSubgroveTx {
  subgroveId: string;
  schema: string; // JSON schema as string
  ownerDid: string;
  mode?: SubgroveMode;
  retention_window?: RetentionWindow;
  /** Initial funding in smallest token unit. Transferred from ownerDid to the subgrove balance. */
  initialFunding?: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Token transfer transaction
 */
export interface TransferTx {
  fromDid: string;
  toDid: string;
  amount: number; // Amount in smallest unit
  memo?: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Data storage transaction
 */
export interface DataStoreTx {
  subgroveId: string;
  key: string;
  data: string; // JSON data as string
  ownerDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

export interface StoreFileManifestTx {
  subgroveId: string;
  fileKey: string;
  filename: string;
  contentType: string;
  totalSize: number;
  contentHash: string; // hex-encoded SHA-256
  chunkCount: number;
  chunkSize: number;
  chunkMerkleRoot: string; // hex-encoded
  ownerDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

export interface DeleteFileManifestTx {
  subgroveId: string;
  fileKey: string;
  ownerDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Deregister (delete) a subgrove transaction.
 * Remaining funding balance is refunded to the owner.
 */
export interface DeregisterSubgroveTx {
  subgroveId: string;
  ownerDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * MCP receipt-batch anchor with chain-enforced per-DID monotonicity.
 * Mirrors `willow_types::consensus::transactions::SubmitAnchorTx`.
 * `anchorHash` is the SHA-256 of the canonical anchor body (sorted-key
 * JSON of all fields except signature/publicKeyId/nonce/anchorHash);
 * `merkleRoot` is the Merkle root over `receiptHashes`. The chain
 * recomputes both and rejects on mismatch.
 */
export interface SubmitAnchorTx {
  did: string;
  anchorId: string;
  sequenceRange: [number, number];
  merkleRoot: string;
  count: number;
  receiptHashes: string[];
  timestamp: string;
  previousAnchorHash: string;
  anchorHash: string;
  isGenesis: boolean;
  signature?: string;
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Transaction type union
 */
export type Transaction = RegisterDidTx | RegisterSubgroveTx | TransferTx | DataStoreTx | StoreFileManifestTx | DeleteFileManifestTx | DeregisterSubgroveTx | SubmitAnchorTx;

/**
 * JSON.stringify with keys sorted alphabetically at every level.
 * Matches Rust's `serde_json::to_string(&serde_json::Value)` output,
 * which serializes Map keys in sorted order.
 */
function stableJsonStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(stableJsonStringify).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const pairs = keys.map(
      (k) => JSON.stringify(k) + ':' + stableJsonStringify((value as Record<string, unknown>)[k]),
    );
    return '{' + pairs.join(',') + '}';
  }
  return JSON.stringify(value);
}

function hexToByteArray(hex: string): number[] {
  const clean = hex.replace(/^0x/, '');
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    out.push(parseInt(clean.substr(i, 2), 16));
  }
  return out;
}

/**
 * Create transaction wrapper for consensus submission.
 *
 * Converts the internal camelCase TypeScript fields to the snake_case JSON
 * the Rust server expects (serde's default), and converts the hex signature
 * string to a byte array (`Vec<u8>` in Rust).
 */
export function createTransactionWrapper(txType: string, transaction: Transaction): any {
  const tx = transaction as unknown as Record<string, unknown>;
  const sig = typeof tx.signature === 'string' ? hexToByteArray(tx.signature as string) : tx.signature ?? [];
  const nonce = typeof tx.nonce === 'number' ? tx.nonce : 0;
  const publicKeyId = tx.publicKeyId ?? '';

  switch (txType) {
    case 'RegisterSubgrove': {
      const t = transaction as RegisterSubgroveTx;
      const wrapper: Record<string, unknown> = {
        subgrove_id: t.subgroveId,
        name: t.subgroveId,
        description: '',
        schema: t.schema,
        owner_did: t.ownerDid,
        admins: [],
        mode: t.mode ?? { DataStorage: { name: t.subgroveId, writers: [t.ownerDid], free_readers: [] } },
        retention_window: t.retention_window,
        signature: sig,
        public_key_id: publicKeyId,
        nonce,
      };
      if (t.initialFunding) {
        wrapper.initial_funding = parseInt(t.initialFunding, 10);
      }
      return { RegisterSubgrove: wrapper };
    }
    case 'DataStore': {
      const t = transaction as DataStoreTx;
      const data = Array.from(new TextEncoder().encode(t.data));
      return {
        StoreData: {
          subgrove_id: t.subgroveId,
          key: t.key,
          data,
          owner_did: t.ownerDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'Transfer': {
      const t = transaction as TransferTx;
      return {
        Transfer: {
          from_did: t.fromDid,
          to_did: t.toDid,
          amount: t.amount,
          memo: t.memo ?? '',
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'RegisterDid': {
      const t = transaction as RegisterDidTx;
      return {
        RegisterDid: {
          did_document: t.didDocument,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'DeregisterSubgrove': {
      const t = transaction as DeregisterSubgroveTx;
      return {
        DeregisterSubgrove: {
          subgrove_id: t.subgroveId,
          owner_did: t.ownerDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'SubmitAnchor': {
      const t = transaction as SubmitAnchorTx;
      return {
        SubmitAnchor: {
          did: t.did,
          anchor_id: t.anchorId,
          sequence_range: t.sequenceRange,
          merkle_root: t.merkleRoot,
          count: t.count,
          receipt_hashes: t.receiptHashes,
          timestamp: t.timestamp,
          previous_anchor_hash: t.previousAnchorHash,
          anchor_hash: t.anchorHash,
          is_genesis: t.isGenesis,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    default:
      return { [txType]: tx };
  }
}

import { keccak_256 } from '@noble/hashes/sha3';

/**
 * Keccak256 hash of a string, matching the Rust server's
 * `TransactionValidator::hash_string` (uses `sha3::Keccak256`).
 */
function schemaHash(schema: string): string {
  const hash: Uint8Array = keccak_256(new TextEncoder().encode(schema));
  return Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create the canonical message a transaction is signed over.
 *
 * The byte sequence here must match the format the chain's signature
 * validator re-derives — any drift causes the signature check to fail.
 */
export function createSignMessage(txType: string, transaction: Transaction): string {
  switch (txType) {
    case 'RegisterDid': {
      const tx = transaction as RegisterDidTx;
      return JSON.stringify(tx.didDocument);
    }

    case 'RegisterSubgrove': {
      const tx = transaction as RegisterSubgroveTx;
      const mode = tx.mode;
      const sh = schemaHash(tx.schema);

      // BlockchainIndexing signs a simpler payload than the other modes.
      if (mode && 'BlockchainIndexing' in mode) {
        return `RegisterSubgrove:${tx.subgroveId}:${tx.ownerDid}:${tx.nonce || 0}`;
      }

      if (mode && 'FileStorage' in mode) {
        const fs = (mode as { FileStorage: { name?: string; writers?: string[]; free_readers?: string[] } }).FileStorage;
        return `RegisterSubgrove\nID: ${tx.subgroveId}\nMode: FileStorage\nName: ${fs.name ?? tx.subgroveId}\nDescription: \nSchemaHash: ${sh}\nOwner: ${tx.ownerDid}\nAdmins: \nWriters: ${(fs.writers ?? []).join(',')}\nReaders: ${(fs.free_readers ?? []).join(',')}\nNonce: ${tx.nonce || 0}`;
      }
      // DataStorage mode (default)
      const ds = mode && 'DataStorage' in mode
        ? (mode as { DataStorage: { name?: string; writers?: string[]; free_readers?: string[] } }).DataStorage
        : { name: tx.subgroveId, writers: [tx.ownerDid], free_readers: [] as string[] };
      return `RegisterSubgrove\nID: ${tx.subgroveId}\nName: ${ds.name ?? tx.subgroveId}\nDescription: \nSchemaHash: ${sh}\nOwner: ${tx.ownerDid}\nAdmins: \nWriters: ${(ds.writers ?? []).join(',')}\nReaders: ${(ds.free_readers ?? []).join(',')}\nNonce: ${tx.nonce || 0}`;
    }

    case 'Transfer': {
      const tx = transaction as TransferTx;
      return `Transfer\nFrom: ${tx.fromDid}\nTo: ${tx.toDid}\nAmount: ${tx.amount}\nMemo: ${tx.memo || ''}\nNonce: ${tx.nonce || 0}`;
    }

    case 'DataStore': {
      const tx = transaction as DataStoreTx;
      return `${tx.subgroveId}:${tx.key}:${tx.data}`;
    }

    case 'StoreFileManifest': {
      const tx = transaction as StoreFileManifestTx;
      return `store_file:${tx.subgroveId}:${tx.fileKey}:${tx.contentHash}:${tx.totalSize}`;
    }

    case 'DeleteFileManifest': {
      const tx = transaction as DeleteFileManifestTx;
      return `delete_file:${tx.subgroveId}:${tx.fileKey}`;
    }

    case 'DeregisterSubgrove': {
      const tx = transaction as DeregisterSubgroveTx;
      return `DeregisterSubgrove:${tx.subgroveId}:${tx.ownerDid}:${tx.nonce || 0}`;
    }

    case 'SubmitAnchor': {
      // Domain-tagged so a SubmitAnchor signature can't be replayed
      // against another tx type.
      const tx = transaction as SubmitAnchorTx;
      return `SubmitAnchor\n${tx.anchorHash}\n${tx.nonce || 0}`;
    }

    default:
      throw new Error(`Unknown transaction type: ${txType}`);
  }
}

/**
 * Utility: Convert string to base64
 */
export function stringToBase64(str: string): string {
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return Buffer.from(str, 'utf-8').toString('base64');
  } else {
    // Browser environment
    return btoa(unescape(encodeURIComponent(str)));
  }
}

/**
 * Utility: Convert base64 to string
 */
export function base64ToString(base64: string): string {
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return Buffer.from(base64, 'base64').toString('utf-8');
  } else {
    // Browser environment
    return decodeURIComponent(escape(atob(base64)));
  }
}