/**
 * Consensus Client Types
 *
 * Transaction structures and types for direct blockchain interaction.
 */

import { keccak_256 } from '@noble/hashes/sha3';
import { WillowError } from '../types';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  utf8ToBytes,
} from '../internal/bytes';
import type { WillowLogger } from '../internal/logger';

/**
 * Base exception for consensus client operations
 */
export class ConsensusError extends WillowError {
  constructor(message: string, code?: string) {
    super(message, code);
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
  consensusRpcUrl?: string; // CometBFT RPC URL for consensus reads (tx status, chain info)
  apiUrl?: string; // REST API URL for tx submission and account queries (nonce, etc.)
  apiKey?: string; // Managed-tier API key sent as X-API-Key
  chainId?: string;
  requestTimeoutSecs?: number;
  maxRetries?: number;
  retryDelaySecs?: number;
  logger?: WillowLogger; // Diagnostics logger; defaults to silent
}

/** Signs a canonical message with a hex private key, returning a hex signature. */
export type SignFunction = (message: string, privateKey: string) => string;

/**
 * Key material for signing consensus transactions. Accepted by every
 * ConsensusClient write method in place of the positional
 * (privateKey, publicKeyId, signFunction) tail.
 */
export interface Signer {
  /** Hex-encoded private key. */
  privateKey: string;
  /** Public key ID registered in the DID document (e.g. `did:willow:x#key-1`). */
  publicKeyId: string;
  /** Defaults to the SDK's `signEd25519`. */
  signFunction?: SignFunction;
}

/** Optional RegisterSubgrove parameters. */
export interface RegisterSubgroveOptions {
  /**
   * Human-readable subgrove name. This is the top-level name the chain
   * stores and signs over (the per-mode `name` is ignored by the
   * validator for the signing message). Defaults to the subgrove id.
   */
  name?: string;
  mode?: SubgroveMode;
  retentionWindow?: RetentionWindow;
  initialFunding?: string;
}

/** Manifest fields for `storeFileManifest`. */
export interface StoreFileManifestFields {
  subgroveId: string;
  fileKey: string;
  filename: string;
  contentType: string;
  totalSize: number;
  contentHash: string;
  chunkCount: number;
  chunkSize: number;
  chunkMerkleRoot: string;
  ownerDid: string;
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
  /**
   * Top-level human-readable name. The chain stores this and signs over it
   * for DataStorage/FileStorage modes (the per-mode `name` is not part of
   * the signing message). Defaults to `subgroveId` when omitted.
   */
  name?: string;
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

/** Unregister a storage node and begin stake unbonding. */
export interface UnregisterStorageNodeTx {
  nodeDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Encrypted copy of a subgrove's symmetric key, wrapped for a reader DID.
 * Byte fields are number arrays — the chain's `EncryptedKeyGrant` declares
 * `ephemeral_public_key`/`encrypted_key` as `Vec<u8>` with no `serde_bytes`,
 * so JSON must carry arrays of numbers, never hex strings.
 */
export interface EncryptedKeyGrant {
  grantee_did: string;
  key_epoch: number;
  grantee_public_key_id: string;
  ephemeral_public_key: number[];
  encrypted_key: number[];
  granted_by: string;
  granted_at: number;
}

/** Grant a subgrove encryption key to a DID. */
export interface GrantSubgroveKeyTx {
  subgroveId: string;
  encryptedKeyGrant: EncryptedKeyGrant;
  senderDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/** Revoke a subgrove encryption key from a DID. */
export interface RevokeSubgroveKeyTx {
  subgroveId: string;
  revokeeDid: string;
  senderDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/** Rotate the subgrove encryption key and re-grant to authorized DIDs. */
export interface RotateSubgroveKeyTx {
  subgroveId: string;
  newEpoch: number;
  newGrants: EncryptedKeyGrant[];
  senderDid: string;
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
export type Transaction =
  | RegisterDidTx
  | RegisterSubgroveTx
  | TransferTx
  | DataStoreTx
  | StoreFileManifestTx
  | DeleteFileManifestTx
  | UnregisterStorageNodeTx
  | DeregisterSubgroveTx
  | SubmitAnchorTx
  | GrantSubgroveKeyTx
  | RevokeSubgroveKeyTx
  | RotateSubgroveKeyTx;

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
  return Array.from(hexToBytes(hex));
}

/**
 * Create transaction wrapper for consensus submission.
 *
 * This is the SINGLE place the SDK encodes a transaction to the wire shape
 * the Rust `Transaction` enum deserializes. The chain's structs declare
 * `signature: Vec<u8>` and digest fields like `content_hash: [u8; 32]`
 * without `serde_bytes`, so serde_json requires arrays of numbers — a hex
 * string is rejected by the axum extractor (422) before the handler runs.
 * Every byte/digest field is converted hex -> number[] here, and every
 * field is renamed to the snake_case key the variant declares.
 *
 * Unknown tx types throw rather than falling through to a camelCase
 * passthrough, so a new variant can't silently ship an unparseable shape.
 */
export function createTransactionWrapper(txType: string, transaction: Transaction): any {
  const tx = transaction as unknown as Record<string, unknown>;
  const sig = typeof tx.signature === 'string' ? hexToByteArray(tx.signature as string) : tx.signature ?? [];
  const nonce = typeof tx.nonce === 'number' ? tx.nonce : 0;
  const publicKeyId = tx.publicKeyId ?? '';

  switch (txType) {
    case 'RegisterSubgrove': {
      const t = transaction as RegisterSubgroveTx;
      const name = t.name ?? t.subgroveId;
      const wrapper: Record<string, unknown> = {
        subgrove_id: t.subgroveId,
        name,
        description: '',
        schema: t.schema,
        owner_did: t.ownerDid,
        admins: [],
        mode: t.mode ?? { DataStorage: { name, writers: [t.ownerDid], free_readers: [] } },
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
    case 'StoreFileManifest': {
      const t = transaction as StoreFileManifestTx;
      return {
        StoreFileManifest: {
          subgrove_id: t.subgroveId,
          file_key: t.fileKey,
          filename: t.filename,
          content_type: t.contentType,
          total_size: t.totalSize,
          content_hash: hexToByteArray(t.contentHash),
          chunk_count: t.chunkCount,
          chunk_size: t.chunkSize,
          chunk_merkle_root: hexToByteArray(t.chunkMerkleRoot),
          owner_did: t.ownerDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'DeleteFileManifest': {
      const t = transaction as DeleteFileManifestTx;
      return {
        DeleteFileManifest: {
          subgrove_id: t.subgroveId,
          file_key: t.fileKey,
          owner_did: t.ownerDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'UnregisterStorageNode': {
      const t = transaction as UnregisterStorageNodeTx;
      return {
        UnregisterStorageNode: {
          node_did: t.nodeDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'GrantSubgroveKey': {
      const t = transaction as GrantSubgroveKeyTx;
      return {
        GrantSubgroveKey: {
          subgrove_id: t.subgroveId,
          encrypted_key_grant: t.encryptedKeyGrant,
          sender_did: t.senderDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'RevokeSubgroveKey': {
      const t = transaction as RevokeSubgroveKeyTx;
      return {
        RevokeSubgroveKey: {
          subgrove_id: t.subgroveId,
          revokee_did: t.revokeeDid,
          sender_did: t.senderDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    case 'RotateSubgroveKey': {
      const t = transaction as RotateSubgroveKeyTx;
      return {
        RotateSubgroveKey: {
          subgrove_id: t.subgroveId,
          new_epoch: t.newEpoch,
          new_grants: t.newGrants,
          sender_did: t.senderDid,
          signature: sig,
          public_key_id: publicKeyId,
          nonce,
        },
      };
    }
    default:
      throw new WillowError(`Unknown transaction type: ${txType}`, 'UNKNOWN_TX_TYPE');
  }
}

/**
 * Keccak256 hash of a string, matching the Rust server's
 * `TransactionValidator::hash_string` (uses `sha3::Keccak256`).
 */
function schemaHash(schema: string): string {
  return bytesToHex(keccak_256(utf8ToBytes(schema)));
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
      // The validator signs over the top-level `name`, not the per-mode one
      // (`create_register_subgrove_message` reads `params.name`, and the mode
      // `name` field is `name: _` in the handler).
      const name = tx.name ?? tx.subgroveId;

      // BlockchainIndexing signs a simpler payload than the other modes.
      if (mode && 'BlockchainIndexing' in mode) {
        return `RegisterSubgrove:${tx.subgroveId}:${tx.ownerDid}:${tx.nonce || 0}`;
      }

      if (mode && 'FileStorage' in mode) {
        const fs = (mode as { FileStorage: { writers?: string[]; free_readers?: string[] } }).FileStorage;
        return `RegisterSubgrove\nID: ${tx.subgroveId}\nMode: FileStorage\nName: ${name}\nDescription: \nSchemaHash: ${sh}\nOwner: ${tx.ownerDid}\nAdmins: \nWriters: ${(fs.writers ?? []).join(',')}\nReaders: ${(fs.free_readers ?? []).join(',')}\nNonce: ${tx.nonce || 0}`;
      }
      // DataStorage mode (default)
      const ds = mode && 'DataStorage' in mode
        ? (mode as { DataStorage: { writers?: string[]; free_readers?: string[] } }).DataStorage
        : { writers: [tx.ownerDid], free_readers: [] as string[] };
      return `RegisterSubgrove\nID: ${tx.subgroveId}\nName: ${name}\nDescription: \nSchemaHash: ${sh}\nOwner: ${tx.ownerDid}\nAdmins: \nWriters: ${(ds.writers ?? []).join(',')}\nReaders: ${(ds.free_readers ?? []).join(',')}\nNonce: ${tx.nonce || 0}`;
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
  return bytesToBase64(utf8ToBytes(str));
}

/**
 * Utility: Convert base64 to string
 */
export function base64ToString(base64: string): string {
  return bytesToUtf8(base64ToBytes(base64));
}