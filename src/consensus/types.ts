/**
 * Consensus Client Types
 *
 * Transaction structures and types for direct blockchain interaction.
 */

import { sha256 } from '@noble/hashes/sha256';
import { WillowError } from '../types';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  hexToBytes,
  utf8ToBytes,
} from '../internal/bytes';
import { toJson } from '../internal/json';
import type { WillowLogger } from '../internal/logger';
import type { NonceAllocator } from './nonces';
import type { PrivacyConfig } from '../privacy';
import { invalid, keySubgroveId, text, textLine, willowDid } from './fields';
import { chainDidDocument, keyGrantWire, registerSubgroveWire } from './wire';
import { registerSubgroveBincode } from './bincode';

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
  /**
   * Hands out transaction nonces per DID. Defaults to
   * `NonceAllocator.shared(apiUrl)`, which every client of that API URL in
   * the process shares.
   */
  nonceAllocator?: NonceAllocator;
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
   * Human-readable subgrove name: the top-level name the chain stores.
   * Defaults to the subgrove id. Like every field, it and the mode's own
   * `name` are signed through the registration's `Config` hash.
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

/**
 * An unsigned integer the chain holds as u64 or u128: a safe-integer number,
 * a bigint, or a string of decimal digits. A number at or above 2^53 is
 * refused, since it may already have been rounded.
 */
export type UintInput = number | bigint | string;

/**
 * How long real-time indexed data is retained on consensus nodes. The chain's
 * own form (`{ Blocks: n }`, `{ Seconds: n }`, `'Indefinite'`, `'VerifyOnly'`)
 * is accepted too.
 */
export type RetentionWindow =
  | { type: 'Blocks'; value: number }
  | { type: 'Seconds'; value: number }
  | { type: 'Indefinite' }
  | { type: 'VerifyOnly' }
  | { Blocks: UintInput }
  | { Seconds: UintInput }
  | 'Indefinite'
  | 'VerifyOnly';

/** A TEE the chain can require. */
export type TeeType = 'AwsNitro' | 'IntelSgx' | 'AmdSev';

/** Paid reads on a data or file subgrove. */
export interface ReadPricing {
  enabled: boolean;
  /** u128, in the token's smallest unit. */
  price_per_query: UintInput;
  /** Owner's share in basis points (u32). */
  owner_revenue_share_bps: number;
}

/** Who runs a BlockchainIndexing subgrove's transformations. */
export type ExecutionMode =
  | 'ConsensusExecution'
  | { IndexerExecution: { sampling_rate_percent: number } }
  | { TeeExecution: { tee_type: TeeType } };

/** Indexer requirements and rewards of a BlockchainIndexing subgrove. */
export interface IndexerConfig {
  min_indexers: number;
  max_indexers: number;
  /** u128. */
  reward_per_epoch: UintInput;
  /** u64; the chain's default, 100, when omitted. */
  epoch_length?: UintInput;
  /** u128. */
  min_indexer_stake: UintInput;
}

/** A WebAssembly module of a BlockchainIndexing subgrove. */
export interface WasmModule {
  name: string;
  /** The 32-byte SHA-256 of `content`, as bytes or hex. */
  hash: number[] | Uint8Array | string;
  content: number[] | Uint8Array;
}

/** Commitments to an indexing subgrove's log and transaction filters. */
export interface CompletenessCommitments {
  log_config_hash: number[];
  tx_config_hash: number[];
  deferred?: boolean;
  /** u128. */
  bond_amount?: UintInput;
}

/**
 * Subgrove mode — determines what kind of data the subgrove holds and how
 * it's ingested. Three variants match the Rust `SubgroveMode` enum. The SDK
 * sends every field, with the chain's default for one left out.
 */
export type SubgroveMode =
  | {
      DataStorage: {
        name: string;
        writers?: string[];
        free_readers?: string[];
        read_pricing?: ReadPricing | null;
      };
    }
  | {
      FileStorage: {
        name: string;
        max_file_size: UintInput;
        replication_factor: number;
        writers?: string[];
        free_readers?: string[];
        read_pricing?: ReadPricing | null;
        retention_period?: UintInput;
      };
    }
  | {
      BlockchainIndexing: {
        manifest_content: number[] | Uint8Array;
        wasm_modules?: WasmModule[];
        execution_mode: ExecutionMode;
        indexer_config: IndexerConfig;
        retention_window?: RetentionWindow;
        completeness?: CompletenessCommitments | null;
        historical_auth_mode?: 'BftEquivalent' | 'CanonizedAccumulator';
      };
    };

/** The ZK-template binding a subgrove can carry. */
export interface TemplateSubgroveConfig {
  template_id: string;
  template_version: number;
  variant_id: string;
  parameters: number[] | Uint8Array;
  contracts: string[];
  event_signatures: string[];
  chain: string | null;
}

/**
 * Subgrove registration transaction.
 *
 * It is signed over a message whose `Config` line is the SHA-256 of the
 * transaction's bincode, so every field is signed; see
 * {@link registerSubgroveSignMessage}.
 */
export interface RegisterSubgroveTx {
  subgroveId: string;
  /** Top-level human-readable name. Defaults to `subgroveId` when omitted. */
  name?: string;
  /** Defaults to `''`. */
  description?: string;
  schema: string; // JSON schema as string
  ownerDid: string;
  /** Defaults to `[]`. */
  admins?: string[];
  /**
   * Defaults to a DataStorage mode named `name` whose only writer is the
   * owner.
   */
  mode?: SubgroveMode;
  /**
   * The retention window of a BlockchainIndexing mode that sets none. The
   * chain has no retention window for other modes, so the SDK refuses one.
   */
  retention_window?: RetentionWindow;
  /** Initial funding (u128) in smallest token unit. Transferred from ownerDid to the subgrove balance. */
  initialFunding?: string;
  /** Defaults to `{ required_tee: null }`. */
  checkpointVerification?: { required_tee: TeeType | null };
  /** Defaults to `null` (a public subgrove). */
  privacy?: PrivacyConfig | null;
  /** Defaults to `null`. */
  initialOwnerKeyGrant?: EncryptedKeyGrant | null;
  /** Defaults to `null`. */
  templateConfig?: TemplateSubgroveConfig | null;
  /** u32; defaults to 0. */
  confirmationDepth?: number;
  /** Defaults to `false`. */
  cryptographicCompleteness?: boolean;
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
  /** u32. */
  key_epoch: number;
  grantee_public_key_id: string;
  ephemeral_public_key: number[];
  encrypted_key: number[];
  granted_by: string;
  /** u64, Unix seconds. */
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

function hexToByteArray(hex: string): number[] {
  return Array.from(hexToBytes(hex));
}

/** The `data` bytes a StoreData transaction carries: its JSON text as UTF-8. */
function storeDataBytes(data: string): Uint8Array {
  return utf8ToBytes(data);
}

/**
 * Decode a hex digest a transaction carries as `[u8; 32]`, refusing any
 * other length. `0x` and upper case are accepted; the wire carries the bytes.
 */
function digestBytes(label: string, hex: string): Uint8Array {
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(hex);
  } catch {
    throw new WillowError(`${label} is not hex`, 'INVALID_DIGEST');
  }
  if (bytes.length !== 32) {
    throw new WillowError(`${label} is ${bytes.length} bytes; it must be 32`, 'INVALID_DIGEST');
  }
  return bytes;
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
    case 'RegisterSubgrove':
      // Every field, in the struct's order, with the chain's default for one
      // the caller left out written out: the signed `Config` hashes the
      // bincode of exactly this object. `initial_funding` (u128) goes as a
      // decimal string, which the chain's `option_u128_flexible` decodes
      // exactly; other u128s above 2^53 go as bigints, which the SDK's JSON
      // writer sends as exact digits.
      return {
        RegisterSubgrove: registerSubgroveWire(transaction as RegisterSubgroveTx, sig as number[]),
      };
    case 'DataStore': {
      const t = transaction as DataStoreTx;
      const data = Array.from(storeDataBytes(t.data));
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
          did_document: chainDidDocument(t.didDocument),
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
          total_size: safeUint('totalSize', t.totalSize, 64),
          content_hash: Array.from(digestBytes('contentHash', t.contentHash)),
          chunk_count: safeUint('chunkCount', t.chunkCount, 32),
          chunk_size: safeUint('chunkSize', t.chunkSize, 32),
          chunk_merkle_root: Array.from(digestBytes('chunkMerkleRoot', t.chunkMerkleRoot)),
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
          node_did: text('nodeDid', t.nodeDid),
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
          subgrove_id: keySubgroveId('subgroveId', t.subgroveId),
          encrypted_key_grant: grantToDid('encryptedKeyGrant', t.encryptedKeyGrant),
          sender_did: text('senderDid', t.senderDid),
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
          ...revokeFields(t),
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
          subgrove_id: keySubgroveId('subgroveId', t.subgroveId),
          new_epoch: safeUint('newEpoch', t.newEpoch, 32),
          new_grants: granteesAreDids(keyGrantsWire(t.newGrants)),
          sender_did: text('senderDid', t.senderDid),
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
 * A number field of the first set of signed transactions, which carry their
 * numbers as JS numbers: a safe integer within u`bits`. A JS number is exact
 * only up to 2^53 - 1, so a larger, negative, or fractional value is refused
 * rather than rounded; ChunkCount and ChunkSize are u32 on the chain, so a
 * value above 2^32 - 1 is refused too.
 */
function safeUint(label: string, value: number | undefined, bits: 32 | 64): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new WillowError(
      `${label} must be a non-negative safe integer, got ${String(value)}`,
      'INVALID_SIGNED_FIELD',
    );
  }
  if (bits === 32 && value > 0xffff_ffff) {
    throw new WillowError(`${label} is outside u32: ${value}`, 'INVALID_SIGNED_FIELD');
  }
  return value;
}

/** A `Label: n` line of a {@link safeUint}: unsigned decimal, no leading zeros. */
function uintLine(label: string, value: number | undefined, bits: 32 | 64 = 64): string {
  return `${label}: ${safeUint(label, value, bits)}`;
}

function keyGrantsWire(grants: unknown): Record<string, unknown>[] {
  if (!Array.isArray(grants)) throw invalid('newGrants must be an array');
  return grants.map((g, i) => keyGrantWire(`newGrants[${i}]`, g));
}

/**
 * A key grant as a grant or rotation carries it ({@link keyGrantWire}),
 * whose grantee is a Willow DID: the chain refuses a grant to anything else.
 */
function grantToDid(label: string, value: unknown): Record<string, unknown> {
  const g = keyGrantWire(label, value);
  willowDid(`${label}.grantee_did`, g.grantee_did);
  return g;
}

/** A rotation's grants, each grantee checked as {@link grantToDid} checks one. */
function granteesAreDids(grants: Record<string, unknown>[]): Record<string, unknown>[] {
  grants.forEach((g, i) => willowDid(`newGrants[${i}].grantee_did`, g.grantee_did));
  return grants;
}

/**
 * A revoke's subgrove id and DIDs, checked: the chain refuses a revoke whose
 * subgrove id is empty or holds a `:`, or whose revokee or sender is not a
 * Willow DID.
 */
function revokeFields(tx: RevokeSubgroveKeyTx): Record<string, string> {
  return {
    subgrove_id: keySubgroveId('subgroveId', tx.subgroveId),
    revokee_did: willowDid('revokeeDid', tx.revokeeDid),
    sender_did: willowDid('senderDid', tx.senderDid),
  };
}

/**
 * The message a StoreData transaction (`'DataStore'` in this SDK) is signed
 * over:
 *
 * ```
 * StoreData
 * Subgrove: <subgroveId>
 * Key: <key>
 * Owner: <ownerDid>
 * DataHash: <hex SHA-256 of the data bytes the transaction carries>
 * Nonce: <nonce>
 * ```
 *
 * Lines are joined by `\n` with no trailing newline. The data bytes are
 * `tx.data` as UTF-8, exactly as {@link createTransactionWrapper} sends them.
 * Set the nonce before building the message: the chain checks the signature
 * against the nonce the transaction carries. A write the chain refuses in its
 * block after its signature and nonce verify still spends that nonce; to
 * retry, sign again under the next free nonce.
 *
 * @throws WillowError if `subgroveId`, `key`, or `ownerDid` holds a `\n`, or
 *   the nonce is not a non-negative safe integer.
 */
export function storeDataSignMessage(tx: DataStoreTx): string {
  return [
    'StoreData',
    textLine('Subgrove', tx.subgroveId),
    textLine('Key', tx.key),
    textLine('Owner', tx.ownerDid),
    `DataHash: ${bytesToHex(sha256(storeDataBytes(tx.data)))}`,
    uintLine('Nonce', tx.nonce),
  ].join('\n');
}

/**
 * The message a StoreFileManifest transaction is signed over, binding every
 * manifest field:
 *
 * ```
 * StoreFileManifest
 * Subgrove: <subgroveId>
 * Key: <fileKey>
 * Owner: <ownerDid>
 * Filename: <filename>
 * ContentType: <contentType>
 * TotalSize: <totalSize>
 * ContentHash: <lowercase hex of the 32-byte contentHash>
 * ChunkCount: <chunkCount>
 * ChunkSize: <chunkSize>
 * ChunkMerkleRoot: <lowercase hex of the 32-byte chunkMerkleRoot>
 * Encryption: none
 * Nonce: <nonce>
 * ```
 *
 * Lines are joined by `\n` with no trailing newline. The SDK sends no
 * `encryption`, so the line is `none`.
 *
 * @throws WillowError if `subgroveId`, `fileKey`, `ownerDid`, `filename`, or
 *   `contentType` holds a `\n`, a digest is not 32 bytes of hex, a number is
 *   not a non-negative safe integer, or `chunkCount` or `chunkSize` is
 *   outside u32.
 */
export function storeFileManifestSignMessage(tx: StoreFileManifestTx): string {
  return [
    'StoreFileManifest',
    textLine('Subgrove', tx.subgroveId),
    textLine('Key', tx.fileKey),
    textLine('Owner', tx.ownerDid),
    textLine('Filename', tx.filename),
    textLine('ContentType', tx.contentType),
    uintLine('TotalSize', tx.totalSize),
    `ContentHash: ${bytesToHex(digestBytes('contentHash', tx.contentHash))}`,
    uintLine('ChunkCount', tx.chunkCount, 32),
    uintLine('ChunkSize', tx.chunkSize, 32),
    `ChunkMerkleRoot: ${bytesToHex(digestBytes('chunkMerkleRoot', tx.chunkMerkleRoot))}`,
    'Encryption: none',
    uintLine('Nonce', tx.nonce),
  ].join('\n');
}

/**
 * The message a DeleteFileManifest transaction is signed over:
 *
 * ```
 * DeleteFileManifest
 * Subgrove: <subgroveId>
 * Key: <fileKey>
 * Owner: <ownerDid>
 * Nonce: <nonce>
 * ```
 *
 * Lines are joined by `\n` with no trailing newline.
 *
 * @throws WillowError if `subgroveId`, `fileKey`, or `ownerDid` holds a `\n`,
 *   or the nonce is not a non-negative safe integer.
 */
export function deleteFileManifestSignMessage(tx: DeleteFileManifestTx): string {
  return [
    'DeleteFileManifest',
    textLine('Subgrove', tx.subgroveId),
    textLine('Key', tx.fileKey),
    textLine('Owner', tx.ownerDid),
    uintLine('Nonce', tx.nonce),
  ].join('\n');
}

/** The nonce of a signed transaction, which the message must carry. */
function nonceLine(nonce: number | undefined): string {
  return uintLine('Nonce', nonce);
}

/**
 * The bincode (1.x default) of a RegisterSubgrove transaction with an empty
 * signature: the bytes its signed `Config` line hashes. It encodes the body
 * {@link createTransactionWrapper} sends, field for field.
 *
 * @throws WillowError if a field is not one the chain can decode as given
 *   (a text field with a lone surrogate, an integer outside its type or an
 *   unsafe JS number, an unknown enum variant, a missing required field), or
 *   a DataStorage or FileStorage registration breaks the chain's rules for
 *   its subgrove id or schema (see {@link registerSubgroveSignMessage}).
 */
export function registerSubgroveUnsignedBincode(tx: RegisterSubgroveTx): Uint8Array {
  return registerSubgroveBincode(registerSubgroveWire(tx, []));
}

/**
 * The message a RegisterSubgrove transaction is signed over, in every mode:
 *
 * ```
 * RegisterSubgrove
 * Subgrove: <subgroveId>
 * Owner: <ownerDid>
 * Config: <hex SHA-256 of the transaction's bincode with an empty signature>
 * Nonce: <nonce>
 * ```
 *
 * `Config` hashes {@link registerSubgroveUnsignedBincode}, so the signature
 * covers every field the transaction carries, including the defaults the SDK
 * writes out for fields the caller left unset. Lines are joined by `\n`
 * with no trailing newline. Set the nonce before building the message.
 *
 * @throws WillowError if `subgroveId` or `ownerDid` holds a `\n`, the nonce
 *   is missing or not a non-negative safe integer, a field can't be encoded
 *   (see {@link registerSubgroveUnsignedBincode}), or a DataStorage or
 *   FileStorage registration breaks the chain's rules for it: a subgrove id
 *   that isn't 1–64 ASCII letters, digits, `-`, or `_` starting with a letter
 *   or digit (`INVALID_SUBGROVE_ID`), schema text the chain doesn't parse as
 *   a schema (`INVALID_SCHEMA`; see `serializeSchema`), or a schema that
 *   declares indexes (`SCHEMA_INDEXES_UNSUPPORTED`).
 */
export function registerSubgroveSignMessage(tx: RegisterSubgroveTx): string {
  nonceLine(tx.nonce);
  // The lines first: a line break is refused as such, before the id's rules.
  const subgrove = textLine('Subgrove', tx.subgroveId);
  const owner = textLine('Owner', tx.ownerDid);
  const w = registerSubgroveWire(tx, []);
  return [
    'RegisterSubgrove',
    subgrove,
    owner,
    `Config: ${bytesToHex(sha256(registerSubgroveBincode(w)))}`,
    `Nonce: ${w.nonce}`,
  ].join('\n');
}

/** The seven lines of one key grant, from its wire form. */
function grantLines(g: Record<string, unknown>): string[] {
  return [
    textLine('Grantee', g.grantee_did),
    textLine('GranteeKey', g.grantee_public_key_id),
    `KeyEpoch: ${g.key_epoch}`,
    `EphemeralKey: ${bytesToHex(Uint8Array.from(g.ephemeral_public_key as number[]))}`,
    `EncryptedKey: ${bytesToHex(Uint8Array.from(g.encrypted_key as number[]))}`,
    textLine('GrantedBy', g.granted_by),
    `GrantedAt: ${g.granted_at}`,
  ];
}

/**
 * The message a GrantSubgroveKey transaction is signed over:
 *
 * ```
 * GrantSubgroveKey
 * Subgrove: <subgroveId>
 * Sender: <senderDid>
 * Grantee: <grantee_did>
 * GranteeKey: <grantee_public_key_id>
 * KeyEpoch: <key_epoch>
 * EphemeralKey: <hex of ephemeral_public_key>
 * EncryptedKey: <hex of encrypted_key>
 * GrantedBy: <granted_by>
 * GrantedAt: <granted_at>
 * Nonce: <nonce>
 * ```
 *
 * @throws WillowError if a text field holds a `\n` or a lone surrogate, a
 *   byte field holds a value outside 0..255, `key_epoch` is outside u32,
 *   `granted_at` is outside u64 (or an unsafe JS number), or the nonce is not
 *   a non-negative safe integer; or, as the chain refuses them, if the
 *   subgrove id is empty or holds a `:` (`INVALID_SUBGROVE_ID`) or the
 *   grantee is not a Willow DID (`INVALID_DID`): `did:willow:` followed by
 *   one or more ASCII letters, digits, `_`, or `-`, at most 128 bytes.
 */
export function grantSubgroveKeySignMessage(tx: GrantSubgroveKeyTx): string {
  const grant = keyGrantWire('encryptedKeyGrant', tx.encryptedKeyGrant);
  const message = [
    'GrantSubgroveKey',
    textLine('Subgrove', tx.subgroveId),
    textLine('Sender', tx.senderDid),
    ...grantLines(grant),
    nonceLine(tx.nonce),
  ].join('\n');
  // The lines first: a line break is refused as such, before the id and DID rules.
  keySubgroveId('subgroveId', tx.subgroveId);
  willowDid('encryptedKeyGrant.grantee_did', grant.grantee_did);
  return message;
}

/**
 * The message a RotateSubgroveKey transaction is signed over:
 *
 * ```
 * RotateSubgroveKey
 * Subgrove: <subgroveId>
 * Sender: <senderDid>
 * NewEpoch: <newEpoch>
 * Grants: <number of newGrants>
 * <for each grant in order, its seven lines Grantee … GrantedAt>
 * Nonce: <nonce>
 * ```
 *
 * @throws WillowError as {@link grantSubgroveKeySignMessage} (for every
 *   grant's grantee), or if `newEpoch` is outside u32.
 */
export function rotateSubgroveKeySignMessage(tx: RotateSubgroveKeyTx): string {
  const grants = keyGrantsWire(tx.newGrants);
  const message = [
    'RotateSubgroveKey',
    textLine('Subgrove', tx.subgroveId),
    textLine('Sender', tx.senderDid),
    uintLine('NewEpoch', tx.newEpoch, 32),
    `Grants: ${grants.length}`,
    ...grants.flatMap(grantLines),
    nonceLine(tx.nonce),
  ].join('\n');
  // The lines first: a line break is refused as such, before the id and DID rules.
  keySubgroveId('subgroveId', tx.subgroveId);
  granteesAreDids(grants);
  return message;
}

/**
 * The message a RevokeSubgroveKey transaction is signed over:
 *
 * ```
 * RevokeSubgroveKey:<subgroveId>:<revokeeDid>:<senderDid>:<nonce>
 * ```
 *
 * The chain refuses a revoke whose subgrove id is empty or holds a `:`, or
 * whose revokee or sender is not a Willow DID (`did:willow:` followed by one
 * or more ASCII letters, digits, `_`, or `-`, at most 128 bytes), so the SDK
 * refuses to sign one.
 *
 * @throws WillowError `INVALID_SUBGROVE_ID` or `INVALID_DID` for such a
 *   field, or if a field holds a lone surrogate or the nonce is not a
 *   non-negative safe integer.
 */
export function revokeSubgroveKeySignMessage(tx: RevokeSubgroveKeyTx): string {
  const f = revokeFields(tx);
  const nonce = safeUint('Nonce', tx.nonce, 64);
  return `RevokeSubgroveKey:${f.subgrove_id}:${f.revokee_did}:${f.sender_did}:${nonce}`;
}

/**
 * The message an UnregisterStorageNode transaction is signed over:
 *
 * ```
 * UnregisterStorageNode
 * Node: <nodeDid>
 * Nonce: <nonce>
 * ```
 *
 * @throws WillowError if `nodeDid` holds a `\n` or the nonce is not a
 *   non-negative safe integer.
 */
export function unregisterStorageNodeSignMessage(tx: UnregisterStorageNodeTx): string {
  return ['UnregisterStorageNode', textLine('Node', tx.nodeDid), nonceLine(tx.nonce)].join('\n');
}

/**
 * The message a RegisterDid transaction is signed over: the JSON text of the
 * DID document as the chain's `DidDocument` (every field in its order, the
 * optional ones written out), which is the text the node signs. It is the
 * document {@link createTransactionWrapper} sends.
 */
export function registerDidSignMessage(tx: RegisterDidTx): string {
  return toJson(chainDidDocument(tx.didDocument));
}

/**
 * Create the canonical message a transaction is signed over.
 *
 * The byte sequence here must match the format the chain's signature
 * validator re-derives — any drift causes the signature check to fail.
 */
export function createSignMessage(txType: string, transaction: Transaction): string {
  switch (txType) {
    case 'RegisterDid':
      return registerDidSignMessage(transaction as RegisterDidTx);

    case 'RegisterSubgrove':
      return registerSubgroveSignMessage(transaction as RegisterSubgroveTx);

    case 'GrantSubgroveKey':
      return grantSubgroveKeySignMessage(transaction as GrantSubgroveKeyTx);

    case 'RotateSubgroveKey':
      return rotateSubgroveKeySignMessage(transaction as RotateSubgroveKeyTx);

    case 'RevokeSubgroveKey':
      return revokeSubgroveKeySignMessage(transaction as RevokeSubgroveKeyTx);

    case 'UnregisterStorageNode':
      return unregisterStorageNodeSignMessage(transaction as UnregisterStorageNodeTx);

    case 'Transfer': {
      const tx = transaction as TransferTx;
      return `Transfer\nFrom: ${tx.fromDid}\nTo: ${tx.toDid}\nAmount: ${tx.amount}\nMemo: ${tx.memo || ''}\nNonce: ${tx.nonce || 0}`;
    }

    case 'DataStore':
      return storeDataSignMessage(transaction as DataStoreTx);

    case 'StoreFileManifest':
      return storeFileManifestSignMessage(transaction as StoreFileManifestTx);

    case 'DeleteFileManifest':
      return deleteFileManifestSignMessage(transaction as DeleteFileManifestTx);

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