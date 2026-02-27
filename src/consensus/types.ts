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

/**
 * App registration transaction
 */
export interface RegisterAppTx {
  appId: string;
  name: string;
  description: string;
  appType: string;
  ownerDid: string;
  admins?: string[];
  initialFunding?: number;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Subgrove mode: DataStorage or BlockchainIndexing.
 * When omitted, defaults to DataStorage with empty values.
 */
export type SubgroveMode =
  | { DataStorage: { name: string; writers?: string[]; free_readers?: string[]; read_pricing?: any; required_verifications?: number } }
  | { BlockchainIndexing: { manifest_ipfs: string; manifest_content?: number[]; wasm_modules?: any[]; execution_mode?: any; indexer_config?: any } };

/**
 * Subgrove registration transaction
 */
export interface RegisterSubgroveTx {
  subgroveId: string;
  appId: string;
  schema: string; // JSON schema as string
  ownerDid: string;
  mode?: SubgroveMode;
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
  appId: string;
  subgroveId: string;
  key: string;
  data: string; // JSON data as string
  ownerDid: string;
  signature?: string; // hex-encoded
  publicKeyId?: string;
  nonce?: number;
}

/**
 * Transaction type union
 */
export type Transaction = RegisterDidTx | RegisterAppTx | RegisterSubgroveTx | TransferTx | DataStoreTx;

/**
 * Create transaction wrapper for consensus submission
 */
export function createTransactionWrapper(txType: string, transaction: Transaction): any {
  return { [txType]: transaction };
}

/**
 * Create canonical message for transaction signing
 */
export function createSignMessage(txType: string, transaction: Transaction): string {
  switch (txType) {
    case 'RegisterDid': {
      const tx = transaction as RegisterDidTx;
      // For DID registration, sign the DID document directly
      return JSON.stringify(tx.didDocument);
    }

    case 'RegisterApp': {
      const tx = transaction as RegisterAppTx;
      const parts = [
        'RegisterApp',
        `App ID: ${tx.appId}`,
        `Name: ${tx.name}`,
        `Description: ${tx.description}`,
        `Type: ${tx.appType}`,
        `Owner: ${tx.ownerDid}`,
        `Admins: ${(tx.admins || []).join(',')}`,
        `Nonce: ${tx.nonce || 0}`
      ];
      if (tx.initialFunding && tx.initialFunding > 0) {
        parts.push(`Funding: ${tx.initialFunding}`);
      }
      return parts.join('\n');
    }

    case 'RegisterSubgrove': {
      const tx = transaction as RegisterSubgroveTx;
      const mode = tx.mode;
      if (mode && 'BlockchainIndexing' in mode) {
        return [
          'RegisterSubgrove',
          `Subgrove ID: ${tx.subgroveId}`,
          `App ID: ${tx.appId}`,
          `Mode: BlockchainIndexing`,
          `Schema: ${tx.schema}`,
          `ManifestIPFS: ${mode.BlockchainIndexing.manifest_ipfs}`,
          `Owner: ${tx.ownerDid}`,
          `Nonce: ${tx.nonce || 0}`
        ].join('\n');
      }
      // DataStorage mode (default)
      const ds = mode && 'DataStorage' in mode ? mode.DataStorage : { name: '', writers: [], free_readers: [] };
      return [
        'RegisterSubgrove',
        `Subgrove ID: ${tx.subgroveId}`,
        `App ID: ${tx.appId}`,
        `Name: ${ds.name || ''}`,
        `Schema: ${tx.schema}`,
        `Owner: ${tx.ownerDid}`,
        `Writers: ${(ds.writers || []).join(',')}`,
        `Readers: ${(ds.free_readers || []).join(',')}`,
        `Nonce: ${tx.nonce || 0}`
      ].join('\n');
    }

    case 'Transfer': {
      const tx = transaction as TransferTx;
      return [
        'Transfer',
        `From: ${tx.fromDid}`,
        `To: ${tx.toDid}`,
        `Amount: ${tx.amount}`,
        `Memo: ${tx.memo || ''}`,
        `Nonce: ${tx.nonce || 0}`
      ].join('\n');
    }

    case 'DataStore': {
      const tx = transaction as DataStoreTx;
      return [
        'DataStore',
        `App ID: ${tx.appId}`,
        `Subgrove ID: ${tx.subgroveId}`,
        `Key: ${tx.key}`,
        `Data: ${tx.data}`,
        `Owner: ${tx.ownerDid}`,
        `Nonce: ${tx.nonce || 0}`
      ].join('\n');
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