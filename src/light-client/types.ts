/**
 * Light Client Types
 * 
 * Core data structures for CometBFT light client protocol and GroveDB proof verification.
 */

/**
 * Base exception for light client operations
 */
export class LightClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LightClientError';
  }
}

/**
 * Trust threshold for validator consensus (e.g., 2/3+ validators)
 */
export interface TrustThreshold {
  numerator: number;
  denominator: number;
}

/**
 * Create a trust threshold with validation
 */
export function createTrustThreshold(numerator: number = 2, denominator: number = 3): TrustThreshold {
  if (numerator <= 0 || denominator <= 0) {
    throw new Error('Trust threshold values must be positive');
  }
  if (numerator > denominator) {
    throw new Error('Numerator cannot exceed denominator');
  }
  return { numerator, denominator };
}

/**
 * Get trust threshold as decimal fraction
 */
export function getTrustFraction(threshold: TrustThreshold): number {
  return threshold.numerator / threshold.denominator;
}

/**
 * Individual validator information
 */
export interface Validator {
  address: Uint8Array;
  pubKey: Uint8Array;
  votingPower: number;
  proposerPriority?: number;
}

/**
 * Create validator from CometBFT JSON response
 */
export function createValidator(data: any): Validator {
  return {
    address: base64ToBytes(data.address),
    pubKey: base64ToBytes(data.pub_key.value),
    votingPower: parseInt(data.voting_power),
    proposerPriority: parseInt(data.proposer_priority || '0')
  };
}

/**
 * Set of validators for a specific block
 */
export interface ValidatorSet {
  validators: Validator[];
  proposer?: Validator;
  totalVotingPower?: number;
}

/**
 * Create validator set from CometBFT JSON response
 */
export function createValidatorSet(data: any): ValidatorSet {
  const validators = data.validators.map(createValidator);
  const proposer = data.proposer ? createValidator(data.proposer) : undefined;
  const totalVotingPower = data.total_voting_power
    ? parseInt(data.total_voting_power)
    : validators.reduce((sum: number, v: Validator) => sum + v.votingPower, 0);
  
  return {
    validators,
    proposer,
    totalVotingPower
  };
}

/**
 * Block identifier containing hash and part set header
 */
export interface BlockId {
  hash: Uint8Array;
  partSetHeaderTotal: number;
  partSetHeaderHash: Uint8Array;
}

/**
 * Create block ID from CometBFT JSON response
 */
export function createBlockId(data: any): BlockId {
  return {
    hash: base64ToBytes(data.hash),
    partSetHeaderTotal: parseInt(data.part_set_header.total),
    partSetHeaderHash: base64ToBytes(data.part_set_header.hash)
  };
}

/**
 * Block header containing consensus metadata
 */
export interface Header {
  version: { block: number; app: number };
  chainId: string;
  height: number;
  time: Date;
  lastBlockId?: BlockId;
  lastCommitHash: Uint8Array;
  dataHash: Uint8Array;
  validatorsHash: Uint8Array;
  nextValidatorsHash: Uint8Array;
  consensusHash: Uint8Array;
  appHash: Uint8Array; // Critical for proof verification
  lastResultsHash: Uint8Array;
  evidenceHash: Uint8Array;
  proposerAddress: Uint8Array;
}

/**
 * Create header from CometBFT JSON response
 */
export function createHeader(data: any): Header {
  let lastBlockId: BlockId | undefined;
  if (data.last_block_id && data.last_block_id.hash) {
    lastBlockId = createBlockId(data.last_block_id);
  }
  
  return {
    version: data.version,
    chainId: data.chain_id,
    height: parseInt(data.height),
    time: new Date(data.time),
    lastBlockId,
    lastCommitHash: base64ToBytes(data.last_commit_hash),
    dataHash: base64ToBytes(data.data_hash),
    validatorsHash: base64ToBytes(data.validators_hash),
    nextValidatorsHash: base64ToBytes(data.next_validators_hash),
    consensusHash: base64ToBytes(data.consensus_hash),
    appHash: base64ToBytes(data.app_hash),
    lastResultsHash: base64ToBytes(data.last_results_hash),
    evidenceHash: base64ToBytes(data.evidence_hash),
    proposerAddress: base64ToBytes(data.proposer_address)
  };
}

/**
 * Individual validator's commit signature
 */
export interface CommitSig {
  blockIdFlag: number;
  validatorAddress: Uint8Array;
  timestamp: Date;
  signature?: Uint8Array;
}

/**
 * Create commit signature from CometBFT JSON response
 */
export function createCommitSig(data: any): CommitSig {
  return {
    blockIdFlag: parseInt(data.block_id_flag),
    validatorAddress: base64ToBytes(data.validator_address),
    timestamp: new Date(data.timestamp),
    signature: data.signature ? base64ToBytes(data.signature) : undefined
  };
}

/**
 * Block commit containing validator signatures
 */
export interface Commit {
  height: number;
  round: number;
  blockId: BlockId;
  signatures: CommitSig[];
}

/**
 * Create commit from CometBFT JSON response
 */
export function createCommit(data: any): Commit {
  return {
    height: parseInt(data.height),
    round: parseInt(data.round),
    blockId: createBlockId(data.block_id),
    signatures: data.signatures.map(createCommitSig)
  };
}

/**
 * Complete light block containing header, commit, and validator set
 */
export interface LightBlock {
  header: Header;
  commit: Commit;
  validators: ValidatorSet;
  nextValidators?: ValidatorSet;
  provider?: string;
}

/**
 * Create light block from CometBFT JSON response
 */
export function createLightBlock(data: any, provider?: string): LightBlock {
  return {
    header: createHeader(data.header),
    commit: createCommit(data.commit),
    validators: createValidatorSet(data.validators),
    nextValidators: data.next_validators ? createValidatorSet(data.next_validators) : undefined,
    provider
  };
}

/**
 * Trusted header for state export/import
 */
export interface TrustedHeader {
  header: Header;
  validatorsHash: Uint8Array;
  nextValidatorsHash: Uint8Array;
  trustedAt: Date;
  provider?: string;
}

/**
 * Serialize trusted header for storage
 */
export function serializeTrustedHeader(trusted: TrustedHeader): any {
  return {
    height: trusted.header.height,
    chainId: trusted.header.chainId,
    appHash: bytesToBase64(trusted.header.appHash),
    validatorsHash: bytesToBase64(trusted.validatorsHash),
    nextValidatorsHash: bytesToBase64(trusted.nextValidatorsHash),
    trustedAt: trusted.trustedAt.toISOString(),
    provider: trusted.provider
  };
}

/**
 * Deserialize trusted header from storage
 */
export function deserializeTrustedHeader(data: any): TrustedHeader {
  // Create minimal header for verification
  const header: Header = {
    version: { block: 11, app: 1 },
    chainId: data.chainId,
    height: data.height,
    time: new Date(data.trustedAt),
    lastCommitHash: new Uint8Array(),
    dataHash: new Uint8Array(),
    validatorsHash: base64ToBytes(data.validatorsHash),
    nextValidatorsHash: base64ToBytes(data.nextValidatorsHash),
    consensusHash: new Uint8Array(),
    appHash: base64ToBytes(data.appHash),
    lastResultsHash: new Uint8Array(),
    evidenceHash: new Uint8Array(),
    proposerAddress: new Uint8Array()
  };
  
  return {
    header,
    validatorsHash: base64ToBytes(data.validatorsHash),
    nextValidatorsHash: base64ToBytes(data.nextValidatorsHash),
    trustedAt: new Date(data.trustedAt),
    provider: data.provider
  };
}

/**
 * GroveDB query proof with verification metadata
 */
export interface QueryProof {
  proof: Uint8Array;
  pathQuery: any;
  height: number;
  queryResult?: Uint8Array[];
}

/**
 * Serialize query proof
 */
export function serializeQueryProof(proof: QueryProof): any {
  return {
    proof: bytesToBase64(proof.proof),
    pathQuery: proof.pathQuery,
    height: proof.height,
    queryResult: proof.queryResult?.map(bytesToBase64)
  };
}

/**
 * Deserialize query proof
 */
export function deserializeQueryProof(data: any): QueryProof {
  return {
    proof: base64ToBytes(data.proof),
    pathQuery: data.pathQuery,
    height: data.height,
    queryResult: data.queryResult?.map(base64ToBytes)
  };
}

/**
 * Result of header or proof verification
 */
export interface VerificationResult {
  success: boolean;
  error?: string;
  height?: number;
  nextHeight?: number;
  trustLevel?: number;
}

/**
 * Check if verification was successful
 */
export function isVerificationValid(result: VerificationResult): boolean {
  return result.success && !result.error;
}

/**
 * Configuration for light client operation
 */
export interface LightClientConfig {
  chainId: string;
  validatorEndpoints: string[];
  trustThreshold?: TrustThreshold;
  trustingPeriodSecs?: number;
  maxClockDriftSecs?: number;
  minValidatorsForConsensus?: number;
  autoSync?: boolean;
  syncIntervalSecs?: number;
  maxRetries?: number;
  requestTimeoutSecs?: number;
}

/**
 * Create light client config with defaults
 */
export function createLightClientConfig(config: Partial<LightClientConfig> & Pick<LightClientConfig, 'chainId' | 'validatorEndpoints'>): LightClientConfig {
  if (!config.validatorEndpoints.length) {
    throw new Error('At least one validator endpoint is required');
  }
  
  const minValidators = config.minValidatorsForConsensus || 2;
  if (minValidators < 1) {
    throw new Error('Minimum validators must be at least 1');
  }
  if (config.validatorEndpoints.length < minValidators) {
    throw new Error('Not enough validator endpoints for consensus requirements');
  }
  
  return {
    chainId: config.chainId,
    validatorEndpoints: config.validatorEndpoints,
    trustThreshold: config.trustThreshold || createTrustThreshold(),
    trustingPeriodSecs: config.trustingPeriodSecs || 86400, // 24 hours
    maxClockDriftSecs: config.maxClockDriftSecs || 10,
    minValidatorsForConsensus: minValidators,
    autoSync: config.autoSync ?? true,
    syncIntervalSecs: config.syncIntervalSecs || 300, // 5 minutes
    maxRetries: config.maxRetries || 3,
    requestTimeoutSecs: config.requestTimeoutSecs || 30
  };
}

// Utility functions

/**
 * Convert base64 string to Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    // Browser environment
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Convert Uint8Array to base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    // Node.js environment
    return Buffer.from(bytes).toString('base64');
  } else {
    // Browser environment
    const binaryString = Array.from(bytes, byte => String.fromCharCode(byte)).join('');
    return btoa(binaryString);
  }
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/^0x/, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}