/**
 * Willow Consensus Client for TypeScript
 * 
 * Provides direct transaction broadcasting to CometBFT consensus layer,
 * enabling full-featured blockchain interactions without relying on data nodes.
 */

export { ConsensusClient } from './client';
export {
  NonceAllocator,
  NONCE_WINDOW,
  NONCE_HOLD_MS,
  parseAccountNonceState,
  refusalKeepsNonce,
} from './nonces';
export type { AccountNonceState, NonceAllocatorOptions } from './nonces';
export { ConsensusConfigBuilder, localConfig, testnetConfig, mainnetConfig } from './config';

export * from './types';
export { serializeSchema, SCHEMA_FIELD_TYPES } from './schema';

// Re-export commonly used functions
export {
  createConsensusConfig,
  createTransactionWrapper,
  createSignMessage,
  createBroadcastResult,
  stringToBase64,
  base64ToString
} from './types';