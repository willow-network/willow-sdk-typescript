/**
 * Willow Consensus Client for TypeScript
 * 
 * Provides direct transaction broadcasting to CometBFT consensus layer,
 * enabling full-featured blockchain interactions without relying on data nodes.
 */

export { ConsensusClient } from './client';
export { ConsensusConfigBuilder, localConfig, testnetConfig, mainnetConfig } from './config';

export * from './types';

// Re-export commonly used functions
export {
  createConsensusConfig,
  createTransactionWrapper,
  createSignMessage,
  createBroadcastResult,
  stringToBase64,
  base64ToString
} from './types';