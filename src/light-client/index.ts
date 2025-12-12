/**
 * Willow Light Client for TypeScript
 * 
 * Provides cryptographically secure data verification through CometBFT light client protocol
 * and GroveDB proof verification, enabling trustless operation without running a full node.
 */

export { LightClient } from './client';
export { HeaderVerifier, ProofVerifier } from './verifier';
export { LightClientConfigBuilder, testConfig, mainnetConfig, fastSyncConfig } from './config';

export * from './types';

// Re-export commonly used functions
export {
  createLightClientConfig,
  createTrustThreshold,
  getTrustFraction,
  isVerificationValid,
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  hexToBytes
} from './types';