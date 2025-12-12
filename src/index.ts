// Main exports for Willow SDK

export { WillowClient } from './client';
export {
  WillowAuth,
  SignatureAlgorithm,
  detectAlgorithm,
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  getEd25519PublicKey
} from './auth';
export { WillowData, extendQueryResponse, QueryResponseExt } from './data';

// Export all types
export * from './types';

// Export utilities
export * from './utils';

// Export proof verification
export * from './proof';

// Export GroveDB proof verification
export * as grovedb from './grovedb';

// Export light client
export * from './light-client';

// Export consensus client
export * from './consensus';

// Export version
export const VERSION = '0.1.0';