// Main exports for Willow SDK

export { WillowClient } from "./client";
export {
  WillowAuth,
  SignatureAlgorithm,
  detectAlgorithm,
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  getEd25519PublicKey,
} from "./auth";
export { WillowData, extendQueryResponse, QueryResponseExt } from "./data";

// Export all types
export * from "./types";

// Export utilities
export * from "./utils";

// Export proof verification
export * from "./proof";

// Export computed fields
export {
  ComputedFieldRegistry,
  ComputedFieldDefinition,
  ComputedFieldSet,
  ComputeFunction,
  applyComputedFields,
  applyComputedFieldsToResponse,
  globalComputedFieldRegistry,
  // Pre-built field sets for common protocols
  UNISWAP_V2_PAIR_FIELDS,
  UNISWAP_V2_TOKEN_FIELDS,
  UNISWAP_V2_AGGREGATION_FIELDS,
  GENERIC_AMM_PAIR_FIELDS,
  LENDING_PROTOCOL_FIELDS,
  LP_SHARE_FIELDS,
} from "./computed-fields";

// Export GroveDB proof verification
export * as grovedb from "./grovedb";

// Export light client (with explicit naming to avoid conflicts)
export {
  LightClient,
  LightClientConfigBuilder,
  testConfig as lightClientTestConfig,
  mainnetConfig as lightClientMainnetConfig,
  fastSyncConfig as lightClientFastSyncConfig,
  HeaderVerifier,
  ProofVerifier,
} from "./light-client";
export type {
  LightClientConfig,
  TrustThreshold,
  VerificationResult,
  LightBlock,
  Header,
  ValidatorSet,
  Validator,
  TrustedHeader,
  QueryProof,
} from "./light-client";

// Export consensus client (with explicit naming to avoid conflicts)
export {
  ConsensusClient,
  ConsensusConfigBuilder,
  localConfig as consensusLocalConfig,
  testnetConfig as consensusTestnetConfig,
  mainnetConfig as consensusMainnetConfig,
} from "./consensus";
export type {
  ConsensusConfig,
  BroadcastResult,
  TransactionStatus,
  RegisterDidTx,
  RegisterAppTx,
  RegisterSubgroveTx,
  TransferTx,
  DataStoreTx,
  Transaction,
} from "./consensus";

// Export file storage operations
export { FileOperations, encryptFile, decryptFile } from "./files";
export type { FileManifest, FileListResponse, FileEncryption } from "./files";

// Export privacy / key grant management
export {
  PrivacyOperations,
  CommitmentFrequency,
} from "./privacy";
export type {
  PrivacyConfig,
  EncryptedKeyGrant,
  KeyGrantProofResponse,
} from "./privacy";

// Export ERC-8004 agent identity
export {
  Erc8004Client,
} from "./erc8004";
export type {
  LinkEthAddressTx,
  RegisterErc8004AgentTx,
  AgentRegistrationJson,
  AgentReputationSummary,
  AgentService,
  AgentChainRegistration,
  Erc8004Registration,
  Erc8004AgentListItem,
  Erc8004AgentListResponse,
  ReputationAttestation,
  ReputationHistoryEvent,
  ReputationHistoryResponse,
  Erc8004ValidationRecord,
  Erc8004ValidationStatusResponse,
  ValidationStatusBreakdown,
  DisputeStats,
  Erc8004ValidationSummary,
} from "./erc8004";

// Export version
export const VERSION = "0.1.0";

/**
 * Pre-funded test account for local devnet development.
 *
 * This account is pre-registered and funded in the devnet genesis.
 * Use it for SDK testing and development - DO NOT use in production!
 *
 * @example
 * ```typescript
 * import { WillowClient, DEVNET_TEST_ACCOUNT } from '@willow/sdk';
 *
 * const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
 * client.auth.setIdentity(
 *   DEVNET_TEST_ACCOUNT.did,
 *   DEVNET_TEST_ACCOUNT.privateKey,
 *   DEVNET_TEST_ACCOUNT.publicKeyId
 * );
 * ```
 */
export const DEVNET_TEST_ACCOUNT = {
  /** DID of the test account */
  did: "did:willow:devnet-test",
  /** Private key (hex) - DO NOT USE IN PRODUCTION */
  privateKey:
    "b5ecc03536f5e039e3c5bc46ad178d7faf80cee5f063016a4f4084e163409b3c",
  /** Public key (hex) */
  publicKey: "c153874d3d284a11e3cb12b524e1a9cc32fef966d56b903c79688a95d5193c8f",
  /** Key ID for authentication */
  publicKeyId: "did:willow:devnet-test#key-1",
} as const;
