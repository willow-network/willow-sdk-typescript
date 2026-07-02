// Main exports for Willow SDK

export { WillowClient } from "./client";
export {
  WillowAuth,
  SignatureAlgorithm,
  detectAlgorithm,
  algorithmFromKeyType,
  signEd25519,
  verifyEd25519,
  generateEd25519KeyPair,
  getEd25519PublicKey,
} from "./auth";
export {
  WillowData,
  extendQueryResponse,
  QueryResponseExt,
  ValidatorHasNoDataError,
  NoIndexersReachableError,
} from "./data";
export type { WillowDataOptions } from "./data";

// Indexer discovery + subscription clients
export { WillowIndexers, effectiveQueryEndpoint } from "./indexers";
export type { ApiIndexerInfo, WillowIndexersOptions } from "./indexers";
export { WillowSubscriptions } from "./subscriptions";
export type {
  SubscribeOptions,
  SubscribeSource,
  UnsubscribeFn,
  WebSocketConstructor,
  WebSocketLike,
  WillowSubscriptionsOptions,
} from "./subscriptions";

// Injectable logging: silent by default, pass `consoleLogger` (or your own)
// via WillowConfig.logger to surface SDK diagnostics.
export { silentLogger, consoleLogger } from "./internal/logger";
export type { WillowLogger } from "./internal/logger";

// Export all types
export * from "./types";

// HTTP client used by all SDK modules; HttpError is thrown on non-2xx
// API responses that a module doesn't map to a WillowError itself.
export { HttpClient, HttpError } from "./internal/http";
export type { HttpClientOptions, HttpRequestOptions } from "./internal/http";

// Public DID/wallet helpers. The generic utils (sleep, retry, chunk,
// generateId) are internal and intentionally not part of the package API.
export {
  generateWallet,
  createDidFromWallet,
  createDidFromPublicKey,
  deriveDid,
  isValidDid,
} from "./utils";
export type { DidKeyAlgorithm } from "./utils";

// Export proof verification
export * from "./proof";

// Export verifiable RPC (direct indexer->client verified reads)
export * from "./verifiable-rpc";

// Export computed fields
export {
  ComputedFieldRegistry,
  ComputedFieldDefinition,
  ComputedFieldSet,
  ComputeFunction,
  applyComputedFields,
  applyComputedFieldsToResponse,
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

// Verifiable Ethereum state reads.
export {
  EthOperations,
  StateVerifyMode,
  verifyMptProof,
  verifyStateProof,
} from "./eth-state";
export type {
  AccountState,
  EthCallRequestBody,
  EthStateRequest,
  EthVerifiableRpcResponse,
  MptProof,
  StateProof,
  StorageSlotProof,
  VerifiedCall,
  VerifiedStateRead,
  VerifiedStorage,
} from "./eth-state";

// Canonical WillowManifest builder + chain identifiers
export * as manifest from "./manifest";
export type {
  WillowManifest,
  DataSource,
  EvmDataSource,
  SupportedChain,
  ChainFamily,
} from "./manifest";
export {
  SUPPORTED_CHAINS,
  MANIFEST_SPEC_VERSION,
  serializeManifest,
  parseManifest,
  validateManifest,
  ManifestValidationError,
  isSupportedChain,
  chainFamily,
  evmChainId,
  fromEvmChainId,
} from "./manifest";

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
  GroveDBQueryProof,
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
  RegisterSubgroveTx,
  TransferTx,
  DataStoreTx,
  Transaction,
  Signer,
  SignFunction,
  RegisterSubgroveOptions,
  StoreFileManifestFields,
} from "./consensus";

// Export file storage operations
export { FileOperations, encryptFile, decryptFile } from "./files";
export type { FileManifest, FileListResponse, FileEncryption } from "./files";

// Export privacy / key grant management
export { PrivacyOperations, CommitmentFrequency } from "./privacy";
export type {
  PrivacyConfig,
  EncryptedKeyGrant,
  KeyGrantProofResponse,
} from "./privacy";

// Export ERC-8004 agent identity
export { Erc8004Client } from "./erc8004";
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

// Per-(vault, day) ERC-4626 flow aggregate codecs (`vault-daily-stats`
// template). Pairs with the indexer's verifiable-rpc-range endpoint.
export {
  VAULT_DAILY_STATS_KEY_LEN,
  VAULT_DAILY_STATS_VALUE_LEN,
  SECONDS_PER_DAY,
  dayIdFromTimestamp,
  dayIdFromDate,
  encodeVaultDailyStatsKey,
  decodeVaultDailyStatsKey,
  decodeDayAggregate,
  encodeDayAggregate,
  decodeVaultDailyStatsRows,
  vaultDayRangeKeys,
} from "./aggregates/vault-daily-stats";
export type {
  DayAggregate,
  VaultDailyStatsRow,
} from "./aggregates/vault-daily-stats";

// Client-side completeness verification: re-derive the on-chain
// `events_commitment` (canonical keccak-256 over the filter-matched event
// set) from indexer-served logs and compare against the trusted anchor.
export {
  canonicalEventSetHash,
  canonicalEventSetHashHex,
  verifyServedEvents,
  // End-to-end wrapper: fetch on-chain anchor + indexer preimage, verify.
  CompletenessClient,
  CompletenessUnavailableError,
  logsFromMatchedResponse,
} from "./completeness";
export type {
  Log,
  BlockNumber,
  ByteInput,
  CompletenessClientOptions,
  IndexedLog,
  MatchedLogsResponse,
} from "./completeness";

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
 * import { WillowClient, DEVNET_TEST_ACCOUNT } from '@willow-network/sdk';
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
