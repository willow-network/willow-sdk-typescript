/**
 * Consensus Client Configuration Builder
 * 
 * Provides a fluent builder pattern for configuring the consensus client.
 */

import { ConsensusConfig, createConsensusConfig } from './types';

/**
 * Builder for creating consensus client configurations
 */
export class ConsensusConfigBuilder {
  private _consensusRpcUrl: string;
  private _apiUrl?: string;
  private _chainId: string = 'willow-chain';
  private _requestTimeoutSecs: number = 30;
  private _maxRetries: number = 3;
  private _retryDelaySecs: number = 1.0;

  /**
   * Initialize builder with required consensus RPC URL
   */
  constructor(consensusRpcUrl: string) {
    this._consensusRpcUrl = consensusRpcUrl;
  }

  /**
   * Set the REST API URL for account queries (nonce, etc.)
   */
  apiUrl(apiUrl: string): ConsensusConfigBuilder {
    this._apiUrl = apiUrl;
    return this;
  }

  /**
   * Set the blockchain chain ID
   */
  chainId(chainId: string): ConsensusConfigBuilder {
    this._chainId = chainId;
    return this;
  }

  /**
   * Set request timeout in seconds
   */
  requestTimeoutSecs(seconds: number): ConsensusConfigBuilder {
    this._requestTimeoutSecs = seconds;
    return this;
  }

  /**
   * Set maximum retry attempts
   */
  maxRetries(retries: number): ConsensusConfigBuilder {
    this._maxRetries = retries;
    return this;
  }

  /**
   * Set delay between retries in seconds
   */
  retryDelaySecs(seconds: number): ConsensusConfigBuilder {
    this._retryDelaySecs = seconds;
    return this;
  }

  /**
   * Build the final configuration
   */
  build(): ConsensusConfig {
    return createConsensusConfig({
      consensusRpcUrl: this._consensusRpcUrl,
      apiUrl: this._apiUrl,
      chainId: this._chainId,
      requestTimeoutSecs: this._requestTimeoutSecs,
      maxRetries: this._maxRetries,
      retryDelaySecs: this._retryDelaySecs
    });
  }
}

/**
 * Convenience functions for common configurations
 */

/**
 * Create configuration for local testing
 * @param rpcPort - CometBFT RPC port (default: 26657)
 * @param apiPort - REST API port (default: 3031)
 */
export function localConfig(rpcPort: number = 26657, apiPort: number = 3031): ConsensusConfigBuilder {
  return new ConsensusConfigBuilder(`http://localhost:${rpcPort}`)
    .apiUrl(`http://localhost:${apiPort}`);
}

/**
 * Create configuration for testnet deployment
 * @param rpcUrl - CometBFT RPC URL
 * @param apiUrl - REST API URL (optional)
 */
export function testnetConfig(rpcUrl: string, apiUrl?: string): ConsensusConfigBuilder {
  const builder = new ConsensusConfigBuilder(rpcUrl)
    .chainId('willow-testnet')
    .requestTimeoutSecs(30)
    .maxRetries(3)
    .retryDelaySecs(2.0);

  if (apiUrl) {
    builder.apiUrl(apiUrl);
  }

  return builder;
}

/**
 * Create configuration for mainnet deployment
 * @param rpcUrl - CometBFT RPC URL
 * @param apiUrl - REST API URL (optional)
 */
export function mainnetConfig(rpcUrl: string, apiUrl?: string): ConsensusConfigBuilder {
  const builder = new ConsensusConfigBuilder(rpcUrl)
    .chainId('willow-mainnet')
    .requestTimeoutSecs(60)
    .maxRetries(5)
    .retryDelaySecs(3.0);

  if (apiUrl) {
    builder.apiUrl(apiUrl);
  }

  return builder;
}