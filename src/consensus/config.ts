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
 */
export function localConfig(port: number = 26657): ConsensusConfigBuilder {
  return new ConsensusConfigBuilder(`http://localhost:${port}`);
}

/**
 * Create configuration for testnet deployment
 */
export function testnetConfig(rpcUrl: string): ConsensusConfigBuilder {
  return new ConsensusConfigBuilder(rpcUrl)
    .chainId('willow-testnet')
    .requestTimeoutSecs(30)
    .maxRetries(3)
    .retryDelaySecs(2.0);
}

/**
 * Create configuration for mainnet deployment
 */
export function mainnetConfig(rpcUrl: string): ConsensusConfigBuilder {
  return new ConsensusConfigBuilder(rpcUrl)
    .chainId('willow-mainnet')
    .requestTimeoutSecs(60)
    .maxRetries(5)
    .retryDelaySecs(3.0);
}