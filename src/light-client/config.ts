/**
 * Light Client Configuration Builder
 * 
 * Provides a fluent builder pattern for configuring the light client.
 */

import { LightClientConfig, TrustThreshold, createLightClientConfig, createTrustThreshold } from './types';
import type { WillowLogger } from '../internal/logger';

/**
 * Builder for creating light client configurations
 */
export class LightClientConfigBuilder {
  private _chainId: string;
  private _validatorEndpoints: string[] = [];
  private _trustThreshold: TrustThreshold = createTrustThreshold();
  private _trustingPeriodSecs: number = 86400; // 24 hours
  private _maxClockDriftSecs: number = 10;
  private _minValidatorsForConsensus: number = 2;
  private _autoSync: boolean = true;
  private _syncIntervalSecs: number = 300; // 5 minutes
  private _maxRetries: number = 3;
  private _requestTimeoutSecs: number = 30;
  private _logger?: WillowLogger;

  /**
   * Initialize builder with required chain ID
   */
  constructor(chainId: string) {
    this._chainId = chainId;
  }

  /**
   * Set validator RPC endpoints
   */
  validatorEndpoints(endpoints: string[]): LightClientConfigBuilder {
    this._validatorEndpoints = [...endpoints];
    return this;
  }

  /**
   * Add a single validator RPC endpoint
   */
  addValidatorEndpoint(endpoint: string): LightClientConfigBuilder {
    this._validatorEndpoints.push(endpoint);
    return this;
  }

  /**
   * Set trust threshold (e.g., 2/3 for 2/3+ consensus)
   */
  trustThreshold(numerator: number, denominator: number): LightClientConfigBuilder {
    this._trustThreshold = createTrustThreshold(numerator, denominator);
    return this;
  }

  /**
   * Set trusting period in seconds
   */
  trustingPeriodSecs(seconds: number): LightClientConfigBuilder {
    this._trustingPeriodSecs = seconds;
    return this;
  }

  /**
   * Set trusting period in hours
   */
  trustingPeriodHours(hours: number): LightClientConfigBuilder {
    this._trustingPeriodSecs = hours * 3600;
    return this;
  }

  /**
   * Set trusting period in days
   */
  trustingPeriodDays(days: number): LightClientConfigBuilder {
    this._trustingPeriodSecs = days * 86400;
    return this;
  }

  /**
   * Set maximum allowed clock drift in seconds
   */
  maxClockDriftSecs(seconds: number): LightClientConfigBuilder {
    this._maxClockDriftSecs = seconds;
    return this;
  }

  /**
   * Set minimum number of validators required for consensus
   */
  minValidatorsForConsensus(count: number): LightClientConfigBuilder {
    this._minValidatorsForConsensus = count;
    return this;
  }

  /**
   * Enable or disable automatic header synchronization
   */
  autoSync(enabled: boolean): LightClientConfigBuilder {
    this._autoSync = enabled;
    return this;
  }

  /**
   * Set automatic sync interval in seconds
   */
  syncIntervalSecs(seconds: number): LightClientConfigBuilder {
    this._syncIntervalSecs = seconds;
    return this;
  }

  /**
   * Set automatic sync interval in minutes
   */
  syncIntervalMinutes(minutes: number): LightClientConfigBuilder {
    this._syncIntervalSecs = minutes * 60;
    return this;
  }

  /**
   * Set maximum retry attempts for network requests
   */
  maxRetries(retries: number): LightClientConfigBuilder {
    this._maxRetries = retries;
    return this;
  }

  /**
   * Set request timeout in seconds
   */
  requestTimeoutSecs(seconds: number): LightClientConfigBuilder {
    this._requestTimeoutSecs = seconds;
    return this;
  }

  /**
   * Set logger for light client diagnostics (defaults to silent)
   */
  logger(logger: WillowLogger): LightClientConfigBuilder {
    this._logger = logger;
    return this;
  }

  /**
   * Build the final configuration
   */
  build(): LightClientConfig {
    return createLightClientConfig({
      chainId: this._chainId,
      validatorEndpoints: this._validatorEndpoints,
      trustThreshold: this._trustThreshold,
      trustingPeriodSecs: this._trustingPeriodSecs,
      maxClockDriftSecs: this._maxClockDriftSecs,
      minValidatorsForConsensus: this._minValidatorsForConsensus,
      autoSync: this._autoSync,
      syncIntervalSecs: this._syncIntervalSecs,
      maxRetries: this._maxRetries,
      requestTimeoutSecs: this._requestTimeoutSecs,
      logger: this._logger
    });
  }
}

/**
 * Convenience functions for common configurations
 */

/**
 * Create configuration for local testing
 */
export function testConfig(chainId: string = 'test-chain-consensus'): LightClientConfigBuilder {
  return new LightClientConfigBuilder(chainId)
    .validatorEndpoints([
      'http://localhost:26657',
      'http://localhost:26757',
      'http://localhost:26957'
    ])
    .minValidatorsForConsensus(2)
    .trustThreshold(2, 3)
    .trustingPeriodHours(24)
    .autoSync(true);
}

/**
 * Create configuration for mainnet deployment
 */
export function mainnetConfig(chainId: string): LightClientConfigBuilder {
  return new LightClientConfigBuilder(chainId)
    .trustThreshold(2, 3)
    .trustingPeriodDays(14) // 2 weeks
    .maxClockDriftSecs(30)
    .minValidatorsForConsensus(3)
    .autoSync(true)
    .syncIntervalMinutes(10)
    .maxRetries(5)
    .requestTimeoutSecs(60);
}

/**
 * Create configuration optimized for fast synchronization
 */
export function fastSyncConfig(chainId: string): LightClientConfigBuilder {
  return new LightClientConfigBuilder(chainId)
    .trustThreshold(1, 2) // Lower threshold for faster sync
    .trustingPeriodHours(6) // Shorter period
    .autoSync(true)
    .syncIntervalMinutes(1) // Frequent updates
    .maxRetries(3)
    .requestTimeoutSecs(15);
}