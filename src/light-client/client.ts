/**
 * Light Client Implementation
 * 
 * Provides cryptographically secure data verification through CometBFT light client protocol
 * and GroveDB proof verification.
 */

import { LightBlock, LightClientConfig, TrustedHeader, GroveDBQueryProof, VerificationResult, LightClientError, createLightBlock, serializeTrustedHeader, deserializeTrustedHeader, decodeBytes } from './types';
import { HeaderVerifier, ProofVerifier } from './verifier';

/** Decode an app_hash from CometBFT (hex or base64) to a lowercase hex string. */
function appHashToHex(appHash: string): string {
  const bytes = decodeBytes(appHash);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * CometBFT light client with GroveDB proof verification
 * 
 * Provides cryptographically secure data verification without running a full node.
 */
export class LightClient {
  private config: LightClientConfig;
  private headerVerifier: HeaderVerifier;
  private proofVerifier: ProofVerifier;

  // State management
  private trustedHeaders: Map<number, LightBlock> = new Map();
  private latestHeight?: number;
  private syncIntervalId?: number;
  private verifiedHeightRange?: [number, number];

  constructor(config: LightClientConfig) {
    this.config = config;
    this.headerVerifier = new HeaderVerifier(config.chainId, config.trustThreshold!);
    this.proofVerifier = new ProofVerifier();
  }

  /**
   * Start the light client and begin synchronization
   */
  async start(): Promise<void> {
    if (this.config.autoSync) {
      this.syncIntervalId = setInterval(
        () => this.syncToLatest().catch(console.error),
        this.config.syncIntervalSecs! * 1000
      ) as any;
    }

    console.log('Light client started');
  }

  /**
   * Stop the light client and cleanup resources
   */
  async stop(): Promise<void> {
    if (this.syncIntervalId) {
      clearInterval(this.syncIntervalId);
      this.syncIntervalId = undefined;
    }

    console.log('Light client stopped');
  }

  /**
   * Initialize the light client using trust-on-first-use.
   *
   * This fetches the latest block from validators and trusts it as the initial state.
   * All subsequent blocks are verified against this initial trusted state.
   *
   * @important TODO: When mainnet/testnet launches, replace trust-on-first-use
   * with hardcoded checkpoint headers for true trustless initialization.
   * Trust-on-first-use is secure for subsequent operations but trusts the
   * initial block from the connected validators.
   */
  async initializeWithTrustOnFirstUse(): Promise<void> {
    // Fetch the latest block from validators
    // TODO: When mainnet/testnet launches, use hardcoded checkpoint headers
    // instead of trust-on-first-use for true trustless initialization from genesis.
    const latestHeader = await this.fetchHeaderFromValidators(0); // 0 = latest
    if (!latestHeader) {
      throw new LightClientError('Could not fetch latest header from validators for trust-on-first-use initialization');
    }

    // Trust this header as our initial state
    const height = latestHeader.header.height;
    this.trustedHeaders.set(height, latestHeader);
    this.latestHeight = height;
    this.verifiedHeightRange = [height, height];

    console.log(`Initialized with trust-on-first-use at height ${height}`);
  }

  /**
   * Initialize the light client with a trusted header
   *
   * This is the bootstrap process that establishes initial trust.
   * The trusted header should be obtained through a secure channel.
   */
  async initializeWithTrustedHeader(trustedHeader: LightBlock): Promise<void> {
    // Validate the trusted header
    const result = await this.headerVerifier.verifyHeader(
      trustedHeader,
      undefined,
      undefined,
      this.config.maxClockDriftSecs
    );

    if (!result.success) {
      throw new LightClientError(`Trusted header validation failed: ${result.error}`);
    }

    // Store as trusted
    const height = trustedHeader.header.height;
    this.trustedHeaders.set(height, trustedHeader);
    this.latestHeight = height;
    this.verifiedHeightRange = [height, height];

    console.log(`Initialized with trusted header at height ${height}`);
  }

  /**
   * Verify a header against the current trusted state
   */
  async verifyHeader(header: LightBlock): Promise<VerificationResult> {
    if (this.trustedHeaders.size === 0) {
      return {
        success: false,
        error: 'No trusted headers available. Initialize first.',
        height: header.header.height
      };
    }

    // Find the best trusted header for verification
    const trustedHeader = this.findBestTrustedHeader(header.header.height);

    if (!trustedHeader) {
      return {
        success: false,
        error: 'No suitable trusted header found',
        height: header.header.height
      };
    }

    // Verify against trusted state
    const result = await this.headerVerifier.verifyHeader(
      header,
      trustedHeader,
      undefined,
      this.config.maxClockDriftSecs
    );

    // If verification succeeds, add to trusted set
    if (result.success) {
      this.addTrustedHeader(header);
    }

    return result;
  }

  /**
   * Get a verified header by height
   */
  async getHeaderByHeight(height: number): Promise<LightBlock | undefined> {
    // Check if we already have it
    if (this.trustedHeaders.has(height)) {
      return this.trustedHeaders.get(height);
    }

    // Try to fetch and verify it
    try {
      const header = await this.fetchHeaderFromValidators(height);
      if (header) {
        const result = await this.verifyHeader(header);
        if (result.success) {
          return header;
        }
      }
    } catch (error) {
      console.warn(`Failed to fetch header ${height}:`, error);
    }

    return undefined;
  }

  /**
   * Get the latest verified header
   */
  async getLatestHeader(): Promise<LightBlock | undefined> {
    if (this.latestHeight !== undefined) {
      return this.trustedHeaders.get(this.latestHeight);
    }
    return undefined;
  }

  /**
   * Synchronize to the latest blockchain state
   */
  async syncToLatest(): Promise<VerificationResult> {
    try {
      // Get latest height from validators
      const latestHeight = await this.getLatestHeightFromValidators();
      if (latestHeight === undefined) {
        return {
          success: false,
          error: 'Could not determine latest height'
        };
      }

      // If we're already at latest, return success
      if (this.latestHeight !== undefined && latestHeight <= this.latestHeight) {
        return {
          success: true,
          height: this.latestHeight
        };
      }

      // Sync to latest height
      const startHeight = (this.latestHeight || 1) + 1;

      for (let height = startHeight; height <= latestHeight; height++) {
        const header = await this.fetchHeaderFromValidators(height);
        if (!header) {
          return {
            success: false,
            error: `Could not fetch header at height ${height}`,
            height
          };
        }

        const result = await this.verifyHeader(header);
        if (!result.success) {
          return result;
        }
      }

      return {
        success: true,
        height: latestHeight
      };

    } catch (error) {
      return {
        success: false,
        error: `Sync failed: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }

  /**
   * Verify a GroveDB query proof against verified headers
   */
  async verifyQueryProof(
    proof: GroveDBQueryProof,
    height?: number
  ): Promise<VerificationResult> {
    const verifyHeight = height || proof.height;

    // Get trusted header for the height
    const trustedHeader = await this.getHeaderByHeight(verifyHeight);
    if (!trustedHeader) {
      return {
        success: false,
        error: `No verified header available for height ${verifyHeight}`,
        height: verifyHeight
      };
    }

    // Verify the proof against the trusted app hash
    return this.proofVerifier.verifyQueryProof(
      proof,
      trustedHeader.header.appHash
    );
  }

  /**
   * Export trusted headers for state persistence
   */
  async exportTrustedState(): Promise<TrustedHeader[]> {
    const trustedState: TrustedHeader[] = [];

    for (const [height, lightBlock] of this.trustedHeaders) {
      const trustedHeader: TrustedHeader = {
        header: lightBlock.header,
        validatorsHash: lightBlock.header.validatorsHash,
        nextValidatorsHash: lightBlock.header.nextValidatorsHash,
        trustedAt: new Date(),
        provider: lightBlock.provider
      };
      trustedState.push(trustedHeader);
    }

    return trustedState;
  }

  /**
   * Import trusted headers from exported state
   */
  async importTrustedState(headers: TrustedHeader[]): Promise<void> {
    for (const trustedHeader of headers) {
      // Convert TrustedHeader back to LightBlock (minimal)
      const lightBlock: LightBlock = {
        header: trustedHeader.header,
        commit: {} as any, // Not needed for verification
        validators: { validators: [] }, // Not needed for verification
        provider: trustedHeader.provider
      };

      const height = trustedHeader.header.height;
      this.trustedHeaders.set(height, lightBlock);

      if (this.latestHeight === undefined || height > this.latestHeight) {
        this.latestHeight = height;
      }
    }

    // Update verified range
    if (this.trustedHeaders.size > 0) {
      const heights = Array.from(this.trustedHeaders.keys());
      this.verifiedHeightRange = [Math.min(...heights), Math.max(...heights)];
    }

    console.log(`Imported ${headers.length} trusted headers`);
  }

  /**
   * Get the verified root hash (app_hash) from the latest trusted header.
   *
   * This is the cryptographically verified root hash that proofs should be
   * verified against for trustless data verification.
   */
  async getVerifiedRootHash(): Promise<string> {
    // Use /block_results for the latest app_hash — same as getVerifiedRootHashAtHeight
    // but without specifying a height (gets the latest).
    return this.getVerifiedRootHashAtHeight(0);
  }

  /**
   * Get the verified root hash (app_hash) at a specific block height.
   *
   * In CometBFT, block H's FinalizeBlock produces an app_hash that represents
   * state AFTER H. That hash is then committed into block H+1's header as
   * `header.app_hash`. So:
   *
   *   - `block H+1.header.app_hash` = state after H (what we want for height H)
   *   - `status.latest_app_hash` = state after the latest committed block
   *
   * We used to use `/block_results` here, but CometBFT 0.38+ does NOT populate
   * `app_hash` in that response — it's intentionally empty. The canonical
   * source is the next block's header, with `/status` as the fallback when
   * height is the very latest (H+1 doesn't exist yet).
   *
   * When `height <= 0`, we fetch the latest app_hash via `/status`.
   */
  async getVerifiedRootHashAtHeight(height: number): Promise<string> {
    for (const endpoint of this.config.validatorEndpoints) {
      try {
        const hash = await this.fetchAppHashForHeight(endpoint, height);
        if (hash) return hash;
      } catch {
        continue;
      }
    }
    throw new LightClientError(`Could not fetch app_hash for height ${height} from any endpoint`);
  }

  /**
   * Fetches `app_hash` for the state AFTER the given block height.
   *
   * Strategy:
   *   - If height <= 0: use `/status.latest_app_hash`.
   *   - Otherwise: try `/block?height=height+1` for `header.app_hash`.
   *     If H+1 doesn't exist yet, poll `/status` — when the chain catches
   *     up (latest >= H+1) retry the block fetch; if chain is exactly at H,
   *     use `status.latest_app_hash` directly.
   *
   * Retries for up to `requestTimeoutSecs` seconds to handle the common
   * race where the proof was generated at the current latest height but
   * H+1 hasn't been produced yet by the time we query.
   */
  private async fetchAppHashForHeight(
    endpoint: string,
    height: number
  ): Promise<string | null> {
    const timeoutMs = this.config.requestTimeoutSecs! * 1000;

    if (height <= 0) {
      return this.fetchLatestAppHash(endpoint, timeoutMs);
    }

    const deadline = Date.now() + timeoutMs;
    const perAttemptTimeoutMs = Math.max(1000, Math.floor(timeoutMs / 4));

    while (Date.now() < deadline) {
      // Try next block's header first.
      const fromNextBlock = await this.tryFetchBlockHeaderAppHash(
        endpoint,
        height + 1,
        perAttemptTimeoutMs
      );
      if (fromNextBlock) return fromNextBlock;

      // Block H+1 not available. Check where the chain is.
      const status = await this.fetchStatus(endpoint, perAttemptTimeoutMs);
      if (!status) {
        return null;
      }
      if (status.latestHeight === height) {
        // Chain is exactly at H — status.latest_app_hash is state after H.
        return status.latestAppHash;
      }
      if (status.latestHeight > height) {
        // Chain advanced past H but /block?height=H+1 still didn't return.
        // Transient — brief delay then retry.
        await new Promise(resolve => setTimeout(resolve, 200));
        continue;
      }
      // Chain is behind H — caller asked for a future block. Wait briefly.
      await new Promise(resolve => setTimeout(resolve, 500));
    }

    return null;
  }

  private async tryFetchBlockHeaderAppHash(
    endpoint: string,
    height: number,
    timeoutMs: number
  ): Promise<string | null> {
    try {
      const response = await fetch(`${endpoint}/block?height=${height}`, {
        method: 'GET',
        signal: AbortSignal.timeout(timeoutMs)
      });
      if (!response.ok) return null;
      const data = await response.json() as {
        result?: { block?: { header?: { app_hash?: string } } }
      };
      const appHash = data.result?.block?.header?.app_hash;
      return appHash ? appHashToHex(appHash) : null;
    } catch {
      return null;
    }
  }

  private async fetchLatestAppHash(endpoint: string, timeoutMs: number): Promise<string | null> {
    const status = await this.fetchStatus(endpoint, timeoutMs);
    return status?.latestAppHash ?? null;
  }

  private async fetchStatus(
    endpoint: string,
    timeoutMs: number
  ): Promise<{ latestHeight: number; latestAppHash: string } | null> {
    const response = await fetch(`${endpoint}/status`, {
      method: 'GET',
      signal: AbortSignal.timeout(timeoutMs)
    });
    if (!response.ok) return null;
    const data = await response.json() as {
      result?: { sync_info?: { latest_block_height?: string; latest_app_hash?: string } }
    };
    const info = data.result?.sync_info;
    if (!info?.latest_app_hash || !info.latest_block_height) return null;
    return {
      latestHeight: parseInt(info.latest_block_height, 10),
      latestAppHash: appHashToHex(info.latest_app_hash)
    };
  }

  /**
   * Get the latest verified height
   */
  async getLatestHeight(): Promise<number | undefined> {
    return this.latestHeight;
  }

  /**
   * Get the range of verified heights (min, max)
   */
  async getVerifiedHeightRange(): Promise<[number, number] | undefined> {
    return this.verifiedHeightRange;
  }

  /**
   * Check if a specific height has been verified
   */
  async isHeightVerified(height: number): Promise<boolean> {
    return this.trustedHeaders.has(height);
  }

  // Private methods

  /**
   * Find the best trusted header for verifying target height
   */
  private findBestTrustedHeader(targetHeight: number): LightBlock | undefined {
    if (this.trustedHeaders.size === 0) {
      return undefined;
    }

    // Find the highest trusted header below target height
    let bestHeight = -1;
    for (const height of this.trustedHeaders.keys()) {
      if (height < targetHeight && height > bestHeight) {
        bestHeight = height;
      }
    }

    if (bestHeight !== -1) {
      return this.trustedHeaders.get(bestHeight);
    }

    // If target is lower than all trusted headers, use the lowest
    const heights = Array.from(this.trustedHeaders.keys());
    const minHeight = Math.min(...heights);
    return this.trustedHeaders.get(minHeight);
  }

  /**
   * Add a verified header to the trusted set
   */
  private addTrustedHeader(header: LightBlock): void {
    const height = header.header.height;
    this.trustedHeaders.set(height, header);

    if (this.latestHeight === undefined || height > this.latestHeight) {
      this.latestHeight = height;
    }

    // Update verified range
    if (this.verifiedHeightRange === undefined) {
      this.verifiedHeightRange = [height, height];
    } else {
      const [minHeight, maxHeight] = this.verifiedHeightRange;
      this.verifiedHeightRange = [
        Math.min(minHeight, height),
        Math.max(maxHeight, height)
      ];
    }

    console.debug(`Added trusted header at height ${height}`);
  }

  /**
   * Fetch header from validators with consensus verification
   */
  private async fetchHeaderFromValidators(height: number): Promise<LightBlock | undefined> {
    const headers: Array<[string, LightBlock]> = [];

    // Query multiple validators
    for (const endpoint of this.config.validatorEndpoints) {
      try {
        const header = await this.fetchHeaderFromEndpoint(endpoint, height);
        if (header) {
          headers.push([endpoint, header]);
        }
      } catch (error) {
        console.debug(`Failed to fetch header from ${endpoint}:`, error);
      }
    }

    if (headers.length < this.config.minValidatorsForConsensus!) {
      console.warn(`Only ${headers.length} validators responded, need ${this.config.minValidatorsForConsensus}`);
      return undefined;
    }

    // Find consensus header (majority agreement)
    return this.findConsensusHeader(headers);
  }

  /**
   * Fetch header from a specific validator endpoint
   */
  private async fetchHeaderFromEndpoint(endpoint: string, height: number): Promise<LightBlock | undefined> {
    const heightParam = height > 0 ? `?height=${height}` : '';
    const timeout = this.config.requestTimeoutSecs! * 1000;

    // Fetch block
    const blockRes = await fetch(`${endpoint}/block${heightParam}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(timeout)
    });
    if (!blockRes.ok) throw new Error(`HTTP ${blockRes.status}`);
    const blockJson = await blockRes.json() as { result?: { block?: any; block_id?: any } };
    if (!blockJson.result?.block) throw new Error('Invalid block response');

    const blockData = blockJson.result.block;

    // Fetch validators at the same height
    const blockHeight = blockData.header?.height ?? '';
    const valParam = blockHeight ? `?height=${blockHeight}` : '';
    try {
      const valRes = await fetch(`${endpoint}/validators${valParam}`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(timeout)
      });
      if (valRes.ok) {
        const valJson = await valRes.json() as { result?: any };
        if (valJson.result) {
          blockData.validators = valJson.result;
        }
      }
    } catch {
      // Validators fetch is best-effort — createLightBlock handles missing validators
    }

    return createLightBlock(blockData, endpoint);
  }

  /**
   * Get latest height from validators
   */
  private async getLatestHeightFromValidators(): Promise<number | undefined> {
    const heights: number[] = [];

    for (const endpoint of this.config.validatorEndpoints) {
      try {
        const header = await this.fetchHeaderFromEndpoint(endpoint, 0); // 0 = latest
        if (header) {
          heights.push(header.header.height);
        }
      } catch (error) {
        console.debug(`Failed to get latest height from ${endpoint}:`, error);
      }
    }

    if (heights.length === 0) {
      return undefined;
    }

    // Return the most common height (consensus)
    const heightCounts = new Map<number, number>();
    for (const height of heights) {
      heightCounts.set(height, (heightCounts.get(height) || 0) + 1);
    }

    let mostCommonHeight = 0;
    let maxCount = 0;
    for (const [height, count] of heightCounts) {
      if (count > maxCount) {
        maxCount = count;
        mostCommonHeight = height;
      }
    }

    if (maxCount >= this.config.minValidatorsForConsensus!) {
      return mostCommonHeight;
    }

    return undefined;
  }

  /**
   * Find consensus header from multiple validator responses
   */
  private findConsensusHeader(headers: Array<[string, LightBlock]>): LightBlock | undefined {
    // Group by header hash (simplified - should use full header comparison)
    const headerGroups = new Map<string, Array<[string, LightBlock]>>();

    for (const [endpoint, header] of headers) {
      // Use app_hash as identifier (could use full header hash)
      const key = Array.from(header.header.appHash).map(b => b.toString(16).padStart(2, '0')).join('');
      
      if (!headerGroups.has(key)) {
        headerGroups.set(key, []);
      }
      headerGroups.get(key)!.push([endpoint, header]);
    }

    // Find the group with most validators
    let largestGroup: Array<[string, LightBlock]> = [];
    for (const group of headerGroups.values()) {
      if (group.length > largestGroup.length) {
        largestGroup = group;
      }
    }

    if (largestGroup.length >= this.config.minValidatorsForConsensus!) {
      // Return the first header from the consensus group
      return largestGroup[0][1];
    }

    return undefined;
  }
}