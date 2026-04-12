/**
 * Consensus Client Implementation
 * 
 * Provides direct transaction broadcasting to CometBFT consensus layer.
 */

import { ConsensusConfig, BroadcastResult, TransactionStatus, ConsensusError, RegisterDidTx, RegisterSubgroveTx, SubgroveMode, RetentionWindow, TransferTx, DataStoreTx, StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx, Transaction, createTransactionWrapper, createSignMessage, createBroadcastResult, stringToBase64 } from './types';

/**
 * CometBFT consensus client for direct transaction broadcasting
 * 
 * Enables full-featured blockchain interactions without relying on data nodes.
 */
export class ConsensusClient {
  private config: ConsensusConfig;
  private nonceCache: Map<string, number> = new Map();

  constructor(config: ConsensusConfig) {
    this.config = {
      ...config,
      requestTimeoutSecs: config.requestTimeoutSecs ?? 30,
      maxRetries: config.maxRetries ?? 3,
      retryDelaySecs: config.retryDelaySecs ?? 1,
    };
  }

  /**
   * Register a DID on the blockchain
   */
  async registerDid(
    didDocument: any,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    // Create transaction
    const tx: RegisterDidTx = {
      didDocument,
      signature: '', // Will be filled by signing
      publicKeyId,
      nonce: await this.getNextNonce(didDocument.id || '')
    };

    // Sign and broadcast
    return this.signAndBroadcast('RegisterDid', tx, privateKey, signFunction);
  }

  /**
   * Register a subgrove (dataset) on the blockchain
   */
  async registerSubgrove(
    subgroveId: string,
    schema: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string,
    mode?: SubgroveMode,
    retentionWindow?: RetentionWindow,
    initialFunding?: string
  ): Promise<BroadcastResult> {
    const tx: RegisterSubgroveTx = {
      subgroveId,
      schema,
      ownerDid,
      mode,
      retention_window: retentionWindow,
      initialFunding,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('RegisterSubgrove', tx, privateKey, signFunction);
  }

  /**
   * Transfer tokens between DIDs
   */
  async transfer(
    fromDid: string,
    toDid: string,
    amount: number,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string,
    memo?: string
  ): Promise<BroadcastResult> {
    const tx: TransferTx = {
      fromDid,
      toDid,
      amount,
      memo,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(fromDid)
    };

    return this.signAndBroadcast('Transfer', tx, privateKey, signFunction);
  }

  /**
   * Store data on the blockchain
   */
  async storeData(
    subgroveId: string,
    key: string,
    data: any,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    const tx: DataStoreTx = {
      subgroveId,
      key,
      data: JSON.stringify(data),
      ownerDid,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DataStore', tx, privateKey, signFunction);
  }

  /**
   * Store a file manifest on the blockchain
   */
  async storeFileManifest(
    subgroveId: string,
    fileKey: string,
    filename: string,
    contentType: string,
    totalSize: number,
    contentHash: string,
    chunkCount: number,
    chunkSize: number,
    chunkMerkleRoot: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    const tx: StoreFileManifestTx = {
      subgroveId,
      fileKey,
      filename,
      contentType,
      totalSize,
      contentHash,
      chunkCount,
      chunkSize,
      chunkMerkleRoot,
      ownerDid,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('StoreFileManifest', tx, privateKey, signFunction);
  }

  /**
   * Delete a file manifest from the blockchain
   */
  async deleteFileManifest(
    subgroveId: string,
    fileKey: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    const tx: DeleteFileManifestTx = {
      subgroveId,
      fileKey,
      ownerDid,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DeleteFileManifest', tx, privateKey, signFunction);
  }

  /**
   * Deregister (delete) a subgrove. Remaining funding is refunded to the owner.
   */
  async deregisterSubgrove(
    subgroveId: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    const tx: DeregisterSubgroveTx = {
      subgroveId,
      ownerDid,
      signature: '',
      publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DeregisterSubgrove', tx, privateKey, signFunction);
  }

  /**
   * Get the status of a transaction
   */
  async getTransactionStatus(txHash: string): Promise<TransactionStatus> {
    try {
      // Query transaction from CometBFT
      const result = await this.queryTransaction(txHash);

      if (!result) {
        return TransactionStatus.NOT_FOUND;
      }

      // Check if transaction succeeded
      const code = result.tx_result?.code || 0;
      return code === 0 ? TransactionStatus.SUCCESS : TransactionStatus.FAILED;

    } catch (error) {
      console.warn('Failed to get transaction status:', error);
      return TransactionStatus.NOT_FOUND;
    }
  }

  /**
   * Wait for a transaction to be confirmed
   */
  async waitForTransaction(
    txHash: string,
    timeoutSecs: number = 60,
    pollInterval: number = 2.0
  ): Promise<TransactionStatus> {
    const startTime = Date.now();
    const timeoutMs = timeoutSecs * 1000;

    while (Date.now() - startTime < timeoutMs) {
      const status = await this.getTransactionStatus(txHash);

      if (status === TransactionStatus.SUCCESS || status === TransactionStatus.FAILED) {
        return status;
      }

      await this.sleep(pollInterval * 1000);
    }

    return TransactionStatus.PENDING;
  }

  /**
   * Get the blockchain chain ID
   */
  async getChainId(): Promise<string> {
    try {
      const result = await this.rpcRequest('status', {});
      return result.node_info?.network || this.config.chainId!;
    } catch (error) {
      console.warn('Failed to get chain ID:', error);
      return this.config.chainId!;
    }
  }

  /**
   * Get the latest blockchain height
   */
  async getLatestHeight(): Promise<number | undefined> {
    try {
      const result = await this.rpcRequest('status', {});
      return parseInt(result.sync_info?.latest_block_height || '0');
    } catch (error) {
      console.warn('Failed to get latest height:', error);
      return undefined;
    }
  }

  // Private methods

  /**
   * Sign a transaction and broadcast it
   */
  private async signAndBroadcast(
    txType: string,
    transaction: Transaction,
    privateKey: string,
    signFunction: (message: string, privateKey: string) => string
  ): Promise<BroadcastResult> {
    // Create canonical message for signing
    const signMessageText = createSignMessage(txType, transaction);

    // Sign the message
    const signatureHex = signFunction(signMessageText, privateKey);

    // Update transaction with signature
    (transaction as any).signature = signatureHex;

    // Create transaction wrapper
    const txWrapper = createTransactionWrapper(txType, transaction);

    // Broadcast transaction
    return this.broadcastTransaction(txWrapper);
  }

  /**
   * Broadcast a transaction to CometBFT
   */
  private async broadcastTransaction(transaction: any): Promise<BroadcastResult> {
    // Serialize and encode transaction
    const txJson = JSON.stringify(transaction);
    const txBase64 = stringToBase64(txJson);

    // Broadcast via JSON-RPC
    const response = await this.rpcRequest('broadcast_tx_sync', { tx: txBase64 });
    return createBroadcastResult({ result: response });
  }

  /**
   * Make a JSON-RPC request to CometBFT
   */
  private async rpcRequest(method: string, params: any): Promise<any> {
    const rpcRequest = {
      jsonrpc: '2.0',
      id: 1,
      method,
      params
    };

    for (let attempt = 0; attempt <= this.config.maxRetries!; attempt++) {
      try {
        const response = await fetch(this.config.consensusRpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(rpcRequest),
          signal: AbortSignal.timeout(this.config.requestTimeoutSecs! * 1000)
        });

        if (response.ok) {
          const data = await response.json() as { error?: any; result?: any };

          if (data.error) {
            throw new ConsensusError(`RPC error: ${JSON.stringify(data.error)}`);
          }

          return data.result || {};
        } else {
          const errorText = await response.text();
          throw new ConsensusError(`HTTP ${response.status}: ${errorText}`);
        }

      } catch (error) {
        if (attempt === this.config.maxRetries) {
          throw new ConsensusError(
            `RPC request failed after ${this.config.maxRetries! + 1} attempts: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        }

        console.warn(`RPC attempt ${attempt + 1} failed:`, error);
        await this.sleep(this.config.retryDelaySecs! * 1000 * (attempt + 1));
      }
    }

    throw new ConsensusError('Unexpected end of retry loop');
  }

  /**
   * Query a transaction by hash
   */
  private async queryTransaction(txHash: string): Promise<any | undefined> {
    try {
      const result = await this.rpcRequest('tx', { hash: txHash, prove: false });
      return result;
    } catch (error) {
      return undefined;
    }
  }

  /**
   * Get the next nonce for a DID
   *
   * Fetches the current nonce from the blockchain and returns the next value.
   * Falls back to in-memory cache if API is unavailable.
   */
  private async getNextNonce(did: string): Promise<number> {
    try {
      const currentNonce = await this.getAccountNonce(did);
      const nextNonce = currentNonce + 1;
      this.nonceCache.set(did, nextNonce);
      return nextNonce;
    } catch (error) {
      // Fall back to cache if API unavailable
      console.warn('Failed to fetch nonce from API, using cache:', error);
      const currentNonce = this.nonceCache.get(did) || 0;
      const nextNonce = currentNonce + 1;
      this.nonceCache.set(did, nextNonce);
      return nextNonce;
    }
  }

  /**
   * Get the current nonce for an account from the blockchain
   */
  private async getAccountNonce(did: string): Promise<number> {
    if (!this.config.apiUrl) {
      // No API URL configured, use cache
      return this.nonceCache.get(did) || 0;
    }

    const response = await fetch(
      `${this.config.apiUrl}/account/${encodeURIComponent(did)}/nonce`,
      {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(this.config.requestTimeoutSecs! * 1000)
      }
    );

    if (!response.ok) {
      throw new ConsensusError(`Failed to fetch nonce: HTTP ${response.status}`);
    }

    const data = await response.json() as { success: boolean; data?: { nonce: number }; error?: string };

    if (!data.success || data.data === undefined) {
      throw new ConsensusError(data.error || 'Failed to fetch nonce');
    }

    return data.data.nonce;
  }

  /**
   * Utility: Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}