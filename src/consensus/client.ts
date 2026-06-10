/**
 * Consensus Client Implementation
 *
 * Provides direct transaction broadcasting to CometBFT consensus layer.
 */

import { ConsensusConfig, BroadcastResult, TransactionStatus, ConsensusError, RegisterDidTx, RegisterSubgroveTx, RegisterSubgroveOptions, SubgroveMode, RetentionWindow, Signer, SignFunction, StoreFileManifestFields, TransferTx, DataStoreTx, StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx, SubmitAnchorTx, Transaction, createTransactionWrapper, createSignMessage } from './types';
import { canonicalizeAnchorBody, computeAnchorMerkleRoot, sha256Hex } from './anchor-canonical';
import { submitTxToApi } from '../internal/tx';
import { signEd25519 } from '../auth';
import { WillowLogger, silentLogger } from '../internal/logger';

/** Misconfiguration (no consensusRpcUrl) must surface, never degrade to a fallback. */
function isRpcUrlMissingError(error: unknown): boolean {
  return error instanceof ConsensusError && error.code === 'CONSENSUS_RPC_URL_REQUIRED';
}

/** Normalize a Signer object or deprecated positional tail into resolved key material. */
function resolveSigner(
  signerOrPrivateKey: Signer | string,
  publicKeyId?: string,
  signFunction?: SignFunction,
): Required<Signer> {
  if (typeof signerOrPrivateKey === 'string') {
    return {
      privateKey: signerOrPrivateKey,
      publicKeyId: publicKeyId!,
      signFunction: signFunction ?? signEd25519,
    };
  }
  return {
    privateKey: signerOrPrivateKey.privateKey,
    publicKeyId: signerOrPrivateKey.publicKeyId,
    signFunction: signerOrPrivateKey.signFunction ?? signEd25519,
  };
}

/**
 * CometBFT consensus client for direct transaction broadcasting
 *
 * Enables full-featured blockchain interactions without relying on data nodes.
 */
export class ConsensusClient {
  private config: ConsensusConfig;
  private nonceCache: Map<string, number> = new Map();
  private logger: WillowLogger;

  constructor(config: ConsensusConfig) {
    this.config = {
      ...config,
      requestTimeoutSecs: config.requestTimeoutSecs ?? 30,
      maxRetries: config.maxRetries ?? 3,
      retryDelaySecs: config.retryDelaySecs ?? 1,
    };
    this.logger = config.logger ?? silentLogger;
  }

  /**
   * Register a DID on the blockchain
   */
  async registerDid(didDocument: any, signer: Signer): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async registerDid(
    didDocument: any,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async registerDid(
    didDocument: any,
    signerOrPrivateKey: Signer | string,
    publicKeyId?: string,
    signFunction?: SignFunction
  ): Promise<BroadcastResult> {
    const signer = resolveSigner(signerOrPrivateKey, publicKeyId, signFunction);
    const tx: RegisterDidTx = {
      didDocument,
      signature: '', // Will be filled by signing
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(didDocument.id || '')
    };

    return this.signAndBroadcast('RegisterDid', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Register a subgrove on the blockchain
   */
  async registerSubgrove(
    subgroveId: string,
    schema: string,
    ownerDid: string,
    signer: Signer,
    options?: RegisterSubgroveOptions
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async registerSubgrove(
    subgroveId: string,
    schema: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction,
    mode?: SubgroveMode,
    retentionWindow?: RetentionWindow,
    initialFunding?: string
  ): Promise<BroadcastResult>;
  async registerSubgrove(
    subgroveId: string,
    schema: string,
    ownerDid: string,
    signerOrPrivateKey: Signer | string,
    publicKeyIdOrOptions?: string | RegisterSubgroveOptions,
    signFunction?: SignFunction,
    mode?: SubgroveMode,
    retentionWindow?: RetentionWindow,
    initialFunding?: string
  ): Promise<BroadcastResult> {
    const positional = typeof signerOrPrivateKey === 'string';
    const signer = resolveSigner(
      signerOrPrivateKey,
      positional ? (publicKeyIdOrOptions as string) : undefined,
      signFunction,
    );
    const options: RegisterSubgroveOptions = positional
      ? { mode, retentionWindow, initialFunding }
      : (publicKeyIdOrOptions as RegisterSubgroveOptions | undefined) ?? {};

    const tx: RegisterSubgroveTx = {
      subgroveId,
      schema,
      ownerDid,
      mode: options.mode,
      retention_window: options.retentionWindow,
      initialFunding: options.initialFunding,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('RegisterSubgrove', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Transfer tokens between DIDs
   */
  async transfer(
    fromDid: string,
    toDid: string,
    amount: number,
    signer: Signer,
    memo?: string
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async transfer(
    fromDid: string,
    toDid: string,
    amount: number,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction,
    memo?: string
  ): Promise<BroadcastResult>;
  async transfer(
    fromDid: string,
    toDid: string,
    amount: number,
    signerOrPrivateKey: Signer | string,
    publicKeyIdOrMemo?: string,
    signFunction?: SignFunction,
    memo?: string
  ): Promise<BroadcastResult> {
    const positional = typeof signerOrPrivateKey === 'string';
    const signer = resolveSigner(
      signerOrPrivateKey,
      positional ? publicKeyIdOrMemo : undefined,
      signFunction,
    );
    const txMemo = positional ? memo : publicKeyIdOrMemo;

    const tx: TransferTx = {
      fromDid,
      toDid,
      amount,
      memo: txMemo,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(fromDid)
    };

    return this.signAndBroadcast('Transfer', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Store data on the blockchain
   */
  async storeData(
    subgroveId: string,
    key: string,
    data: any,
    ownerDid: string,
    signer: Signer
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async storeData(
    subgroveId: string,
    key: string,
    data: any,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async storeData(
    subgroveId: string,
    key: string,
    data: any,
    ownerDid: string,
    signerOrPrivateKey: Signer | string,
    publicKeyId?: string,
    signFunction?: SignFunction
  ): Promise<BroadcastResult> {
    const signer = resolveSigner(signerOrPrivateKey, publicKeyId, signFunction);
    const tx: DataStoreTx = {
      subgroveId,
      key,
      data: JSON.stringify(data),
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DataStore', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Store a file manifest on the blockchain
   */
  async storeFileManifest(
    manifest: StoreFileManifestFields,
    signer: Signer
  ): Promise<BroadcastResult>;
  /** @deprecated Pass {@link StoreFileManifestFields} and a {@link Signer} instead of 13 positional arguments. */
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
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async storeFileManifest(
    manifestOrSubgroveId: StoreFileManifestFields | string,
    signerOrFileKey: Signer | string,
    filename?: string,
    contentType?: string,
    totalSize?: number,
    contentHash?: string,
    chunkCount?: number,
    chunkSize?: number,
    chunkMerkleRoot?: string,
    ownerDid?: string,
    privateKey?: string,
    publicKeyId?: string,
    signFunction?: SignFunction
  ): Promise<BroadcastResult> {
    let fields: StoreFileManifestFields;
    let signer: Required<Signer>;
    if (typeof manifestOrSubgroveId === 'string') {
      fields = {
        subgroveId: manifestOrSubgroveId,
        fileKey: signerOrFileKey as string,
        filename: filename!,
        contentType: contentType!,
        totalSize: totalSize!,
        contentHash: contentHash!,
        chunkCount: chunkCount!,
        chunkSize: chunkSize!,
        chunkMerkleRoot: chunkMerkleRoot!,
        ownerDid: ownerDid!,
      };
      signer = resolveSigner(privateKey!, publicKeyId, signFunction);
    } else {
      fields = manifestOrSubgroveId;
      signer = resolveSigner(signerOrFileKey as Signer);
    }

    const tx: StoreFileManifestTx = {
      ...fields,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(fields.ownerDid)
    };

    return this.signAndBroadcast('StoreFileManifest', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Delete a file manifest from the blockchain
   */
  async deleteFileManifest(
    subgroveId: string,
    fileKey: string,
    ownerDid: string,
    signer: Signer
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async deleteFileManifest(
    subgroveId: string,
    fileKey: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async deleteFileManifest(
    subgroveId: string,
    fileKey: string,
    ownerDid: string,
    signerOrPrivateKey: Signer | string,
    publicKeyId?: string,
    signFunction?: SignFunction
  ): Promise<BroadcastResult> {
    const signer = resolveSigner(signerOrPrivateKey, publicKeyId, signFunction);
    const tx: DeleteFileManifestTx = {
      subgroveId,
      fileKey,
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DeleteFileManifest', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Deregister (delete) a subgrove. Remaining funding is refunded to the owner.
   */
  async deregisterSubgrove(
    subgroveId: string,
    ownerDid: string,
    signer: Signer
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async deregisterSubgrove(
    subgroveId: string,
    ownerDid: string,
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async deregisterSubgrove(
    subgroveId: string,
    ownerDid: string,
    signerOrPrivateKey: Signer | string,
    publicKeyId?: string,
    signFunction?: SignFunction
  ): Promise<BroadcastResult> {
    const signer = resolveSigner(signerOrPrivateKey, publicKeyId, signFunction);
    const tx: DeregisterSubgroveTx = {
      subgroveId,
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(ownerDid)
    };

    return this.signAndBroadcast('DeregisterSubgrove', tx, signer.privateKey, signer.signFunction);
  }

  /**
   * Submit an MCP receipt-batch anchor. The chain enforces per-DID
   * monotonicity (genesis-once, sequence contiguity, prev_anchor_hash
   * linkage) and recomputes both `anchorHash` and `merkleRoot` from
   * the canonical body — so the values must match byte-for-byte.
   * `merkleRoot` is computed automatically if omitted; `anchorHash`
   * is always computed here.
   */
  async submitAnchor(
    fields: {
      did: string;
      anchorId: string;
      sequenceRange: [number, number];
      receiptHashes: string[];
      timestamp: string;
      previousAnchorHash: string;
      isGenesis: boolean;
      merkleRoot?: string;
    },
    signer: Signer
  ): Promise<BroadcastResult>;
  /** @deprecated Pass a {@link Signer} options object instead of positional key material. */
  async submitAnchor(
    fields: {
      did: string;
      anchorId: string;
      sequenceRange: [number, number];
      receiptHashes: string[];
      timestamp: string;
      previousAnchorHash: string;
      isGenesis: boolean;
      merkleRoot?: string;
    },
    privateKey: string,
    publicKeyId: string,
    signFunction: SignFunction
  ): Promise<BroadcastResult>;
  async submitAnchor(
    fields: {
      did: string;
      anchorId: string;
      sequenceRange: [number, number];
      receiptHashes: string[];
      timestamp: string;
      previousAnchorHash: string;
      isGenesis: boolean;
      merkleRoot?: string;
    },
    signerOrPrivateKey: Signer | string,
    publicKeyId?: string,
    signFunction?: SignFunction,
  ): Promise<BroadcastResult> {
    const signer = resolveSigner(signerOrPrivateKey, publicKeyId, signFunction);
    const count = fields.receiptHashes.length;
    const merkleRoot = fields.merkleRoot ?? computeAnchorMerkleRoot(fields.receiptHashes);

    const canonical = canonicalizeAnchorBody({
      anchor_id: fields.anchorId,
      count,
      did: fields.did,
      is_genesis: fields.isGenesis,
      merkle_root: merkleRoot,
      previous_anchor_hash: fields.previousAnchorHash,
      receipt_hashes: fields.receiptHashes,
      sequence_range: fields.sequenceRange,
      timestamp: fields.timestamp,
    });
    const anchorHash = sha256Hex(canonical);

    const tx: SubmitAnchorTx = {
      did: fields.did,
      anchorId: fields.anchorId,
      sequenceRange: fields.sequenceRange,
      merkleRoot,
      count,
      receiptHashes: fields.receiptHashes,
      timestamp: fields.timestamp,
      previousAnchorHash: fields.previousAnchorHash,
      anchorHash,
      isGenesis: fields.isGenesis,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce: await this.getNextNonce(fields.did),
    };

    return this.signAndBroadcast('SubmitAnchor', tx, signer.privateKey, signer.signFunction);
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
      if (isRpcUrlMissingError(error)) throw error;
      this.logger.warn('Failed to get transaction status:', error);
      return TransactionStatus.NOT_FOUND;
    }
  }

  /**
   * Wait for a transaction to be confirmed.
   *
   * Resolves with SUCCESS or FAILED once the transaction lands in a block.
   * Throws a ConsensusError with code `TX_CONFIRM_TIMEOUT` if the
   * transaction is still unconfirmed when the timeout elapses.
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

    throw new ConsensusError(
      `Transaction ${txHash} not confirmed within ${timeoutSecs}s`,
      'TX_CONFIRM_TIMEOUT'
    );
  }

  /**
   * Get the blockchain chain ID
   */
  async getChainId(): Promise<string> {
    try {
      const result = await this.rpcRequest('status', {});
      return result.node_info?.network || this.config.chainId!;
    } catch (error) {
      if (isRpcUrlMissingError(error)) throw error;
      this.logger.warn('Failed to get chain ID:', error);
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
      if (isRpcUrlMissingError(error)) throw error;
      this.logger.warn('Failed to get latest height:', error);
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
    signFunction: SignFunction
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
   * Broadcast a transaction to Willow consensus.
   *
   * Goes through the API server's `POST /tx/submit` endpoint: the server
   * accepts the JSON-encoded Transaction, bincode-encodes it, and forwards
   * to CometBFT's `broadcast_tx_sync`. The chain's on-the-wire format is
   * bincode — letting the API server handle the conversion keeps the SDK on
   * JSON without implementing a bincode encoder per language.
   */
  private async broadcastTransaction(transaction: any): Promise<BroadcastResult> {
    if (!this.config.apiUrl) {
      throw new ConsensusError(
        'apiUrl is required for transaction submission. Set it in the SDK config.',
        'API_URL_REQUIRED'
      );
    }

    for (let attempt = 0; attempt <= this.config.maxRetries!; attempt++) {
      try {
        return await submitTxToApi(this.config.apiUrl, transaction, {
          apiKey: this.config.apiKey,
          timeoutMs: this.config.requestTimeoutSecs! * 1000,
        });
      } catch (error) {
        if (attempt === this.config.maxRetries) {
          throw new ConsensusError(
            `tx submit failed after ${this.config.maxRetries! + 1} attempts: ${
              error instanceof Error ? error.message : String(error)
            }`,
            'TX_SUBMIT_FAILED'
          );
        }
        // fall through to retry
      }
    }
    throw new ConsensusError('tx submit: exhausted retries', 'TX_SUBMIT_FAILED');
  }

  /**
   * Make a JSON-RPC request to CometBFT
   */
  private async rpcRequest(method: string, params: any): Promise<any> {
    const rpcUrl = this.config.consensusRpcUrl;
    if (!rpcUrl) {
      throw new ConsensusError(
        'CometBFT RPC URL is not configured. Set `consensusRpcUrl` in the SDK config to use consensus reads (transaction status, chain info).',
        'CONSENSUS_RPC_URL_REQUIRED'
      );
    }

    const rpcRequest = {
      jsonrpc: '2.0',
      id: 1,
      method,
      params
    };

    for (let attempt = 0; attempt <= this.config.maxRetries!; attempt++) {
      try {
        const response = await fetch(rpcUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(this.config.apiKey ? { 'X-API-Key': this.config.apiKey } : {})
          },
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

        this.logger.warn(`RPC attempt ${attempt + 1} failed:`, error);
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
      if (isRpcUrlMissingError(error)) throw error;
      return undefined;
    }
  }

  /**
   * Get the next nonce for a DID. Falls back to the in-memory cache only
   * if a prior call populated it — if the API is unreachable on first use
   * the error is propagated rather than fabricating nonce=1, which would
   * silently submit txs with a stale nonce.
   */
  private async getNextNonce(did: string): Promise<number> {
    try {
      const currentNonce = await this.getAccountNonce(did);
      const nextNonce = currentNonce + 1;
      this.nonceCache.set(did, nextNonce);
      return nextNonce;
    } catch (error) {
      const cached = this.nonceCache.get(did);
      if (cached === undefined) {
        throw error;
      }
      this.logger.warn('Failed to fetch nonce from API, using cache:', error);
      const nextNonce = cached + 1;
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
        headers: {
          'Content-Type': 'application/json',
          ...(this.config.apiKey ? { 'X-API-Key': this.config.apiKey } : {})
        },
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
