/**
 * Consensus Client Implementation
 *
 * Provides direct transaction broadcasting to CometBFT consensus layer.
 */

import { ConsensusConfig, BroadcastResult, TransactionStatus, ConsensusError, RegisterDidTx, RegisterSubgroveTx, RegisterSubgroveOptions, SubgroveMode, RetentionWindow, Signer, SignFunction, StoreFileManifestFields, TransferTx, DataStoreTx, StoreFileManifestTx, DeleteFileManifestTx, DeregisterSubgroveTx, SubmitAnchorTx, Transaction, createTransactionWrapper, createSignMessage } from './types';
import { canonicalizeAnchorBody, computeAnchorMerkleRoot, sha256Hex } from './anchor-canonical';
import { submitTxToApi } from '../internal/tx';
import { NonceAllocator, AccountNonceState, NONCE_WINDOW, parseAccountNonceStateBase64 } from './nonces';
import { signEd25519, signSecp256k1, algorithmFromKeyType } from '../auth';
import { didDocumentKeyType } from './wire';
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
  private logger: WillowLogger;
  /** Hands out this client's transaction nonces, per DID. */
  readonly nonces: NonceAllocator;

  constructor(config: ConsensusConfig) {
    this.config = {
      ...config,
      requestTimeoutSecs: config.requestTimeoutSecs ?? 30,
      maxRetries: config.maxRetries ?? 3,
      retryDelaySecs: config.retryDelaySecs ?? 1,
    };
    this.logger = config.logger ?? silentLogger;
    this.nonces = config.nonceAllocator ?? NonceAllocator.shared(config.apiUrl ?? '');
  }

  /**
   * Register a DID on the blockchain by a RegisterDid transaction.
   *
   * `didDocument` is the SDK's `DidDocument` (from `createDidFromPublicKey`
   * or `createDidFromWallet`) or the chain's own shape. It is sent as the
   * chain's `DidDocument`, and signed over that document's JSON text (see
   * `registerDidSignMessage`). The signer is a key in the document, and
   * signs with that key's algorithm: a signer without a `signFunction` takes
   * the SDK's for the key's type, and one whose `signFunction` is the SDK's
   * for the other algorithm is refused (`ALGORITHM_MISMATCH`). A DID's
   * registration is its first transaction, so its nonce is 1.
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
    const given =
      typeof signerOrPrivateKey === 'string' ? signFunction : signerOrPrivateKey.signFunction;
    const keyAlgorithm = algorithmFromKeyType(didDocumentKeyType(didDocument, signer.publicKeyId));
    if (keyAlgorithm !== undefined) {
      const sdkFunction = keyAlgorithm === 'secp256k1' ? signSecp256k1 : signEd25519;
      const otherFunction = keyAlgorithm === 'secp256k1' ? signEd25519 : signSecp256k1;
      if (given === otherFunction) {
        throw new ConsensusError(
          `The key ${signer.publicKeyId} is ${keyAlgorithm}, but the signer signs with the other algorithm`,
          'ALGORITHM_MISMATCH',
        );
      }
      if (given === undefined) signer.signFunction = sdkFunction;
    }
    const tx: RegisterDidTx = {
      didDocument,
      signature: '', // Will be filled by signing
      publicKeyId: signer.publicKeyId,
      // The chain accepts a DID registration only at nonce 1.
      nonce: 1,
    };

    const result = await this.signAndBroadcast('RegisterDid', tx, signer.privateKey, signer.signFunction);
    // Nonce 1 is the new DID's while the registration is pending.
    const did = typeof didDocument?.id === 'string' ? didDocument.id : undefined;
    if (did && result.success) this.nonces.hold(did, 1);
    return result;
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

    return this.submitWithNonce(ownerDid, 'RegisterSubgrove', signer, (nonce): RegisterSubgroveTx => ({
      subgroveId,
      name: options.name,
      schema,
      ownerDid,
      mode: options.mode,
      retention_window: options.retentionWindow,
      initialFunding: options.initialFunding,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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

    return this.submitWithNonce(fromDid, 'Transfer', signer, (nonce): TransferTx => ({
      fromDid,
      toDid,
      amount,
      memo: txMemo,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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
    return this.submitWithNonce(ownerDid, 'DataStore', signer, (nonce): DataStoreTx => ({
      subgroveId,
      key,
      data: JSON.stringify(data),
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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

    return this.submitWithNonce(fields.ownerDid, 'StoreFileManifest', signer, (nonce): StoreFileManifestTx => ({
      ...fields,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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
    return this.submitWithNonce(ownerDid, 'DeleteFileManifest', signer, (nonce): DeleteFileManifestTx => ({
      subgroveId,
      fileKey,
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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
    return this.submitWithNonce(ownerDid, 'DeregisterSubgrove', signer, (nonce): DeregisterSubgroveTx => ({
      subgroveId,
      ownerDid,
      signature: '',
      publicKeyId: signer.publicKeyId,
      nonce,
    }));
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

    return this.submitWithNonce(fields.did, 'SubmitAnchor', signer, (nonce): SubmitAnchorTx => ({
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
      nonce,
    }));
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
   * Take a nonce for `did`, build the transaction under it, sign, and
   * broadcast, then record the outcome with the nonce allocator: an accepted
   * write holds its nonce; one refused at CheckTx gives it back unless the
   * refusal says the nonce is held, used, or spent. A write that fails before
   * it is sent gives its nonce back; one whose submission failed in transport
   * keeps it until its hold runs out (it may yet land).
   */
  private async submitWithNonce(
    did: string,
    txType: string,
    signer: Required<Signer>,
    build: (nonce: number) => Transaction,
  ): Promise<BroadcastResult> {
    const nonce = await this.nextNonce(did);
    let sent = false;
    try {
      const tx = build(nonce);
      const result = await this.signAndBroadcast(txType, tx, signer.privateKey, signer.signFunction, () => {
        sent = true;
      });
      this.nonces.settle(did, nonce, result);
      return result;
    } catch (error) {
      if (!sent) this.nonces.release(did, nonce);
      throw error;
    }
  }

  /**
   * Sign a transaction and broadcast it
   */
  private async signAndBroadcast(
    txType: string,
    transaction: Transaction,
    privateKey: string,
    signFunction: SignFunction,
    onSend?: () => void,
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
    onSend?.();
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
   * Take the next nonce for a DID from the nonce allocator ({@link nonces}),
   * against the account's nonce state as just read. If the read fails after
   * the state was read before (a transient API failure), the newest state
   * seen is used; on first use the error propagates rather than fabricating
   * a nonce.
   *
   * This client's own writes call it. For a transaction it doesn't build (a
   * file manifest from `FileOperations`), take the nonce here and report the
   * submission's outcome with `nonces.settle(did, nonce, result)`; the nonce
   * is held until it lands or 120 s pass.
   */
  async nextNonce(did: string): Promise<number> {
    let chain: AccountNonceState;
    try {
      chain = await this.readNonceState(did);
    } catch (error) {
      if (!this.nonces.hasState(did)) throw error;
      this.logger.warn('Failed to read the account nonce, using the last state seen:', error);
      return this.nonces.take(did);
    }
    return this.nonces.take(did, chain);
  }

  /**
   * An account's nonce state: the base and, with a CometBFT RPC URL, which of
   * the 24 nonces above it are used (ABCI query
   * `/store/account_nonce_state/{did}`); else the base alone from the API's
   * `/account/{did}/nonce`.
   */
  private async readNonceState(did: string): Promise<AccountNonceState> {
    if (this.config.consensusRpcUrl) {
      try {
        return await this.queryNonceState(did);
      } catch (error) {
        if (!this.config.apiUrl) throw error;
        this.logger.warn('Failed to read the nonce state over RPC, reading the base from the API:', error);
      }
    }
    return { base: await this.getAccountNonce(did), used: 0 };
  }

  /** ABCI query `/store/account_nonce_state/{did}`, one attempt. */
  private async queryNonceState(did: string): Promise<AccountNonceState> {
    const response = await fetch(this.config.consensusRpcUrl!, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(this.config.apiKey ? { 'X-API-Key': this.config.apiKey } : {})
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'abci_query',
        params: { path: `/store/account_nonce_state/${did}`, data: '', height: '0', prove: false },
      }),
      signal: AbortSignal.timeout(this.config.requestTimeoutSecs! * 1000)
    });
    if (!response.ok) {
      throw new ConsensusError(`Failed to read the nonce state: HTTP ${response.status}`);
    }
    const body = await response.json() as { result?: { response?: { code?: number; value?: string | null; log?: string } } };
    const answer = body.result?.response;
    if (!answer || typeof answer !== 'object') {
      throw new ConsensusError('Failed to read the nonce state: malformed response');
    }
    if ((answer.code ?? 0) !== 0) {
      throw new ConsensusError(`Failed to read the nonce state: ${answer.log ?? `code ${answer.code}`}`);
    }
    return parseAccountNonceStateBase64(answer.value ?? '');
  }

  /**
   * Get the current nonce (the base) for an account from the API
   */
  private async getAccountNonce(did: string): Promise<number> {
    if (!this.config.apiUrl) {
      throw new ConsensusError(
        'apiUrl is required to read the account nonce. Set it in the SDK config.',
        'API_URL_REQUIRED'
      );
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

    const base = data.data.nonce;
    if (!Number.isSafeInteger(base) || base < 0 || base > Number.MAX_SAFE_INTEGER - NONCE_WINDOW) {
      throw new ConsensusError(`Failed to fetch nonce: ${String(base)} is not a nonce this SDK can send`);
    }
    return base;
  }

  /**
   * Utility: Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
