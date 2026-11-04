/**
 * File storage operations for Willow.
 *
 * Upload, download, and manage files in FileStorage subgroves.
 * Files are chunked locally, manifests go through consensus,
 * and chunks are uploaded to storage nodes.
 *
 * This module is browser-safe: it uses `Uint8Array` instead of Node's
 * `Buffer`, `@noble/hashes` for SHA-256, and `@noble/ciphers` for
 * XChaCha20-Poly1305.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { WillowError } from '../types';
import {
  BroadcastResult,
  createTransactionWrapper,
  deleteFileManifestSignMessage,
  DeleteFileManifestTx,
  storeFileManifestSignMessage,
  StoreFileManifestTx,
  Transaction,
  TransactionSubmitError,
  unregisterStorageNodeSignMessage,
  UnregisterStorageNodeTx,
} from '../consensus/types';
import type { NonceAllocator } from '../consensus/nonces';
import { submitTxToApi } from '../internal/tx';
import { RequestSigner, resolveRequest } from '../internal/http';

const DEFAULT_CHUNK_SIZE = 262_144; // 256 KB

export interface FileManifest {
  file_key: string;
  filename: string;
  content_type: string;
  total_size: number;
  content_hash: string;
  chunk_count: number;
  chunk_size: number;
  chunk_merkle_root: string;
  owner_did: string;
  created_at: number;
  updated_at: number;
  encrypted: boolean;
  storage_nodes: string[];
}

export interface FileListResponse {
  files: FileManifest[];
}

/** Signing options for file transactions that require consensus broadcast. */
export interface FileSigningOptions {
  ownerDid: string;
  privateKey: string;
  publicKeyId: string;
  signFunction: (message: string, privateKey: string) => string;
  /**
   * The nonce the transaction carries. The signature covers it. Leave it out
   * and the write takes the lowest free nonce from the operations' nonce
   * source (`WillowClient.files` uses `client.consensus`), as every other
   * write does; or take one with `client.consensus.nextNonce(did)` and pass
   * it. Either way, with a nonce source the outcome is recorded with its
   * allocator: an accepted write holds the nonce, a refusal at CheckTx gives
   * it back unless the refusal says it is held, used, or spent. A write the
   * chain refuses in its block after its signature and nonce verify still
   * spends it; to retry, sign again under a fresh nonce.
   */
  nonce?: number;
}

/**
 * Where `FileOperations` takes and settles transaction nonces: a
 * `ConsensusClient` (`WillowClient` passes its own).
 */
export interface FileNonceSource {
  /** Take the next free nonce for `did`. */
  nextNonce(did: string): Promise<number>;
  /** The allocator the nonces come from, which the outcome is settled with. */
  readonly nonces: NonceAllocator;
}

/** The chain refuses an unsigned transaction: refuse to send one. */
function requireSigning(signing: FileSigningOptions | undefined, what: string): void {
  if (!signing) {
    throw new WillowError(
      `${what} is a transaction the chain accepts only signed; pass signing options`,
      'SIGNING_REQUIRED',
    );
  }
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export class FileOperations {
  private apiUrl: string;
  private getAuthHeaders: RequestSigner;
  private nonceSource?: FileNonceSource;

  /**
   * @param getAuthHeaders - Makes the headers for each request to the API,
   *   given its method and its path and query exactly as sent
   *   (`WillowClient` passes `WillowAuth.getAuthHeaders`, the older form).
   * @param nonceSource - Takes the nonce of a write whose signing options
   *   leave it out, and records each write's outcome with its allocator
   *   (`WillowClient` passes its `ConsensusClient`). Without one, every write
   *   needs `signing.nonce`.
   */
  constructor(apiUrl: string, getAuthHeaders: RequestSigner, nonceSource?: FileNonceSource) {
    this.apiUrl = apiUrl;
    this.getAuthHeaders = getAuthHeaders;
    this.nonceSource = nonceSource;
  }

  /** GET a path on the API, signed over its path exactly as sent. */
  private getFromApi(path: string): Promise<Response> {
    const resolved = resolveRequest(this.apiUrl, path);
    return fetch(resolved?.href ?? `${this.apiUrl}${path}`, {
      headers: this.getAuthHeaders('GET', resolved?.target ?? path),
    });
  }

  /**
   * Upload a file to a FileStorage subgrove.
   *
   * @param signing - Signs the manifest transaction. The chain refuses an
   *   unsigned one, so without it this throws `SIGNING_REQUIRED` and sends
   *   nothing.
   */
  async upload(
    subgroveId: string,
    fileKey: string,
    filename: string,
    data: Uint8Array,
    storageNodeEndpoint: string,
    signing: FileSigningOptions,
  ): Promise<FileManifest> {
    requireSigning(signing, 'A file manifest');
    const chunkSize = DEFAULT_CHUNK_SIZE;
    const chunks = chunkData(data, chunkSize);
    const chunkCount = chunks.length;

    // Compute hashes
    const contentHash = bytesToHex(sha256(data));
    const chunkHashes = chunks.map((c) => sha256(c));
    const chunkMerkleRoot = bytesToHex(computeMerkleRoot(chunkHashes));

    // Submit StoreFileManifestTx to consensus, signed over every field it
    // carries, nonce included.
    await this.submitSigned(
      'Failed to submit file manifest',
      signing.ownerDid,
      signing,
      'StoreFileManifest',
      (nonce): StoreFileManifestTx => ({
        subgroveId,
        fileKey,
        filename,
        contentType: guessContentType(filename),
        totalSize: data.length,
        contentHash,
        chunkCount,
        chunkSize,
        chunkMerkleRoot,
        ownerDid: signing.ownerDid,
        publicKeyId: signing.publicKeyId,
        nonce,
      }),
      storeFileManifestSignMessage,
    );

    // Upload chunks to storage node
    for (let i = 0; i < chunks.length; i++) {
      const url = `${storageNodeEndpoint}/upload/${subgroveId}/${fileKey}?chunk_index=${i}&chunk_count=${chunkCount}&content_hash=${contentHash}`;
      const chunkResp = await fetch(url, {
        method: 'POST',
        body: chunks[i],
        headers: { 'Content-Type': 'application/octet-stream' },
      });
      if (!chunkResp.ok) {
        throw new WillowError(
          `Failed to upload chunk ${i}: ${await chunkResp.text()}`,
          'CHUNK_UPLOAD_FAILED',
          chunkResp.status,
        );
      }
    }

    return {
      file_key: fileKey,
      filename,
      content_type: guessContentType(filename),
      total_size: data.length,
      content_hash: contentHash,
      chunk_count: chunkCount,
      chunk_size: chunkSize,
      chunk_merkle_root: chunkMerkleRoot,
      owner_did: '',
      created_at: 0,
      updated_at: 0,
      encrypted: false,
      storage_nodes: [storageNodeEndpoint],
    };
  }

  /**
   * Download a file from a FileStorage subgrove.
   */
  async download(
    subgroveId: string,
    fileKey: string,
    storageNodeEndpoint: string,
  ): Promise<Uint8Array> {
    const manifest = await this.metadata(subgroveId, fileKey);

    const chunks: Uint8Array[] = [];
    for (let i = 0; i < manifest.chunk_count; i++) {
      const url = `${storageNodeEndpoint}/chunk/${subgroveId}/${fileKey}/${i}?content_hash=${manifest.content_hash}`;
      const resp = await fetch(url);
      if (!resp.ok) {
        throw new WillowError(
          `Failed to download chunk ${i}`,
          'CHUNK_DOWNLOAD_FAILED',
          resp.status,
        );
      }
      chunks.push(new Uint8Array(await resp.arrayBuffer()));
    }

    // Verify chunk Merkle root
    const chunkHashes = chunks.map((c) => sha256(c));
    const computedMerkleRoot = bytesToHex(computeMerkleRoot(chunkHashes));
    if (computedMerkleRoot !== manifest.chunk_merkle_root) {
      throw new WillowError('Chunk Merkle root mismatch', 'CHUNK_MERKLE_ROOT_MISMATCH');
    }

    const fileData = concatBytes(chunks);

    // Verify content hash
    const computedHash = bytesToHex(sha256(fileData));
    if (computedHash !== manifest.content_hash) {
      throw new WillowError('Content hash mismatch', 'CONTENT_HASH_MISMATCH');
    }

    return fileData;
  }

  /**
   * Get file manifest metadata.
   */
  async metadata(
    subgroveId: string,
    fileKey: string,
  ): Promise<FileManifest> {
    const resp = await this.getFromApi(`/files/${subgroveId}/${fileKey}`);
    if (!resp.ok) {
      throw new WillowError(`File not found: ${fileKey}`, 'FILE_NOT_FOUND', resp.status);
    }
    return (await resp.json()) as FileManifest;
  }

  /**
   * List all files in a subgrove.
   */
  async list(subgroveId: string): Promise<FileManifest[]> {
    const resp = await this.getFromApi(`/files/${subgroveId}`);
    if (!resp.ok) {
      throw new WillowError('Failed to list files', 'FILE_LIST_FAILED', resp.status);
    }
    const body = (await resp.json()) as FileListResponse;
    return body.files;
  }

  /**
   * Delete a file (submits DeleteFileManifestTx to consensus).
   *
   * @param signing - Signs the transaction. The chain refuses an unsigned
   *   one, so without it this throws `SIGNING_REQUIRED` and sends nothing.
   */
  async delete(
    subgroveId: string,
    fileKey: string,
    signing: FileSigningOptions,
  ): Promise<void> {
    requireSigning(signing, 'A file delete');
    await this.submitSigned(
      'Failed to delete file',
      signing.ownerDid,
      signing,
      'DeleteFileManifest',
      (nonce): DeleteFileManifestTx => ({
        subgroveId,
        fileKey,
        ownerDid: signing.ownerDid,
        publicKeyId: signing.publicKeyId,
        nonce,
      }),
      deleteFileManifestSignMessage,
    );
  }

  /**
   * Unregister a storage node (submits UnregisterStorageNode to consensus),
   * signed over the node DID and the nonce
   * ({@link unregisterStorageNodeSignMessage}). The signing identity is the
   * node's DID; `signing.ownerDid` is not used. The chain refuses an
   * unsigned removal, so without `signing` this throws `SIGNING_REQUIRED`
   * and sends nothing.
   */
  async unregisterStorageNode(
    nodeDid: string,
    signing: FileSigningOptions,
  ): Promise<void> {
    requireSigning(signing, "A storage node's removal");
    await this.submitSigned(
      'Failed to unregister storage node',
      nodeDid,
      signing,
      'UnregisterStorageNode',
      (nonce): UnregisterStorageNodeTx => ({
        nodeDid,
        publicKeyId: signing.publicKeyId,
        nonce,
      }),
      unregisterStorageNodeSignMessage,
    );
  }

  /**
   * Sign a write under its nonce and submit it through `/tx/submit`.
   *
   * Its fields are checked (by building its message) before a nonce is
   * taken. The nonce is `signing.nonce`, or else one taken from the nonce
   * source for `did`. With a source, the nonce is held while the write is in
   * flight and the outcome settled with its allocator: accepted holds it, a
   * refusal at CheckTx gives it back unless it says the nonce is held, used,
   * or spent, and a transport failure keeps it held (the write may yet land).
   * A transport failure or a refusal throws a `TX_SUBMIT_FAILED`
   * {@link TransactionSubmitError} carrying the DID, the nonce, the signed
   * body, and (for a refusal) the chain's answer, so the write can be posted
   * again under the same nonce (`client.consensus.resubmit(error)`).
   */
  private async submitSigned<T extends { signature?: string }>(
    failure: string,
    did: string,
    signing: FileSigningOptions,
    txType: string,
    unsigned: (nonce: number) => T,
    signMessage: (tx: T) => string,
  ): Promise<BroadcastResult> {
    signMessage(unsigned(signing.nonce ?? 0));
    const source = this.nonceSource;
    const taken = signing.nonce === undefined;
    let nonce: number;
    if (signing.nonce !== undefined) {
      nonce = signing.nonce;
    } else if (source) {
      nonce = await source.nextNonce(did);
    } else {
      throw new WillowError(
        'A file write needs a nonce: pass signing.nonce (take one with client.consensus.nextNonce), ' +
          'or give FileOperations a nonce source (WillowClient.files has one)',
        'NONCE_REQUIRED',
      );
    }

    let transaction: Record<string, unknown>;
    let headers: Record<string, string>;
    try {
      const tx = unsigned(nonce);
      tx.signature = signing.signFunction(signMessage(tx), signing.privateKey);
      transaction = createTransactionWrapper(txType, tx as unknown as Transaction);
      headers = this.getAuthHeaders('POST', '/tx/submit');
    } catch (error) {
      if (taken) source!.nonces.release(did, nonce);
      throw error;
    }

    source?.nonces.hold(did, nonce);
    let result: BroadcastResult;
    try {
      result = await submitTxToApi(this.apiUrl, transaction, { headers });
    } catch (error) {
      throw new TransactionSubmitError(
        `Failed to submit transaction: ${error instanceof Error ? error.message : String(error)}`,
        'TX_SUBMIT_FAILED',
        { did, nonce, transaction },
      );
    }
    source?.nonces.settle(did, nonce, result);
    if (!result.success) {
      throw new TransactionSubmitError(
        `${failure}: ${result.rawLog || result.errorMessage || 'unknown error'}`,
        'TX_SUBMIT_FAILED',
        { did, nonce, transaction, result },
      );
    }
    return result;
  }
}

function chunkData(data: Uint8Array, chunkSize: number): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < data.length; i += chunkSize) {
    chunks.push(data.subarray(i, Math.min(i + chunkSize, data.length)));
  }
  return chunks;
}

function computeMerkleRoot(hashes: Uint8Array[]): Uint8Array {
  if (hashes.length === 0) return new Uint8Array(32);
  // No early return for single-leaf: pad to [leaf, leaf] and hash.
  // This prevents availability proof forgery for single-chunk files.

  let current = [...hashes];
  if (current.length === 1) current.push(current[0]);
  while (current.length > 1) {
    if (current.length % 2 !== 0) current.push(current[current.length - 1]);
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      next.push(sha256(concatBytes([current[i], current[i + 1]])));
    }
    current = next;
  }
  return current[0];
}

/**
 * Encryption metadata for private file subgroves.
 */
export interface FileEncryption {
  key_epoch: number;
  nonce: string; // hex-encoded 24-byte nonce
}

/**
 * Encrypt file data using XChaCha20-Poly1305.
 *
 * Uses XChaCha20-Poly1305 with a 24-byte nonce to match the Rust SDK and
 * consensus layer. Files encrypted with this function are interoperable
 * across all Willow SDKs.
 *
 * @param data - Plaintext file data
 * @param key - 32-byte symmetric key from the subgrove key grant system
 * @returns Object with ciphertext and 24-byte nonce
 */
export function encryptFile(
  data: Uint8Array,
  key: Uint8Array,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(data);
  return { ciphertext, nonce };
}

/**
 * Decrypt file data using XChaCha20-Poly1305.
 *
 * @param ciphertext - Encrypted data (ciphertext + 16-byte auth tag)
 * @param key - 32-byte symmetric key
 * @param nonce - 24-byte nonce used during encryption
 * @returns Decrypted plaintext
 */
export function decryptFile(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
): Uint8Array {
  const cipher = xchacha20poly1305(key, nonce);
  return cipher.decrypt(ciphertext);
}

function guessContentType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  const types: Record<string, string> = {
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    pdf: 'application/pdf',
    json: 'application/json',
    txt: 'text/plain',
    html: 'text/html',
    css: 'text/css',
    js: 'application/javascript',
    wasm: 'application/wasm',
    zip: 'application/zip',
    mp4: 'video/mp4',
    mp3: 'audio/mpeg',
  };
  return types[ext ?? ''] ?? 'application/octet-stream';
}
