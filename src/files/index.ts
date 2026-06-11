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
import { createTransactionWrapper } from '../consensus/types';
import { submitTxToApi, SubmitTxOptions } from '../internal/tx';

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
  nonce: number;
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
  private getAuthHeaders: (method: string, path: string) => Record<string, string>;

  constructor(
    apiUrl: string,
    getAuthHeaders: (method: string, path: string) => Record<string, string>,
  ) {
    this.apiUrl = apiUrl;
    this.getAuthHeaders = getAuthHeaders;
  }

  /**
   * Upload a file to a FileStorage subgrove.
   *
   * @param signing - When provided, the manifest transaction is properly signed.
   *   Without signing options, the transaction is broadcast unsigned (requires
   *   server-side signing or a permissive test environment).
   */
  async upload(
    subgroveId: string,
    fileKey: string,
    filename: string,
    data: Uint8Array,
    storageNodeEndpoint: string,
    signing?: FileSigningOptions,
  ): Promise<FileManifest> {
    const chunkSize = DEFAULT_CHUNK_SIZE;
    const chunks = chunkData(data, chunkSize);
    const chunkCount = chunks.length;

    // Compute hashes
    const contentHash = bytesToHex(sha256(data));
    const chunkHashes = chunks.map((c) => sha256(c));
    const chunkMerkleRoot = bytesToHex(computeMerkleRoot(chunkHashes));

    // Submit StoreFileManifestTx to consensus
    const ownerDid = signing?.ownerDid ?? '';
    const signMessage = `store_file:${subgroveId}:${fileKey}:${contentHash}:${data.length}`;
    const signature = signing
      ? signing.signFunction(signMessage, signing.privateKey)
      : '';
    const manifestTx = createTransactionWrapper('StoreFileManifest', {
      subgroveId,
      fileKey,
      filename,
      contentType: guessContentType(filename),
      totalSize: data.length,
      contentHash,
      chunkCount,
      chunkSize,
      chunkMerkleRoot,
      ownerDid,
      signature,
      publicKeyId: signing?.publicKeyId ?? '',
      nonce: signing?.nonce ?? 0,
    });
    const txResult = await this.submitTx(manifestTx);
    if (!txResult.success) {
      throw new WillowError(
        `Failed to submit file manifest: ${txResult.rawLog || txResult.errorMessage || 'unknown error'}`,
        'TX_SUBMIT_FAILED',
      );
    }

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
    const path = `/files/${subgroveId}/${fileKey}`;
    const resp = await fetch(
      `${this.apiUrl}${path}`,
      { headers: this.getAuthHeaders('GET', path) },
    );
    if (!resp.ok) {
      throw new WillowError(`File not found: ${fileKey}`, 'FILE_NOT_FOUND', resp.status);
    }
    return (await resp.json()) as FileManifest;
  }

  /**
   * List all files in a subgrove.
   */
  async list(subgroveId: string): Promise<FileManifest[]> {
    const path = `/files/${subgroveId}`;
    const resp = await fetch(
      `${this.apiUrl}${path}`,
      { headers: this.getAuthHeaders('GET', path) },
    );
    if (!resp.ok) {
      throw new WillowError('Failed to list files', 'FILE_LIST_FAILED', resp.status);
    }
    const body = (await resp.json()) as FileListResponse;
    return body.files;
  }

  /**
   * Delete a file (submits DeleteFileManifestTx to consensus).
   */
  async delete(
    subgroveId: string,
    fileKey: string,
    signing?: FileSigningOptions,
  ): Promise<void> {
    const signMessage = `delete_file:${subgroveId}:${fileKey}`;
    const signature = signing
      ? signing.signFunction(signMessage, signing.privateKey)
      : '';
    const deleteTx = createTransactionWrapper('DeleteFileManifest', {
      subgroveId,
      fileKey,
      ownerDid: signing?.ownerDid ?? '',
      signature,
      publicKeyId: signing?.publicKeyId ?? '',
      nonce: signing?.nonce ?? 0,
    });
    const result = await this.submitTx(deleteTx);
    if (!result.success) {
      throw new WillowError(
        `Failed to delete file: ${result.rawLog || result.errorMessage || 'unknown error'}`,
        'TX_SUBMIT_FAILED',
      );
    }
  }

  /**
   * Unregister a storage node (submits UnregisterStorageNode to consensus).
   */
  async unregisterStorageNode(
    nodeDid: string,
    signing?: FileSigningOptions,
  ): Promise<void> {
    const signMessage = `unregister_storage_node:${nodeDid}`;
    const signature = signing
      ? signing.signFunction(signMessage, signing.privateKey)
      : '';
    const tx = createTransactionWrapper('UnregisterStorageNode', {
      nodeDid,
      signature,
      publicKeyId: signing?.publicKeyId ?? '',
      nonce: signing?.nonce ?? 0,
    });
    const result = await this.submitTx(tx);
    if (!result.success) {
      throw new WillowError(
        `Failed to unregister storage node: ${result.rawLog || result.errorMessage || 'unknown error'}`,
        'TX_SUBMIT_FAILED',
      );
    }
  }

  /**
   * Submit a tx through `/tx/submit`, folding transport-level failures
   * (which `submitTxToApi` throws to enable retries elsewhere) into a
   * `TX_SUBMIT_FAILED` WillowError so file callers see one error type.
   */
  private async submitTx(txWrapper: Record<string, unknown>) {
    const opts: SubmitTxOptions = { headers: this.getAuthHeaders('POST', '/tx/submit') };
    try {
      return await submitTxToApi(this.apiUrl, txWrapper, opts);
    } catch (error) {
      throw new WillowError(
        `Failed to submit transaction: ${error instanceof Error ? error.message : String(error)}`,
        'TX_SUBMIT_FAILED',
      );
    }
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
