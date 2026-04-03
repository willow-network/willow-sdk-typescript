/**
 * File storage operations for Willow.
 *
 * Upload, download, and manage files in FileStorage subgroves.
 * Files are chunked locally, manifests go through consensus,
 * and chunks are uploaded to storage nodes.
 */

import { createHash } from 'crypto';

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

export class FileOperations {
  private apiUrl: string;
  private getHeaders: () => Record<string, string>;

  constructor(apiUrl: string, getHeaders: () => Record<string, string>) {
    this.apiUrl = apiUrl;
    this.getHeaders = getHeaders;
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
    data: Buffer,
    storageNodeEndpoint: string,
    signing?: FileSigningOptions,
  ): Promise<FileManifest> {
    const chunkSize = DEFAULT_CHUNK_SIZE;
    const chunks = chunkData(data, chunkSize);
    const chunkCount = chunks.length;

    // Compute hashes
    const contentHash = createHash('sha256').update(data).digest('hex');
    const chunkHashes = chunks.map(c =>
      createHash('sha256').update(c).digest(),
    );
    const chunkMerkleRoot = computeMerkleRoot(chunkHashes).toString('hex');

    // Submit StoreFileManifestTx to consensus
    const ownerDid = signing?.ownerDid ?? '';
    const signMessage = `store_file:${subgroveId}:${fileKey}:${contentHash}:${data.length}`;
    const signature = signing
      ? signing.signFunction(signMessage, signing.privateKey)
      : '';
    const manifestTx = {
      StoreFileManifest: {
        
        subgrove_id: subgroveId,
        file_key: fileKey,
        filename,
        content_type: guessContentType(filename),
        total_size: data.length,
        content_hash: contentHash,
        chunk_count: chunkCount,
        chunk_size: chunkSize,
        chunk_merkle_root: chunkMerkleRoot,
        owner_did: ownerDid,
        signature,
        public_key_id: signing?.publicKeyId ?? '',
        nonce: signing?.nonce ?? 0,
      },
    };
    const txResp = await fetch(`${this.apiUrl}/broadcast_tx`, {
      method: 'POST',
      headers: { ...this.getHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(manifestTx),
    });
    if (!txResp.ok) {
      throw new Error(`Failed to submit file manifest: ${await txResp.text()}`);
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
        throw new Error(`Failed to upload chunk ${i}: ${await chunkResp.text()}`);
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
  ): Promise<Buffer> {
    const manifest = await this.metadata(subgroveId, fileKey);

    const chunks: Buffer[] = [];
    for (let i = 0; i < manifest.chunk_count; i++) {
      const url = `${storageNodeEndpoint}/chunk/${subgroveId}/${fileKey}/${i}?content_hash=${manifest.content_hash}`;
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`Failed to download chunk ${i}`);
      chunks.push(Buffer.from(await resp.arrayBuffer()));
    }

    // Verify chunk Merkle root
    const chunkHashes = chunks.map(c => createHash('sha256').update(c).digest());
    const computedMerkleRoot = computeMerkleRoot(chunkHashes).toString('hex');
    if (computedMerkleRoot !== manifest.chunk_merkle_root) {
      throw new Error('Chunk Merkle root mismatch');
    }

    const fileData = Buffer.concat(chunks);

    // Verify content hash
    const computedHash = createHash('sha256').update(fileData).digest('hex');
    if (computedHash !== manifest.content_hash) {
      throw new Error('Content hash mismatch');
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
    const resp = await fetch(
      `${this.apiUrl}/files/${subgroveId}/${fileKey}`,
      { headers: this.getHeaders() },
    );
    if (!resp.ok) throw new Error(`File not found: ${fileKey}`);
    return (await resp.json()) as FileManifest;
  }

  /**
   * List all files in a subgrove.
   */
  async list(subgroveId: string): Promise<FileManifest[]> {
    const resp = await fetch(
      `${this.apiUrl}/files/${subgroveId}`,
      { headers: this.getHeaders() },
    );
    if (!resp.ok) throw new Error('Failed to list files');
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
    const deleteTx = {
      DeleteFileManifest: {
        
        subgrove_id: subgroveId,
        file_key: fileKey,
        owner_did: signing?.ownerDid ?? '',
        signature,
        public_key_id: signing?.publicKeyId ?? '',
        nonce: signing?.nonce ?? 0,
      },
    };
    const resp = await fetch(`${this.apiUrl}/broadcast_tx`, {
      method: 'POST',
      headers: { ...this.getHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(deleteTx),
    });
    if (!resp.ok) {
      throw new Error(`Failed to delete file: ${await resp.text()}`);
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
    const tx = {
      UnregisterStorageNode: {
        node_did: nodeDid,
        signature,
        public_key_id: signing?.publicKeyId ?? '',
        nonce: signing?.nonce ?? 0,
      },
    };
    const resp = await fetch(`${this.apiUrl}/broadcast_tx`, {
      method: 'POST',
      headers: { ...this.getHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(tx),
    });
    if (!resp.ok) {
      throw new Error(`Failed to unregister storage node: ${await resp.text()}`);
    }
  }
}

function chunkData(data: Buffer, chunkSize: number): Buffer[] {
  const chunks: Buffer[] = [];
  for (let i = 0; i < data.length; i += chunkSize) {
    chunks.push(data.subarray(i, Math.min(i + chunkSize, data.length)));
  }
  return chunks;
}

function computeMerkleRoot(hashes: Buffer[]): Buffer {
  if (hashes.length === 0) return Buffer.alloc(32);
  // No early return for single-leaf: pad to [leaf, leaf] and hash.
  // This prevents availability proof forgery for single-chunk files.

  let current = [...hashes];
  if (current.length === 1) current.push(current[0]);
  while (current.length > 1) {
    if (current.length % 2 !== 0) current.push(current[current.length - 1]);
    const next: Buffer[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const h = createHash('sha256');
      h.update(current[i]);
      h.update(current[i + 1]);
      next.push(h.digest());
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
 * IMPORTANT: This uses XChaCha20-Poly1305 with a 24-byte nonce to match the
 * Rust SDK and consensus layer. Files encrypted with this function are
 * interoperable across all Willow SDKs.
 *
 * Requires the `@noble/ciphers` package: `npm install @noble/ciphers`
 *
 * @param data - Plaintext file data
 * @param key - 32-byte symmetric key from the subgrove key grant system
 * @returns Object with ciphertext Buffer and 24-byte nonce
 */
export function encryptFile(
  data: Buffer,
  key: Buffer,
): { ciphertext: Buffer; nonce: Buffer } {
  const { xchacha20poly1305 } = require('@noble/ciphers/chacha');
  const { randomBytes } = require('crypto');
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(key, nonce);
  const ciphertext = cipher.encrypt(data);
  return {
    ciphertext: Buffer.from(ciphertext),
    nonce: Buffer.from(nonce),
  };
}

/**
 * Decrypt file data using XChaCha20-Poly1305.
 *
 * Requires the `@noble/ciphers` package: `npm install @noble/ciphers`
 *
 * @param ciphertext - Encrypted data (ciphertext + 16-byte auth tag)
 * @param key - 32-byte symmetric key
 * @param nonce - 24-byte nonce used during encryption
 * @returns Decrypted plaintext
 */
export function decryptFile(
  ciphertext: Buffer,
  key: Buffer,
  nonce: Buffer,
): Buffer {
  const { xchacha20poly1305 } = require('@noble/ciphers/chacha');
  const cipher = xchacha20poly1305(key, nonce);
  return Buffer.from(cipher.decrypt(ciphertext));
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
