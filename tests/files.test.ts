import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { FileOperations, encryptFile, decryptFile } from '../src/files';
import { WillowError } from '../src/types';
import { hexToBytes } from '../src/internal/bytes';

const API_URL = 'http://api.test';
const NODE_URL = 'http://storage.test';

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response;
}

function txAccepted(txHash = 'AB12') {
  return jsonResponse({ success: true, data: { tx_hash: txHash, code: 0, log: '' } });
}

function txRejected(log: string) {
  return jsonResponse({ success: true, data: { tx_hash: 'AB12', code: 1, log } });
}

function makeOps() {
  const getAuthHeaders = jest.fn((method: string, path: string) => ({
    'X-DID': 'did:willow:test',
    'X-Signature': `${method}:${path}`,
  }));
  return { ops: new FileOperations(API_URL, getAuthHeaders), getAuthHeaders };
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

beforeEach(() => jest.clearAllMocks());

describe('FileOperations.upload', () => {
  const data = new TextEncoder().encode('{"hello":"world"}');

  it('submits the manifest via POST /tx/submit with per-request auth headers', async () => {
    mockFetch
      .mockResolvedValueOnce(txAccepted())
      .mockResolvedValue(jsonResponse({ ok: true }));

    const { ops, getAuthHeaders } = makeOps();
    const manifest = await ops.upload('sg', 'file-1', 'doc.json', data, NODE_URL);

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${API_URL}/tx/submit`);
    expect(init.method).toBe('POST');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(init.headers['X-Signature']).toBe('POST:/tx/submit');
    expect(getAuthHeaders).toHaveBeenCalledWith('POST', '/tx/submit');

    const tx = JSON.parse(init.body).StoreFileManifest;
    expect(tx.subgrove_id).toBe('sg');
    expect(tx.file_key).toBe('file-1');
    expect(tx.filename).toBe('doc.json');
    expect(tx.content_type).toBe('application/json');
    expect(tx.total_size).toBe(data.length);
    expect(tx.chunk_count).toBe(1);

    // content_hash / chunk_merkle_root are [u8; 32] in Rust (no serde_bytes):
    // the wire shape is a 32-number array, never a hex string.
    expect(Array.isArray(tx.content_hash)).toBe(true);
    expect(tx.content_hash).toHaveLength(32);
    expect(tx.content_hash).toEqual(Array.from(sha256(data)));

    // Single-leaf Merkle roots are padded to [leaf, leaf] (anti-forgery).
    const leaf = sha256(data);
    const expectedRoot = sha256(concat([leaf, leaf]));
    expect(Array.isArray(tx.chunk_merkle_root)).toBe(true);
    expect(tx.chunk_merkle_root).toHaveLength(32);
    expect(tx.chunk_merkle_root).toEqual(Array.from(expectedRoot));

    // The returned manifest still surfaces the hex digests for callers.
    expect(manifest.chunk_merkle_root).toBe(bytesToHex(expectedRoot));
    expect(manifest.content_hash).toBe(bytesToHex(sha256(data)));
  });

  it('uploads each chunk to the storage node after the manifest is accepted', async () => {
    mockFetch
      .mockResolvedValueOnce(txAccepted())
      .mockResolvedValue(jsonResponse({ ok: true }));

    const { ops } = makeOps();
    const big = new Uint8Array(262_144 + 10); // 2 chunks
    const manifest = await ops.upload('sg', 'file-2', 'blob.bin', big, NODE_URL);

    expect(manifest.chunk_count).toBe(2);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    const contentHash = bytesToHex(sha256(big));
    expect(mockFetch.mock.calls[1][0]).toBe(
      `${NODE_URL}/upload/sg/file-2?chunk_index=0&chunk_count=2&content_hash=${contentHash}`,
    );
    expect(mockFetch.mock.calls[2][0]).toBe(
      `${NODE_URL}/upload/sg/file-2?chunk_index=1&chunk_count=2&content_hash=${contentHash}`,
    );
  });

  it('throws TX_SUBMIT_FAILED when consensus rejects the manifest', async () => {
    mockFetch.mockResolvedValueOnce(txRejected('insufficient balance'));

    const { ops } = makeOps();
    const err = await ops
      .upload('sg', 'file-1', 'doc.json', data, NODE_URL)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('TX_SUBMIT_FAILED');
    expect(err.message).toMatch(/insufficient balance/);
    expect(mockFetch).toHaveBeenCalledTimes(1); // no chunk uploads after rejection
  });

  it('throws TX_SUBMIT_FAILED when the API server errors', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, 500));

    const { ops } = makeOps();
    const err = await ops
      .upload('sg', 'file-1', 'doc.json', data, NODE_URL)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('TX_SUBMIT_FAILED');
    expect(err.message).toMatch(/boom/);
  });

  it('throws CHUNK_UPLOAD_FAILED with the status when a chunk upload fails', async () => {
    mockFetch
      .mockResolvedValueOnce(txAccepted())
      .mockResolvedValueOnce({
        ok: false,
        status: 507,
        text: async () => 'disk full',
      });

    const { ops } = makeOps();
    const err = await ops
      .upload('sg', 'file-1', 'doc.json', data, NODE_URL)
      .catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('CHUNK_UPLOAD_FAILED');
    expect(err.statusCode).toBe(507);
    expect(err.message).toMatch(/disk full/);
  });
});

describe('FileOperations.metadata / list', () => {
  it('signs the real metadata path', async () => {
    const manifest = { file_key: 'file-1', chunk_count: 1, content_hash: 'cc' };
    mockFetch.mockResolvedValueOnce(jsonResponse(manifest));

    const { ops, getAuthHeaders } = makeOps();
    const result = await ops.metadata('sg', 'file-1');

    expect(result).toEqual(manifest);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${API_URL}/files/sg/file-1`);
    expect(init.headers['X-Signature']).toBe('GET:/files/sg/file-1');
    expect(getAuthHeaders).toHaveBeenCalledWith('GET', '/files/sg/file-1');
  });

  it('throws FILE_NOT_FOUND on a missing file', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'nope' }, 404));

    const { ops } = makeOps();
    const err = await ops.metadata('sg', 'missing').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('FILE_NOT_FOUND');
    expect(err.statusCode).toBe(404);
  });

  it('signs the real list path and unwraps the files array', async () => {
    const files = [{ file_key: 'a' }, { file_key: 'b' }];
    mockFetch.mockResolvedValueOnce(jsonResponse({ files }));

    const { ops, getAuthHeaders } = makeOps();
    expect(await ops.list('sg')).toEqual(files);
    expect(mockFetch.mock.calls[0][0]).toBe(`${API_URL}/files/sg`);
    expect(getAuthHeaders).toHaveBeenCalledWith('GET', '/files/sg');
  });

  it('throws FILE_LIST_FAILED when the server errors', async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ error: 'nope' }, 500));

    const { ops } = makeOps();
    const err = await ops.list('sg').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('FILE_LIST_FAILED');
    expect(err.statusCode).toBe(500);
  });
});

describe('FileOperations.download', () => {
  const data = new TextEncoder().encode('verifiable file body');
  const leaf = sha256(data);
  const manifest = {
    file_key: 'file-1',
    chunk_count: 1,
    chunk_size: 262_144,
    content_hash: bytesToHex(sha256(data)),
    chunk_merkle_root: bytesToHex(sha256(concat([leaf, leaf]))),
  };

  it('fetches chunks, verifies hashes, and returns the file bytes', async () => {
    mockFetch
      .mockResolvedValueOnce(jsonResponse(manifest))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        arrayBuffer: async () => data.slice().buffer,
      });

    const { ops } = makeOps();
    const result = await ops.download('sg', 'file-1', NODE_URL);
    expect(new TextDecoder().decode(result)).toBe('verifiable file body');
    expect(mockFetch.mock.calls[1][0]).toBe(
      `${NODE_URL}/chunk/sg/file-1/0?content_hash=${manifest.content_hash}`,
    );
  });

  it('rejects chunks that do not match the manifest Merkle root', async () => {
    const tampered = data.slice();
    tampered[0] ^= 0xff;
    mockFetch
      .mockResolvedValueOnce(jsonResponse(manifest))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        arrayBuffer: async () => tampered.buffer,
      });

    const { ops } = makeOps();
    const err = await ops.download('sg', 'file-1', NODE_URL).catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('CHUNK_MERKLE_ROOT_MISMATCH');
  });

  it('throws CHUNK_DOWNLOAD_FAILED when the storage node errors', async () => {
    mockFetch
      .mockResolvedValueOnce(jsonResponse(manifest))
      .mockResolvedValueOnce({ ok: false, status: 502 });

    const { ops } = makeOps();
    const err = await ops.download('sg', 'file-1', NODE_URL).catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('CHUNK_DOWNLOAD_FAILED');
    expect(err.statusCode).toBe(502);
  });
});

describe('FileOperations.delete', () => {
  it('submits DeleteFileManifest via /tx/submit with auth headers', async () => {
    mockFetch.mockResolvedValueOnce(txAccepted());

    const { ops, getAuthHeaders } = makeOps();
    // The signFunction returns hex (as signEd25519 does); the wrapper decodes
    // it to a Vec<u8> byte array for the wire.
    const sigHex = 'ab'.repeat(32);
    await ops.delete('sg', 'file-1', {
      ownerDid: 'did:willow:owner',
      privateKey: 'pk',
      publicKeyId: 'did:willow:owner#key-1',
      signFunction: () => sigHex,
      nonce: 7,
    });

    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${API_URL}/tx/submit`);
    expect(getAuthHeaders).toHaveBeenCalledWith('POST', '/tx/submit');
    const tx = JSON.parse(init.body).DeleteFileManifest;
    expect(tx).toEqual({
      subgrove_id: 'sg',
      file_key: 'file-1',
      owner_did: 'did:willow:owner',
      signature: Array.from(hexToBytes(sigHex)),
      public_key_id: 'did:willow:owner#key-1',
      nonce: 7,
    });
    expect(Array.isArray(tx.signature)).toBe(true);
  });

  it('throws TX_SUBMIT_FAILED when consensus rejects the delete', async () => {
    mockFetch.mockResolvedValueOnce(txRejected('not the owner'));

    const { ops } = makeOps();
    const err = await ops.delete('sg', 'file-1').catch((e) => e);
    expect(err).toBeInstanceOf(WillowError);
    expect(err.code).toBe('TX_SUBMIT_FAILED');
    expect(err.message).toMatch(/not the owner/);
  });
});

describe('encryptFile / decryptFile', () => {
  it('round-trips with XChaCha20-Poly1305 and rejects a wrong key', () => {
    const key = new Uint8Array(32).fill(7);
    const plaintext = new TextEncoder().encode('secret payload');

    const { ciphertext, nonce } = encryptFile(plaintext, key);
    expect(nonce.length).toBe(24);
    expect(ciphertext.length).toBe(plaintext.length + 16); // + auth tag

    expect(decryptFile(ciphertext, key, nonce)).toEqual(plaintext);

    const wrongKey = new Uint8Array(32).fill(8);
    expect(() => decryptFile(ciphertext, wrongKey, nonce)).toThrow();
  });
});
