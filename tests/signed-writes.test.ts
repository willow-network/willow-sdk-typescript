import * as fs from 'fs';
import * as path from 'path';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  signEd25519,
  signSecp256k1,
  verifyEd25519,
  verifySecp256k1,
} from '../src/auth';
import { ConsensusClient } from '../src/consensus/client';
import {
  createSignMessage,
  DataStoreTx,
  DeleteFileManifestTx,
  deleteFileManifestSignMessage,
  StoreFileManifestTx,
  storeDataSignMessage,
  storeFileManifestSignMessage,
} from '../src/consensus/types';
import { FileOperations } from '../src/files';
import { WillowError } from '../src/types';

/**
 * The messages StoreData, StoreFileManifest, and DeleteFileManifest are
 * signed over. `signed_messages_kat.json` holds the chain's own known
 * answers: for each vector the inputs, the exact message, and its Ed25519
 * and secp256k1 signatures by the key whose seed is 32 bytes of 0x03.
 */

interface KatVector {
  name: string;
  inputs: Record<string, any>;
  message: string;
  ed25519_signature_hex: string;
  secp256k1_keccak256_hex: string;
  secp256k1_compact_signature_hex: string;
}

const KAT = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'signed_messages_kat.json'), 'utf8'),
) as {
  private_key_seed_hex: string;
  public_key_id: string;
  ed25519_public_key_hex: string;
  secp256k1_public_key_compressed_hex: string;
  vectors: KatVector[];
};

const SEED = KAT.private_key_seed_hex;
const ED_PUB = KAT.ed25519_public_key_hex;
const SECP_PUB = KAT.secp256k1_public_key_compressed_hex;

function vector(name: string): KatVector {
  const v = KAT.vectors.find((x) => x.name === name);
  if (!v) throw new Error(`no KAT vector ${name}`);
  return v;
}

function dataStoreTx(i: Record<string, any>): DataStoreTx {
  return {
    subgroveId: i.subgrove_id,
    key: i.key,
    ownerDid: i.owner_did,
    data: i.data_utf8,
    nonce: i.nonce,
  };
}

function manifestTx(i: Record<string, any>): StoreFileManifestTx {
  return {
    subgroveId: i.subgrove_id,
    fileKey: i.file_key,
    ownerDid: i.owner_did,
    filename: i.filename,
    contentType: i.content_type,
    totalSize: i.total_size,
    contentHash: i.content_hash_hex,
    chunkCount: i.chunk_count,
    chunkSize: i.chunk_size,
    chunkMerkleRoot: i.chunk_merkle_root_hex,
    nonce: i.nonce,
  };
}

function deleteFileTx(i: Record<string, any>): DeleteFileManifestTx {
  return {
    subgroveId: i.subgrove_id,
    fileKey: i.file_key,
    ownerDid: i.owner_did,
    nonce: i.nonce,
  };
}

/** The vectors for the kinds this SDK sends, with its builder for each. */
const SENT: Record<string, (i: Record<string, any>) => string> = {
  StoreData: (i) => storeDataSignMessage(dataStoreTx(i)),
  StoreFileManifest: (i) => storeFileManifestSignMessage(manifestTx(i)),
  DeleteFileManifest: (i) => deleteFileManifestSignMessage(deleteFileTx(i)),
};

/**
 * The vectors this SDK has no transaction for: it sends no UpdateData or
 * DeleteData, and no `encryption` on a file manifest.
 */
const NOT_SENT = ['UpdateData', 'DeleteData', 'StoreFileManifest (encrypted)'];

describe('signed data and file write messages: known answers', () => {
  it('accounts for every vector', () => {
    expect(KAT.vectors.map((v) => v.name).sort()).toEqual(
      [...Object.keys(SENT), ...NOT_SENT].sort(),
    );
  });

  it('derives the known public keys from the seed', () => {
    expect(bytesToHex(ed25519.getPublicKey(hexToBytes(SEED)))).toBe(ED_PUB);
    expect(bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), true))).toBe(SECP_PUB);
  });

  describe.each(Object.keys(SENT))('%s', (name) => {
    const v = vector(name);
    const message = SENT[name](v.inputs);

    it('builds the message byte for byte', () => {
      expect(message).toBe(v.message);
      expect(Buffer.from(message, 'utf8').equals(Buffer.from(v.message, 'utf8'))).toBe(true);
    });

    it('signs it with Ed25519 to the known signature', () => {
      expect(signEd25519(message, SEED)).toBe(v.ed25519_signature_hex);
      expect(verifyEd25519(message, v.ed25519_signature_hex, ED_PUB)).toBe(true);
    });

    it('signs it with secp256k1 (Keccak-256, lower-S) to the known signature', () => {
      expect(bytesToHex(keccak_256(new TextEncoder().encode(message)))).toBe(
        v.secp256k1_keccak256_hex,
      );
      const sig = signSecp256k1(message, SEED);
      expect(sig).toBe(`0x${v.secp256k1_compact_signature_hex}`);
      expect(verifySecp256k1(message, sig, SECP_PUB)).toBe(true);
    });
  });

  it('createSignMessage uses the same builders', () => {
    expect(createSignMessage('DataStore', dataStoreTx(vector('StoreData').inputs))).toBe(
      vector('StoreData').message,
    );
    expect(
      createSignMessage('StoreFileManifest', manifestTx(vector('StoreFileManifest').inputs)),
    ).toBe(vector('StoreFileManifest').message);
    expect(
      createSignMessage('DeleteFileManifest', deleteFileTx(vector('DeleteFileManifest').inputs)),
    ).toBe(vector('DeleteFileManifest').message);
  });
});

describe('signed data and file write messages: refusals', () => {
  const store = dataStoreTx(vector('StoreData').inputs);
  const manifest = manifestTx(vector('StoreFileManifest').inputs);
  const del = deleteFileTx(vector('DeleteFileManifest').inputs);

  function refusesLineBreak(build: () => string) {
    let err: unknown;
    try {
      build();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WillowError);
    expect((err as WillowError).code).toBe('LINE_BREAK_IN_SIGNED_FIELD');
  }

  it.each(['subgroveId', 'key', 'ownerDid'] as const)(
    'StoreData refuses a line break in %s',
    (field) => {
      refusesLineBreak(() => storeDataSignMessage({ ...store, [field]: 'a\nb' }));
    },
  );

  it.each(['subgroveId', 'fileKey', 'ownerDid', 'filename', 'contentType'] as const)(
    'StoreFileManifest refuses a line break in %s',
    (field) => {
      refusesLineBreak(() => storeFileManifestSignMessage({ ...manifest, [field]: 'a\nb' }));
    },
  );

  it.each(['subgroveId', 'fileKey', 'ownerDid'] as const)(
    'DeleteFileManifest refuses a line break in %s',
    (field) => {
      refusesLineBreak(() => deleteFileManifestSignMessage({ ...del, [field]: 'a\nb' }));
    },
  );

  it('signs a line break inside the data, which is hashed', () => {
    const msg = storeDataSignMessage({ ...store, data: '"a\\nb\nc"' });
    expect(msg.split('\n')).toHaveLength(6);
  });

  it('refuses a missing or non-integer nonce', () => {
    for (const nonce of [undefined, -1, 1.5, Number.NaN, 2 ** 53]) {
      expect(() => storeDataSignMessage({ ...store, nonce })).toThrow(WillowError);
      expect(() => storeFileManifestSignMessage({ ...manifest, nonce })).toThrow(WillowError);
      expect(() => deleteFileManifestSignMessage({ ...del, nonce })).toThrow(WillowError);
    }
  });

  it('writes the 32-byte digests as lowercase hex, however they are given', () => {
    const msg = storeFileManifestSignMessage({
      ...manifest,
      contentHash: `0x${'AB'.repeat(32)}`,
      chunkMerkleRoot: 'Cd'.repeat(32),
    });
    expect(msg).toContain(`\nContentHash: ${'ab'.repeat(32)}\n`);
    expect(msg).toContain(`\nChunkMerkleRoot: ${'cd'.repeat(32)}\n`);
  });

  it('refuses a digest that is not 32 bytes of hex', () => {
    for (const bad of ['11'.repeat(31), '11'.repeat(33), 'zz'.repeat(32), '']) {
      expect(() => storeFileManifestSignMessage({ ...manifest, contentHash: bad })).toThrow(
        WillowError,
      );
      expect(() => storeFileManifestSignMessage({ ...manifest, chunkMerkleRoot: bad })).toThrow(
        WillowError,
      );
    }
  });

  it('refuses a size or chunk count that is not a non-negative integer', () => {
    expect(() => storeFileManifestSignMessage({ ...manifest, totalSize: -1 })).toThrow(WillowError);
    expect(() => storeFileManifestSignMessage({ ...manifest, chunkCount: 1.5 })).toThrow(
      WillowError,
    );
    expect(() => storeFileManifestSignMessage({ ...manifest, chunkSize: Number.NaN })).toThrow(
      WillowError,
    );
  });
});

// ---------------------------------------------------------------------------
// Flows: the transaction sent carries a signature over the line-form message
// of its own wire fields, nonce included. The messages are rebuilt here from
// the wire JSON, independently of the SDK's builders.
// ---------------------------------------------------------------------------

function wireMessage(kind: string, w: any): string {
  const digest = (bytes: number[]) => bytesToHex(Uint8Array.from(bytes));
  switch (kind) {
    case 'StoreData':
      return [
        'StoreData',
        `Subgrove: ${w.subgrove_id}`,
        `Key: ${w.key}`,
        `Owner: ${w.owner_did}`,
        `DataHash: ${bytesToHex(sha256(Uint8Array.from(w.data)))}`,
        `Nonce: ${w.nonce}`,
      ].join('\n');
    case 'StoreFileManifest':
      return [
        'StoreFileManifest',
        `Subgrove: ${w.subgrove_id}`,
        `Key: ${w.file_key}`,
        `Owner: ${w.owner_did}`,
        `Filename: ${w.filename}`,
        `ContentType: ${w.content_type}`,
        `TotalSize: ${w.total_size}`,
        `ContentHash: ${digest(w.content_hash)}`,
        `ChunkCount: ${w.chunk_count}`,
        `ChunkSize: ${w.chunk_size}`,
        `ChunkMerkleRoot: ${digest(w.chunk_merkle_root)}`,
        `Encryption: ${w.encryption == null ? 'none' : `${w.encryption.key_epoch}:${digest(w.encryption.nonce)}`}`,
        `Nonce: ${w.nonce}`,
      ].join('\n');
    case 'DeleteFileManifest':
      return [
        'DeleteFileManifest',
        `Subgrove: ${w.subgrove_id}`,
        `Key: ${w.file_key}`,
        `Owner: ${w.owner_did}`,
        `Nonce: ${w.nonce}`,
      ].join('\n');
    default:
      throw new Error(kind);
  }
}

/** The signature bytes a wire transaction carries, as hex. */
function wireSignatureHex(w: any): string {
  return bytesToHex(Uint8Array.from(w.signature));
}

function accepted() {
  const body = { success: true, data: { tx_hash: 'AB12', code: 0, log: '' } };
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => JSON.stringify(body),
    arrayBuffer: async () => new ArrayBuffer(0),
  } as unknown as Response;
}

/**
 * A fetch that answers the account nonce with `current` (so the next nonce
 * is `current + 1`), accepts every transaction, and records the bodies sent
 * to /tx/submit.
 */
function stubFetch(current: number) {
  const submitted: any[] = [];
  const fetchMock = jest.fn(async (url: string, init?: RequestInit) => {
    if (url.includes('/nonce')) {
      return {
        ok: true,
        status: 200,
        json: async () => ({ success: true, data: { nonce: current } }),
      } as unknown as Response;
    }
    if (url.endsWith('/tx/submit')) {
      submitted.push(JSON.parse(init!.body as string));
    }
    return accepted();
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  return { submitted, fetchMock };
}

describe('signed writes in flight', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  function client() {
    return new ConsensusClient({ apiUrl: 'http://api.test', consensusRpcUrl: 'http://rpc.test' });
  }

  const ed = { privateKey: SEED, publicKeyId: KAT.public_key_id };
  const secp = { ...ed, signFunction: signSecp256k1 };

  it('storeData signs the line form at the nonce it sends (the known answer)', async () => {
    const v = vector('StoreData');
    const { submitted } = stubFetch(v.inputs.nonce - 1);
    await client().storeData(
      v.inputs.subgrove_id,
      v.inputs.key,
      JSON.parse(v.inputs.data_utf8),
      v.inputs.owner_did,
      ed,
    );

    const w = submitted[0].StoreData;
    expect(w.nonce).toBe(v.inputs.nonce);
    expect(new TextDecoder().decode(Uint8Array.from(w.data))).toBe(v.inputs.data_utf8);
    expect(wireMessage('StoreData', w)).toBe(v.message);
    expect(wireSignatureHex(w)).toBe(v.ed25519_signature_hex);
    expect(verifyEd25519(wireMessage('StoreData', w), wireSignatureHex(w), ED_PUB)).toBe(true);
  });

  it('storeData under secp256k1 sends the known compact signature', async () => {
    const v = vector('StoreData');
    const { submitted } = stubFetch(v.inputs.nonce - 1);
    await client().storeData(
      v.inputs.subgrove_id,
      v.inputs.key,
      JSON.parse(v.inputs.data_utf8),
      v.inputs.owner_did,
      secp,
    );

    const w = submitted[0].StoreData;
    expect(w.signature).toHaveLength(64);
    expect(wireSignatureHex(w)).toBe(v.secp256k1_compact_signature_hex);
    expect(
      verifySecp256k1(wireMessage('StoreData', w), `0x${wireSignatureHex(w)}`, SECP_PUB),
    ).toBe(true);
  });

  it('storeData hashes non-ASCII data as the UTF-8 bytes it sends', async () => {
    const { submitted } = stubFetch(41);
    await client().storeData('sg-1', 'doc1', { name: 'Zoë 🌳' }, 'did:willow:a', ed);

    const w = submitted[0].StoreData;
    expect(w.nonce).toBe(42);
    expect(verifyEd25519(wireMessage('StoreData', w), wireSignatureHex(w), ED_PUB)).toBe(true);
  });

  it('storeFileManifest signs every manifest field and the nonce (the known answer)', async () => {
    const v = vector('StoreFileManifest');
    const { submitted } = stubFetch(v.inputs.nonce - 1);
    const { nonce: _nonce, ...fields } = manifestTx(v.inputs);
    await client().storeFileManifest(fields, ed);

    const w = submitted[0].StoreFileManifest;
    expect(w.nonce).toBe(v.inputs.nonce);
    expect(w.encryption).toBeUndefined();
    expect(wireMessage('StoreFileManifest', w)).toBe(v.message);
    expect(wireSignatureHex(w)).toBe(v.ed25519_signature_hex);
  });

  it('deleteFileManifest signs the nonce it sends (the known answer)', async () => {
    const v = vector('DeleteFileManifest');
    const { submitted } = stubFetch(v.inputs.nonce - 1);
    await client().deleteFileManifest(
      v.inputs.subgrove_id,
      v.inputs.file_key,
      v.inputs.owner_did,
      ed,
    );

    const w = submitted[0].DeleteFileManifest;
    expect(w.nonce).toBe(v.inputs.nonce);
    expect(wireMessage('DeleteFileManifest', w)).toBe(v.message);
    expect(wireSignatureHex(w)).toBe(v.ed25519_signature_hex);
  });

  it('storeData refuses a key with a line break and sends nothing', async () => {
    const { submitted } = stubFetch(0);
    await expect(
      client().storeData('sg-1', 'doc\n1', { a: 1 }, 'did:willow:a', ed),
    ).rejects.toThrow(/line break/);
    expect(submitted).toHaveLength(0);
  });

  function files() {
    return new FileOperations('http://api.test', () => ({}));
  }

  const signing = (nonce: number, signFunction = signEd25519) => ({
    ownerDid: 'did:willow:a',
    privateKey: SEED,
    publicKeyId: KAT.public_key_id,
    signFunction,
    nonce,
  });

  it('files.upload signs the manifest it sends, every field and the nonce', async () => {
    const { submitted } = stubFetch(0);
    const data = new Uint8Array(262_144 + 5).fill(9); // two chunks
    await files().upload('files-1', 'blob.bin', 'blob.bin', data, 'http://node.test', signing(23));

    const w = submitted[0].StoreFileManifest;
    expect(w.nonce).toBe(23);
    expect(w.owner_did).toBe('did:willow:a');
    expect(w.chunk_count).toBe(2);
    const message = wireMessage('StoreFileManifest', w);
    expect(message).toContain('\nFilename: blob.bin\nContentType: application/octet-stream\n');
    expect(message).toContain(`\nContentHash: ${bytesToHex(sha256(data))}\n`);
    expect(verifyEd25519(message, wireSignatureHex(w), ED_PUB)).toBe(true);
    expect(storeFileManifestSignMessage({
      subgroveId: 'files-1',
      fileKey: 'blob.bin',
      ownerDid: 'did:willow:a',
      filename: 'blob.bin',
      contentType: 'application/octet-stream',
      totalSize: data.length,
      contentHash: bytesToHex(sha256(data)),
      chunkCount: 2,
      chunkSize: 262_144,
      chunkMerkleRoot: bytesToHex(Uint8Array.from(w.chunk_merkle_root)),
      nonce: 23,
    })).toBe(message);
  });

  it('files.upload under secp256k1 sends a compact signature over the line form', async () => {
    const { submitted } = stubFetch(0);
    const data = new TextEncoder().encode('{"hello":"world"}');
    await files().upload('files-1', 'doc', 'doc.json', data, 'http://node.test',
      signing(5, signSecp256k1));

    const w = submitted[0].StoreFileManifest;
    expect(w.signature).toHaveLength(64);
    expect(
      verifySecp256k1(wireMessage('StoreFileManifest', w), `0x${wireSignatureHex(w)}`, SECP_PUB),
    ).toBe(true);
  });

  it('files.upload refuses a file key with a line break and sends nothing', async () => {
    const { fetchMock } = stubFetch(0);
    const data = new TextEncoder().encode('x');
    await expect(
      files().upload('files-1', 'a\nb', 'doc.json', data, 'http://node.test', signing(1)),
    ).rejects.toThrow(/line break/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('files.delete signs the line form at the nonce it sends (the known answer)', async () => {
    const v = vector('DeleteFileManifest');
    const { submitted } = stubFetch(0);
    await files().delete(v.inputs.subgrove_id, v.inputs.file_key, signing(v.inputs.nonce));

    const w = submitted[0].DeleteFileManifest;
    expect(w.nonce).toBe(v.inputs.nonce);
    expect(wireMessage('DeleteFileManifest', w)).toBe(v.message);
    expect(wireSignatureHex(w)).toBe(v.ed25519_signature_hex);
  });
});
