import * as fs from 'fs';
import * as path from 'path';
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  WillowAuth,
  signEd25519,
  signSecp256k1,
  verifyEd25519,
  verifySecp256k1,
} from '../src/auth';
import { WillowClient } from '../src/client';
import { ConsensusClient } from '../src/consensus/client';
import {
  createSignMessage,
  createTransactionWrapper,
  GrantSubgroveKeyTx,
  grantSubgroveKeySignMessage,
  RegisterSubgroveTx,
  registerSubgroveSignMessage,
  registerSubgroveUnsignedBincode,
  RotateSubgroveKeyTx,
  rotateSubgroveKeySignMessage,
  storeFileManifestSignMessage,
  UnregisterStorageNodeTx,
  unregisterStorageNodeSignMessage,
} from '../src/consensus/types';
import { FileOperations } from '../src/files';
import { toJson } from '../src/internal/json';
import { PrivacyOperations } from '../src/privacy';
import { NonceAllocator } from '../src/consensus/nonces';
import { WillowError } from '../src/types';
import { parseExactJson } from './helpers/exact-json';

/**
 * The second set of signed messages: RegisterSubgrove (`Config`, the SHA-256
 * of the transaction's bincode), GrantSubgroveKey, RotateSubgroveKey, and
 * UnregisterStorageNode. `signed_messages_kat_2.json` is the chain's own
 * known answers: each vector's `transaction_json` is the exact `/tx/submit`
 * body (signature empty), with the message, the RegisterSubgrove bincode,
 * and the Ed25519 and secp256k1 signatures by the key whose seed is 32 bytes
 * of 0x03.
 */

interface Kat2Vector {
  name: string;
  transaction_json: string;
  unsigned_bincode_hex: string | null;
  message: string;
  ed25519_signature_hex: string;
  secp256k1_keccak256_hex: string;
  secp256k1_compact_signature_hex: string;
}

const KAT = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'signed_messages_kat_2.json'), 'utf8'),
) as {
  private_key_seed_hex: string;
  public_key_id: string;
  ed25519_public_key_hex: string;
  secp256k1_public_key_compressed_hex: string;
  vectors: Kat2Vector[];
};

const SEED = KAT.private_key_seed_hex;
const ED_PUB = KAT.ed25519_public_key_hex;
const SECP_PUB = KAT.secp256k1_public_key_compressed_hex;
const OWNER = 'did:willow:a';

function vector(name: string): Kat2Vector {
  const v = KAT.vectors.find((x) => x.name === name);
  if (!v) throw new Error(`no KAT vector ${name}`);
  return v;
}

/** The kind and body of a vector's transaction, big integers kept exact. */
function body(v: Kat2Vector): [string, any] {
  const [entry] = Object.entries(parseExactJson(v.transaction_json));
  return entry as [string, any];
}

// --- The SDK's transaction types, from a wire body -----------------------

function registerTx(w: any): RegisterSubgroveTx {
  return {
    subgroveId: w.subgrove_id,
    name: w.name,
    description: w.description,
    schema: w.schema,
    ownerDid: w.owner_did,
    admins: w.admins,
    initialFunding: w.initial_funding === null ? undefined : String(w.initial_funding),
    checkpointVerification: w.checkpoint_verification,
    mode: w.mode,
    privacy: w.privacy,
    initialOwnerKeyGrant: w.initial_owner_key_grant,
    templateConfig: w.template_config,
    confirmationDepth: w.confirmation_depth,
    cryptographicCompleteness: w.cryptographic_completeness,
    publicKeyId: w.public_key_id,
    nonce: w.nonce,
  };
}

function grantTx(w: any): GrantSubgroveKeyTx {
  return {
    subgroveId: w.subgrove_id,
    encryptedKeyGrant: w.encrypted_key_grant,
    senderDid: w.sender_did,
    publicKeyId: w.public_key_id,
    nonce: w.nonce,
  };
}

function rotateTx(w: any): RotateSubgroveKeyTx {
  return {
    subgroveId: w.subgrove_id,
    newEpoch: w.new_epoch,
    newGrants: w.new_grants,
    senderDid: w.sender_did,
    publicKeyId: w.public_key_id,
    nonce: w.nonce,
  };
}

function unregisterTx(w: any): UnregisterStorageNodeTx {
  return { nodeDid: w.node_did, publicKeyId: w.public_key_id, nonce: w.nonce };
}

/** For each kind this SDK sends: its transaction from a body, and its builder. */
const SENT: Record<string, { tx: (w: any) => any; build: (tx: any) => string }> = {
  RegisterSubgrove: { tx: registerTx, build: registerSubgroveSignMessage },
  GrantSubgroveKey: { tx: grantTx, build: grantSubgroveKeySignMessage },
  RotateSubgroveKey: { tx: rotateTx, build: rotateSubgroveKeySignMessage },
  UnregisterStorageNode: { tx: unregisterTx, build: unregisterStorageNodeSignMessage },
};

/** The kinds this SDK has no transaction for. */
const NOT_SENT = [
  'UpdateSubgroveReadPricing',
  'BlockContentHash',
  'UnblockContentHash',
  'ReportContent',
];

/**
 * The body the SDK sends, as JSON text. The SDK sends `initial_funding` (a
 * u128 the chain decodes from a string or a number) as a decimal string;
 * the chain's own JSON writes it as a number. Nothing else differs.
 */
function sentJson(kind: string, tx: any): string {
  return toJson(createTransactionWrapper(kind, { ...tx, signature: '' }));
}

function asTheSdkSendsIt(transactionJson: string): string {
  return transactionJson.replace(/"initial_funding":(\d+)/, '"initial_funding":"$1"');
}

describe('second set of signed messages: known answers', () => {
  it('accounts for every vector', () => {
    const kinds = new Set(KAT.vectors.map((v) => body(v)[0]));
    expect([...kinds].sort()).toEqual([...Object.keys(SENT), ...NOT_SENT].sort());
  });

  it('derives the known public keys from the seed', () => {
    expect(bytesToHex(ed25519.getPublicKey(hexToBytes(SEED)))).toBe(ED_PUB);
    expect(bytesToHex(secp256k1.getPublicKey(hexToBytes(SEED), true))).toBe(SECP_PUB);
  });

  const sent = KAT.vectors.filter((v) => body(v)[0] in SENT).map((v) => v.name);

  describe.each(sent)('%s', (name) => {
    const v = vector(name);
    const [kind, w] = body(v);
    const tx = SENT[kind].tx(w);
    const message = SENT[kind].build(tx);

    it('builds the message byte for byte', () => {
      expect(message).toBe(v.message);
      expect(Buffer.from(message, 'utf8').equals(Buffer.from(v.message, 'utf8'))).toBe(true);
    });

    it('createSignMessage uses the same builder', () => {
      expect(createSignMessage(kind, tx)).toBe(v.message);
    });

    it('sends the known transaction JSON (the bytes the message covers)', () => {
      expect(sentJson(kind, tx)).toBe(asTheSdkSendsIt(v.transaction_json));
    });

    if (kind === 'RegisterSubgrove') {
      it('encodes the known unsigned bincode, which Config hashes', () => {
        const bincode = registerSubgroveUnsignedBincode(tx);
        expect(bytesToHex(bincode)).toBe(v.unsigned_bincode_hex);
        expect(v.message).toContain(`\nConfig: ${bytesToHex(sha256(bincode))}\n`);
      });
    }

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
});

describe('second set of signed messages: refusals', () => {
  const data = registerTx(body(vector('RegisterSubgrove (data)'))[1]);
  const indexing = registerTx(body(vector('RegisterSubgrove (indexing)'))[1]);
  const grant = grantTx(body(vector('GrantSubgroveKey'))[1]);
  const rotate = rotateTx(body(vector('RotateSubgroveKey'))[1]);
  const unregister = unregisterTx(body(vector('UnregisterStorageNode'))[1]);

  function refuses(build: () => unknown, code: string, pattern?: RegExp) {
    let err: unknown;
    try {
      build();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(WillowError);
    expect((err as WillowError).code).toBe(code);
    if (pattern) expect((err as WillowError).message).toMatch(pattern);
  }
  const lineBreak = (build: () => unknown) => refuses(build, 'LINE_BREAK_IN_SIGNED_FIELD');
  const invalid = (build: () => unknown, pattern?: RegExp) =>
    refuses(build, 'INVALID_SIGNED_FIELD', pattern);

  it.each(['subgroveId', 'ownerDid'] as const)('RegisterSubgrove refuses a line break in %s', (f) => {
    lineBreak(() => registerSubgroveSignMessage({ ...data, [f]: 'a\nb' }));
  });

  it('RegisterSubgrove hashes a line break in a field it does not write as a line', () => {
    const msg = registerSubgroveSignMessage({ ...data, description: 'two\nlines' });
    expect(msg.split('\n')).toHaveLength(5);
    expect(msg).not.toBe(vector('RegisterSubgrove (data)').message);
  });

  it.each([
    ['subgroveId', { subgroveId: 'a\nb' }],
    ['senderDid', { senderDid: 'a\nb' }],
    ['grantee_did', { encryptedKeyGrant: { ...grant.encryptedKeyGrant, grantee_did: 'a\nb' } }],
    [
      'grantee_public_key_id',
      { encryptedKeyGrant: { ...grant.encryptedKeyGrant, grantee_public_key_id: 'a\nb' } },
    ],
    ['granted_by', { encryptedKeyGrant: { ...grant.encryptedKeyGrant, granted_by: 'a\nb' } }],
  ])('GrantSubgroveKey refuses a line break in %s', (_f, change) => {
    lineBreak(() => grantSubgroveKeySignMessage({ ...grant, ...change }));
  });

  it('RotateSubgroveKey refuses a line break in any grant', () => {
    const grants = [...rotate.newGrants];
    grants[1] = { ...grants[1], grantee_did: 'did:willow:b\n' };
    lineBreak(() => rotateSubgroveKeySignMessage({ ...rotate, newGrants: grants }));
    lineBreak(() => rotateSubgroveKeySignMessage({ ...rotate, senderDid: 'a\nb' }));
  });

  it('UnregisterStorageNode refuses a line break in the node DID', () => {
    lineBreak(() => unregisterStorageNodeSignMessage({ ...unregister, nodeDid: 'did:willow:s\n' }));
  });

  it('refuses CRLF but signs a lone CR verbatim, as the chain does', () => {
    lineBreak(() => unregisterStorageNodeSignMessage({ ...unregister, nodeDid: 'a\r\nb' }));
    expect(unregisterStorageNodeSignMessage({ ...unregister, nodeDid: 'a\rb' })).toBe(
      'UnregisterStorageNode\nNode: a\rb\nNonce: 14',
    );
  });

  it('refuses a text field holding a lone surrogate, which has no UTF-8 form', () => {
    invalid(() => registerSubgroveSignMessage({ ...data, name: 'bad \ud800' }), /surrogate/);
    invalid(() => grantSubgroveKeySignMessage({ ...grant, senderDid: '\udc00' }), /surrogate/);
    // A surrogate pair is one character, and fine.
    expect(() => registerSubgroveSignMessage({ ...data, name: 'tree \u{1F333}' })).not.toThrow();
  });

  it('refuses to sign without a nonce, or with an unsafe one', () => {
    for (const nonce of [undefined, -1, 1.5, 2 ** 53]) {
      expect(() => registerSubgroveSignMessage({ ...data, nonce })).toThrow(WillowError);
      expect(() => grantSubgroveKeySignMessage({ ...grant, nonce })).toThrow(WillowError);
      expect(() => rotateSubgroveKeySignMessage({ ...rotate, nonce })).toThrow(WillowError);
      expect(() => unregisterStorageNodeSignMessage({ ...unregister, nonce })).toThrow(WillowError);
    }
  });

  it('refuses an integer outside its type rather than wrap or round it', () => {
    const g = grant.encryptedKeyGrant;
    invalid(() =>
      grantSubgroveKeySignMessage({ ...grant, encryptedKeyGrant: { ...g, key_epoch: 2 ** 32 } }),
    );
    invalid(() =>
      grantSubgroveKeySignMessage({ ...grant, encryptedKeyGrant: { ...g, granted_at: 2 ** 53 } }),
    );
    invalid(() =>
      grantSubgroveKeySignMessage({
        ...grant,
        encryptedKeyGrant: { ...g, ephemeral_public_key: [1, 256] },
      }),
    );
    invalid(() => rotateSubgroveKeySignMessage({ ...rotate, newEpoch: 2 ** 32 }));
    invalid(() => registerSubgroveSignMessage({ ...data, confirmationDepth: 2 ** 32 }));
    invalid(() => registerSubgroveSignMessage({ ...data, initialFunding: (1n << 128n).toString() }));
    invalid(() => registerSubgroveSignMessage({ ...data, initialFunding: '-1' }));
    invalid(() => registerSubgroveSignMessage({ ...data, initialFunding: '0x10' }));

    const mode = (indexing.mode as any).BlockchainIndexing;
    const withMode = (m: any) => ({ ...indexing, mode: { BlockchainIndexing: { ...mode, ...m } } });
    invalid(() =>
      registerSubgroveSignMessage(
        withMode({ execution_mode: { IndexerExecution: { sampling_rate_percent: 256 } } }),
      ),
    );
    invalid(() =>
      registerSubgroveSignMessage(
        withMode({ indexer_config: { ...mode.indexer_config, min_indexer_stake: 1n << 128n } }),
      ),
    );
    // An unsafe number may already be rounded; the same value as a bigint is exact.
    invalid(() =>
      registerSubgroveSignMessage(
        withMode({ indexer_config: { ...mode.indexer_config, reward_per_epoch: 2 ** 61 } }),
      ),
    );
    expect(() =>
      registerSubgroveSignMessage(
        withMode({ indexer_config: { ...mode.indexer_config, reward_per_epoch: 1n << 61n } }),
      ),
    ).not.toThrow();
  });

  it('refuses a mode it cannot encode', () => {
    invalid(() => registerSubgroveSignMessage({ ...data, mode: { Archive: {} } as any }), /mode/);
    const mode = (indexing.mode as any).BlockchainIndexing;
    const { execution_mode: _e, ...noExecution } = mode;
    invalid(() =>
      registerSubgroveSignMessage({ ...indexing, mode: { BlockchainIndexing: noExecution } }),
    );
    const { indexer_config: _c, ...noConfig } = mode;
    invalid(() =>
      registerSubgroveSignMessage({ ...indexing, mode: { BlockchainIndexing: noConfig } }),
    );
    invalid(() =>
      registerSubgroveSignMessage({
        ...indexing,
        mode: { BlockchainIndexing: { ...mode, execution_mode: 'Everyone' } },
      }),
    );
  });

  it('refuses a retention window on a mode that has none', () => {
    invalid(
      () => registerSubgroveSignMessage({ ...data, retention_window: { type: 'Blocks', value: 100 } }),
      /BlockchainIndexing/,
    );
  });

  it('puts a transaction-level retention window into the indexing mode it signs', () => {
    const mode = { ...(indexing.mode as any).BlockchainIndexing };
    delete mode.retention_window;
    const viaTx = {
      ...indexing,
      mode: { BlockchainIndexing: mode },
      retention_window: { type: 'Blocks' as const, value: 1000 },
    };
    expect(registerSubgroveSignMessage(viaTx)).toBe(vector('RegisterSubgrove (indexing)').message);
    expect(
      createTransactionWrapper('RegisterSubgrove', viaTx).RegisterSubgrove.mode.BlockchainIndexing
        .retention_window,
    ).toEqual({ Blocks: 1000 });
  });
});

describe('file manifest chunk fields are u32', () => {
  const manifest = {
    subgroveId: 'files-1',
    fileKey: 'photo.png',
    ownerDid: OWNER,
    filename: 'photo.png',
    contentType: 'image/png',
    totalSize: 1048577,
    contentHash: '11'.repeat(32),
    chunkCount: 2,
    chunkSize: 1048576,
    chunkMerkleRoot: '22'.repeat(32),
    nonce: 9,
  };

  it.each(['chunkCount', 'chunkSize'] as const)(
    'refuses %s above 2^32 - 1, in the message and on the wire',
    (field) => {
      const tx = { ...manifest, [field]: 2 ** 32 };
      expect(() => storeFileManifestSignMessage(tx)).toThrow(/outside u32/);
      expect(() => createTransactionWrapper('StoreFileManifest', tx)).toThrow(/outside u32/);
    },
  );

  it('signs and sends 2^32 - 1', () => {
    const tx = { ...manifest, chunkCount: 2 ** 32 - 1, chunkSize: 2 ** 32 - 1 };
    expect(storeFileManifestSignMessage(tx)).toContain(
      '\nChunkCount: 4294967295\nChunkSize: 4294967295\n',
    );
    const w = createTransactionWrapper('StoreFileManifest', tx).StoreFileManifest;
    expect([w.chunk_count, w.chunk_size]).toEqual([4294967295, 4294967295]);
  });
});

// ---------------------------------------------------------------------------
// Flows: the transaction sent is the known one, and carries the known
// signature over the message its own fields give.
// ---------------------------------------------------------------------------

function accepted() {
  const ok = { success: true, data: { tx_hash: 'AB12', code: 0, log: '' } };
  return {
    ok: true,
    status: 200,
    json: async () => ok,
    text: async () => JSON.stringify(ok),
  } as unknown as Response;
}

/**
 * A fetch that answers the account nonce with `current` (so the next nonce
 * is `current + 1`), accepts every transaction, and records each body sent
 * to /tx/submit as its exact text.
 */
function stubFetch(current: number) {
  const submitted: string[] = [];
  const urls: string[] = [];
  const fetchMock = jest.fn(async (url: string, init?: RequestInit) => {
    urls.push(url);
    if (url.includes('/nonce')) {
      const nonce = { success: true, data: { nonce: current } };
      return {
        ok: true,
        status: 200,
        json: async () => nonce,
        text: async () => JSON.stringify(nonce),
      } as unknown as Response;
    }
    if (url.endsWith('/tx/submit')) submitted.push(init!.body as string);
    return accepted();
  });
  global.fetch = fetchMock as unknown as typeof fetch;
  return { submitted, urls, fetchMock };
}

/** A sent body with its signature emptied, and the signature as hex. */
function unsigned(sentText: string): { json: string; signature: string; kind: string; w: any } {
  const parsed = parseExactJson(sentText);
  const [[kind, w]] = Object.entries(parsed) as [string, any][];
  const signature = bytesToHex(Uint8Array.from(w.signature));
  return { json: toJson({ [kind]: { ...w, signature: [] } }), signature, kind, w };
}

describe('second set in flight', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  const ed = { privateKey: SEED, publicKeyId: KAT.public_key_id };
  const secp = { ...ed, signFunction: signSecp256k1 };
  const schema = JSON.stringify({ version: 1, fields: {}, indexes: [], required_fields: [] });

  function consensus() {
    return new ConsensusClient({ apiUrl: 'http://api.test', consensusRpcUrl: 'http://rpc.test', nonceAllocator: new NonceAllocator() });
  }

  it('consensus.registerSubgrove sends the known data registration, every field explicit', async () => {
    const v = vector('RegisterSubgrove (data, defaults)');
    const { submitted } = stubFetch(3);
    await consensus().registerSubgrove('sg-1', schema, OWNER, ed, {
      name: '',
      mode: { DataStorage: { name: '', writers: [], free_readers: [] } },
    });

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v.ed25519_signature_hex);
    expect(registerSubgroveSignMessage(registerTx(sent.w))).toBe(v.message);
  });

  it('consensus.registerSubgrove sends the known file registration under secp256k1', async () => {
    const v = vector('RegisterSubgrove (file)');
    const { submitted } = stubFetch(4);
    await consensus().registerSubgrove('files-1', schema, OWNER, secp, {
      name: 'Files',
      initialFunding: '1',
      mode: {
        FileStorage: {
          name: 'Files',
          max_file_size: 104857600,
          replication_factor: 3,
          writers: [OWNER],
          free_readers: [],
        },
      },
    });

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(asTheSdkSendsIt(v.transaction_json));
    expect(sent.w.signature).toHaveLength(64);
    expect(sent.signature).toBe(v.secp256k1_compact_signature_hex);
  });

  it('consensus.registerSubgrove signs an indexing mode, sending u128s above 2^64 exactly', async () => {
    const { submitted } = stubFetch(9);
    await consensus().registerSubgrove('idx-9', schema, OWNER, ed, {
      mode: {
        BlockchainIndexing: {
          manifest_content: new TextEncoder().encode('specVersion: 1.0.0'),
          execution_mode: 'ConsensusExecution',
          indexer_config: {
            min_indexers: 1,
            max_indexers: 3,
            reward_per_epoch: '2000000000000000000',
            min_indexer_stake: 10n ** 22n,
          },
        },
      },
      retentionWindow: { type: 'Seconds', value: 3600 },
    });

    expect(submitted[0]).toContain('"min_indexer_stake":10000000000000000000000');
    expect(submitted[0]).toContain('"reward_per_epoch":2000000000000000000');
    expect(submitted[0]).toContain('"epoch_length":100');
    expect(submitted[0]).toContain('"retention_window":{"Seconds":3600}');
    expect(submitted[0]).not.toContain('"retention_window":{"type"');
    const sent = unsigned(submitted[0]);
    expect(sent.w.nonce).toBe(10);
    const message = registerSubgroveSignMessage(registerTx(sent.w));
    expect(message.split('\n')).toEqual([
      'RegisterSubgrove',
      'Subgrove: idx-9',
      `Owner: ${OWNER}`,
      expect.stringMatching(/^Config: [0-9a-f]{64}$/),
      'Nonce: 10',
    ]);
    expect(verifyEd25519(message, sent.signature, ED_PUB)).toBe(true);
  });

  it('client.registerSubgrove signs with a secp256k1 identity\'s own key (the known answer)', async () => {
    const v = vector('RegisterSubgrove (data, defaults)');
    const { submitted } = stubFetch(3);
    const client = new WillowClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator: new NonceAllocator(),
    });
    client.auth.setIdentity(OWNER, SEED, KAT.public_key_id, 'secp256k1');
    await client.registerSubgrove({
      dataset_id: 'sg-1',
      name: '',
      schema: { version: 1, fields: {}, indexes: [], required_fields: [] },
      owner_did: OWNER,
      writers: [],
      readers: [],
    });

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v.secp256k1_compact_signature_hex);
    expect(verifySecp256k1(v.message, `0x${sent.signature}`, SECP_PUB)).toBe(true);
    expect(verifyEd25519(v.message, sent.signature, ED_PUB)).toBe(false);
  });

  it('client.data.registerSubgrove sends a RegisterSubgrove transaction, not a REST call', async () => {
    const v = vector('RegisterSubgrove (data, defaults)');
    const { submitted, urls } = stubFetch(3);
    const client = new WillowClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator: new NonceAllocator(),
    });
    client.auth.setIdentity(OWNER, SEED, KAT.public_key_id, 'Ed25519');
    await client.data.registerSubgrove({
      dataset_id: 'sg-1',
      name: '',
      schema: { version: 1, fields: {}, indexes: [], required_fields: [] },
      owner_did: OWNER,
      writers: [],
      readers: [],
    });

    expect(urls.some((u) => u.includes('/register/subgrove'))).toBe(false);
    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v.ed25519_signature_hex);
  });

  function privacy(algorithm: 'Ed25519' | 'secp256k1') {
    const auth = new WillowAuth('http://api.test');
    auth.setIdentity(OWNER, SEED, KAT.public_key_id, algorithm);
    return new PrivacyOperations('http://api.test', auth, SEED, KAT.public_key_id, undefined, new NonceAllocator());
  }

  it.each([
    ['Ed25519', 'ed25519_signature_hex'],
    ['secp256k1', 'secp256k1_compact_signature_hex'],
  ] as const)('privacy.grantSubgroveKey sends the known grant (%s)', async (alg, sigField) => {
    const v = vector('GrantSubgroveKey');
    const [, w] = body(v);
    const { submitted } = stubFetch(w.nonce - 1);
    await privacy(alg).grantSubgroveKey(w.subgrove_id, w.encrypted_key_grant);

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v[sigField]);
  });

  it('privacy.rotateSubgroveKey sends the known rotation, every grant signed', async () => {
    const v = vector('RotateSubgroveKey');
    const [, w] = body(v);
    const { submitted } = stubFetch(w.nonce - 1);
    await privacy('Ed25519').rotateSubgroveKey(w.subgrove_id, w.new_epoch, w.new_grants);

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v.ed25519_signature_hex);
  });

  it('files.unregisterStorageNode sends the known removal', async () => {
    const v = vector('UnregisterStorageNode');
    const [, w] = body(v);
    const { submitted } = stubFetch(0);
    await new FileOperations('http://api.test', () => ({})).unregisterStorageNode(w.node_did, {
      ownerDid: w.node_did,
      privateKey: SEED,
      publicKeyId: w.public_key_id,
      signFunction: signEd25519,
      nonce: w.nonce,
    });

    const sent = unsigned(submitted[0]);
    expect(sent.json).toBe(v.transaction_json);
    expect(sent.signature).toBe(v.ed25519_signature_hex);
  });

  it('privacy.grantSubgroveKey refuses a grant with a line break and sends nothing', async () => {
    const [, w] = body(vector('GrantSubgroveKey'));
    const { submitted } = stubFetch(0);
    await expect(
      privacy('Ed25519').grantSubgroveKey(w.subgrove_id, {
        ...w.encrypted_key_grant,
        granted_by: 'did:willow:a\n',
      }),
    ).rejects.toThrow(/line break/);
    expect(submitted).toHaveLength(0);
  });
});
