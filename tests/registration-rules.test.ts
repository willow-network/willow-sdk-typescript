/**
 * A data or file registration the chain refuses is refused before it is
 * signed: schema text its `serde_json` parse refuses (where `JSON.parse` is
 * more lenient), access lists that aren't DIDs, and a private DataStorage
 * registration whose initial key grant isn't the owner's first key.
 */
import { WillowClient } from '../src/client';
import { NonceAllocator } from '../src/consensus/nonces';
import { RegisterSubgroveTx, registerSubgroveSignMessage } from '../src/consensus/types';
import { WillowError } from '../src/types';

const OWNER = 'did:willow:a';
const KEY_ID = 'did:willow:a#key-1';

function refuses(f: () => unknown, code: string, pattern?: RegExp) {
  let caught: unknown;
  try {
    f();
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(WillowError);
  expect((caught as WillowError).code).toBe(code);
  if (pattern) expect((caught as WillowError).message).toMatch(pattern);
}

const modes = {
  data: { DataStorage: { name: 'notes' } },
  file: { FileStorage: { name: 'files', max_file_size: 1024, replication_factor: 1 } },
} as const;

function tx(overrides: Partial<RegisterSubgroveTx> = {}): RegisterSubgroveTx {
  return {
    subgroveId: 'notes-1',
    schema: '{}',
    ownerDid: OWNER,
    mode: modes.data,
    publicKeyId: KEY_ID,
    nonce: 1,
    ...overrides,
  };
}

describe('schema text, as the chain parses it', () => {
  it.each([
    ['a version written as a float', '{"version":1.0}'],
    ['a version written with an exponent', '{"version":1e0}'],
    ['a version of minus zero', '{"version":-0}'],
    ['a positional version written as a float', '[1.0]'],
    ['a key written twice', '{"version":1,"version":2}'],
    ['fields written twice', '{"fields":{},"fields":{}}'],
    ['a key escaped to read as another written twice', '{"version":1,"vers\\u0069on":1}'],
    ['a lone surrogate in a key the chain ignores', '{"\\ud800":1}'],
    ['a lone surrogate in a field name', '{"fields":{"\\udc00":"string"}}'],
    ['a lone surrogate in a required field', '{"required_fields":["\\ud800x"]}'],
    ['a field type object with its key written twice', '{"fields":{"a":{"string":null,"string":null}}}'],
    ['a field written twice, once with a bad type', '{"fields":{"a":"int","a":"string"}}'],
  ])('refuses %s', (_, schema) => {
    // JSON.parse takes each of these.
    expect(() => JSON.parse(schema)).not.toThrow();
    for (const mode of Object.values(modes)) {
      refuses(() => registerSubgroveSignMessage(tx({ mode, schema })), 'INVALID_SCHEMA');
    }
  });

  it.each([
    ['an integer version', '{"version":1}'],
    ['a version with whitespace', '{ "version" : 7 , "fields" : { "a" : "string" } }'],
    ['a key the chain ignores, written twice', '{"x":1,"x":2}'],
    ['a lone surrogate in a value the chain ignores', '{"x":"\\ud800"}'],
    ['a deeply nested value the chain ignores', `{"x":${'['.repeat(300)}${']'.repeat(300)},"version":1}`],
    ['a field written twice with valid types', '{"fields":{"a":"number","a":"string"}}'],
    ['an escaped key the chain reads', '{"vers\\u0069on":3}'],
    ['a surrogate pair', '{"fields":{"\\ud83d\\ude00":"string"},"required_fields":["\\ud83d\\ude00"]}'],
  ])('takes %s', (_, schema) => {
    for (const mode of Object.values(modes)) {
      expect(() => registerSubgroveSignMessage(tx({ mode, schema }))).not.toThrow();
    }
  });
});

describe('access lists are DIDs', () => {
  it.each([
    ['a writer', { writers: ['alice'] }],
    ['a free reader', { free_readers: ['bob bob'] }],
    ['a reader given as readers', { readers: ['did:willow:'] }],
    ['a writer with a second colon', { writers: ['did:willow:a:b'] }],
    ['a writer over 128 bytes', { writers: [`did:willow:${'x'.repeat(118)}`] }],
  ])('refuses %s that is not one', (_, lists) => {
    for (const [kind, fields] of Object.entries(modes)) {
      const mode = { [kind === 'data' ? 'DataStorage' : 'FileStorage']: { ...Object.values(fields)[0], ...lists } };
      refuses(() => registerSubgroveSignMessage(tx({ mode: mode as any })), 'INVALID_DID');
    }
  });

  it('refuses an admin that is not one', () => {
    for (const mode of Object.values(modes)) {
      refuses(() => registerSubgroveSignMessage(tx({ mode, admins: ['x'] })), 'INVALID_DID', /admins\[0\]/);
    }
  });

  it('takes DIDs', () => {
    const lists = { writers: [OWNER, 'did:willow:b_2'], free_readers: ['did:willow:C-3'] };
    for (const [kind, fields] of Object.entries(modes)) {
      const mode = { [kind === 'data' ? 'DataStorage' : 'FileStorage']: { ...Object.values(fields)[0], ...lists } };
      expect(() =>
        registerSubgroveSignMessage(tx({ mode: mode as any, admins: [`did:willow:${'x'.repeat(117)}`] })),
      ).not.toThrow();
    }
  });
});

describe("a private DataStorage registration's initial key grant", () => {
  const grant = {
    grantee_did: OWNER,
    key_epoch: 0,
    grantee_public_key_id: KEY_ID,
    ephemeral_public_key: new Array(32).fill(1),
    encrypted_key: new Array(72).fill(2),
    granted_by: OWNER,
    granted_at: 1_800_000_000,
  };
  const privacy = { allowed_indexers: null, commitment_frequency: 'EveryUpdate' };
  const priv = (g: object, overrides: Partial<RegisterSubgroveTx> = {}) =>
    tx({ privacy: privacy as any, initialOwnerKeyGrant: g as any, ...overrides });

  it("takes the owner's key epoch 0", () => {
    expect(() => registerSubgroveSignMessage(priv(grant))).not.toThrow();
  });

  it('refuses another epoch', () => {
    refuses(() => registerSubgroveSignMessage(priv({ ...grant, key_epoch: 1 })), 'INVALID_KEY_GRANT', /key_epoch must be 0/);
  });

  it('refuses a grant to someone else', () => {
    refuses(
      () => registerSubgroveSignMessage(priv({ ...grant, grantee_did: 'did:willow:b' })),
      'INVALID_KEY_GRANT',
      /must grant the owner/,
    );
  });

  it('refuses a grant to an owner that is not a DID', () => {
    const owner = 'did:willow:a:b';
    refuses(
      () =>
        registerSubgroveSignMessage(
          priv({ ...grant, grantee_did: owner }, { ownerDid: owner, mode: { DataStorage: { name: 'n', writers: [] } } }),
        ),
      'INVALID_DID',
      /grantee_did/,
    );
  });

  it('is not checked where the chain does not check it', () => {
    // A public DataStorage registration, or a FileStorage one, doesn't store the grant.
    const other = { ...grant, key_epoch: 5, grantee_did: 'did:willow:b' };
    expect(() => registerSubgroveSignMessage(tx({ initialOwnerKeyGrant: other as any }))).not.toThrow();
    expect(() =>
      registerSubgroveSignMessage(priv(other, { mode: modes.file })),
    ).not.toThrow();
  });
});

describe('client.registerSubgrove refuses before reading a nonce', () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it('sends nothing and reads no nonce for a writer that is not a DID', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;
    const client = new WillowClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator: new NonceAllocator(),
    });
    client.auth.setIdentity(OWNER, '03'.repeat(32), KEY_ID, 'Ed25519');
    await expect(
      client.registerSubgrove({
        dataset_id: 'sg-1',
        name: 'n',
        schema: { version: 1, fields: {} },
        owner_did: OWNER,
        writers: ['alice'],
        readers: [],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_DID' });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
