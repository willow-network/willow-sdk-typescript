import * as fs from 'fs';
import * as path from 'path';
import { verifyEd25519 } from '../src/auth';
import { WillowClient } from '../src/client';
import { NonceAllocator } from '../src/consensus/nonces';
import { serializeSchema, SCHEMA_FIELD_TYPES } from '../src/consensus/schema';
import { RegisterSubgroveTx, registerSubgroveSignMessage } from '../src/consensus/types';
import { SchemaDefinition, WillowError } from '../src/types';
import { parseExactJson } from './helpers/exact-json';

/**
 * A DataStorage or FileStorage registration carries its schema as JSON text,
 * which the chain parses as its `SchemaDefinition`:
 *
 * ```rust
 * #[derive(Serialize, Deserialize)]
 * pub struct SchemaDefinition {
 *     #[serde(default = "default_schema_version")] // 1
 *     pub version: u32,
 *     #[serde(default)]
 *     pub fields: BTreeMap<String, FieldType>,
 *     #[serde(default)]
 *     pub indexes: Vec<IndexDefinition>, // { name: String, fields: Vec<String>, unique: bool }
 *     #[serde(default)]
 *     pub required_fields: Vec<String>,
 * }
 *
 * #[derive(Serialize, Deserialize)]
 * #[serde(rename_all = "lowercase")]
 * pub enum FieldType { String, Number, Boolean, Array, Object, Bytes }
 * ```
 *
 * In its block the chain refuses a registration whose schema doesn't parse
 * ("Invalid schema JSON"), and the refusal spends the nonce.
 */

const KAT = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'signed_messages_kat_2.json'), 'utf8'),
);
const SEED = KAT.private_key_seed_hex as string;
const ED_PUB = KAT.ed25519_public_key_hex as string;
const OWNER = 'did:willow:a';

/**
 * The chain's parse of a data or file schema followed by `serde_json`'s
 * write of what it parsed, written by hand from the definition above (an
 * object form only): each key defaults when absent; a field type is one of
 * the six lowercase names; the four fields are written in declaration order
 * and the map in its key order (UTF-8 bytes, which `Buffer.compare`
 * orders).
 */
function chainRoundTrip(text: string): string {
  const v = JSON.parse(text);
  if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not a struct');
  const version = 'version' in v ? v.version : 1;
  if (!Number.isInteger(version) || version < 0 || version > 0xffffffff) throw new Error('version');
  const fields = 'fields' in v ? v.fields : {};
  if (fields === null || typeof fields !== 'object' || Array.isArray(fields)) throw new Error('fields');
  for (const t of Object.values(fields)) {
    if (!['string', 'number', 'boolean', 'array', 'object', 'bytes'].includes(t as string)) {
      throw new Error(`unknown variant ${JSON.stringify(t)}`);
    }
  }
  const indexes = 'indexes' in v ? v.indexes : [];
  if (!Array.isArray(indexes) || indexes.length !== 0) throw new Error('indexes');
  const required = 'required_fields' in v ? v.required_fields : [];
  if (!Array.isArray(required) || !required.every((r: unknown) => typeof r === 'string')) {
    throw new Error('required_fields');
  }
  const keys = Object.keys(fields).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const map = keys.map((k) => `${JSON.stringify(k)}:${JSON.stringify(fields[k])}`).join(',');
  return `{"version":${version},"fields":{${map}},"indexes":[],"required_fields":${JSON.stringify(required)}}`;
}

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

describe('serializeSchema', () => {
  it("writes the chain's own default schema text for an empty schema", () => {
    // The chain's known answers carry the schema text it writes for the default schema.
    const chainDefault = parseExactJson(
      KAT.vectors.find((v: any) => v.name === 'RegisterSubgrove (data)').transaction_json,
    ).RegisterSubgrove.schema;
    expect(chainDefault).toBe('{"version":1,"fields":{},"indexes":[],"required_fields":[]}');
    expect(serializeSchema({ version: 1, fields: {} })).toBe(chainDefault);
    expect(serializeSchema({ version: 1, fields: {}, indexes: [], required_fields: [] })).toBe(
      chainDefault,
    );
    // An absent version is the chain's default, 1.
    expect(serializeSchema({ fields: {} } as unknown as SchemaDefinition)).toBe(chainDefault);
    expect(serializeSchema(undefined as unknown as SchemaDefinition)).toBe(chainDefault);
  });

  it("sends the SDK's field objects as the chain's field types", () => {
    // serde_json::to_string(&SchemaDefinition { version: 1, fields: {title: String,
    // value: Number}, indexes: [], required_fields: ["title"] }), by hand.
    const expected =
      '{"version":1,"fields":{"title":"string","value":"number"},"indexes":[],"required_fields":["title"]}';
    expect(
      serializeSchema({
        version: 1,
        fields: { value: { type: 'number' }, title: { type: 'string' } },
        required_fields: ['title'],
      }),
    ).toBe(expected);
    // `required: true` puts the field in `required_fields`.
    expect(
      serializeSchema({
        version: 1,
        fields: { value: { type: 'number', required: false }, title: { type: 'string', required: true } },
      }),
    ).toBe(expected);
    // The chain's own form, and the two forms mixed.
    expect(
      serializeSchema({ version: 1, fields: { title: 'string', value: 'number' }, required_fields: ['title'] }),
    ).toBe(expected);
    expect(
      serializeSchema({ version: 1, fields: { title: { type: 'string', required: true }, value: 'number' } }),
    ).toBe(expected);
  });

  it('maps each of the six field types to itself', () => {
    expect([...SCHEMA_FIELD_TYPES]).toEqual(['string', 'number', 'boolean', 'array', 'object', 'bytes']);
    for (const t of SCHEMA_FIELD_TYPES) {
      const want = `{"version":1,"fields":{"f":"${t}"},"indexes":[],"required_fields":[]}`;
      expect(serializeSchema({ version: 1, fields: { f: t } })).toBe(want);
      expect(serializeSchema({ version: 1, fields: { f: { type: t } } })).toBe(want);
    }
  });

  it("writes the fields in the chain's map order, by code point", () => {
    // JS orders integer-like keys first; UTF-16 order puts U+10000 before U+FFFF.
    const fields = { b: 'string', '\u{10000}': 'bytes', B: 'number', '￿': 'array', '10': 'object', '2': 'boolean' } as const;
    const sent = serializeSchema({ version: 1, fields });
    expect(sent).toBe(
      '{"version":1,"fields":{"10":"object","2":"boolean","B":"number","b":"string",' +
        '"￿":"array","\u{10000}":"bytes"},"indexes":[],"required_fields":[]}',
    );
    expect(chainRoundTrip(sent)).toBe(sent);
  });

  it('keeps the listed required fields in order and adds the flagged ones after them', () => {
    expect(
      serializeSchema({
        version: 1,
        fields: { c: { type: 'string', required: true }, a: { type: 'string', required: true }, b: 'string' },
        required_fields: ['b', 'c'],
      }),
    ).toBe('{"version":1,"fields":{"a":"string","b":"string","c":"string"},"indexes":[],"required_fields":["b","c","a"]}');
  });

  it('writes a version anywhere in u32 and refuses one outside it', () => {
    for (const version of [0, 7, 0xffffffff]) {
      expect(serializeSchema({ version, fields: {} })).toBe(
        `{"version":${version},"fields":{},"indexes":[],"required_fields":[]}`,
      );
    }
    for (const version of [-1, 1.5, 2 ** 32, Number.NaN]) {
      refuses(() => serializeSchema({ version, fields: {} }), 'INVALID_SCHEMA');
    }
  });

  it('refuses a field type the chain has no variant for', () => {
    for (const bad of ['int', 'String', 'date', '', 1, null, [], { kind: 'string' }, { type: 'text' }]) {
      refuses(
        () => serializeSchema({ version: 1, fields: { f: bad as any } }),
        'INVALID_SCHEMA',
        /string, number, boolean, array, object, bytes/,
      );
    }
    refuses(() => serializeSchema({ version: 1, fields: [] as any }), 'INVALID_SCHEMA');
    refuses(() => serializeSchema({ version: 1, fields: { f: { type: 'string', required: 'yes' as any } } }), 'INVALID_SCHEMA');
    refuses(() => serializeSchema({ version: 1, fields: {}, required_fields: [1 as any] }), 'INVALID_SCHEMA');
    refuses(() => serializeSchema({ version: 1, fields: { ['\ud800']: 'string' } }), 'INVALID_SCHEMA', /surrogate/);
  });

  it('refuses indexes and fields marked indexed, which a data or file schema cannot have', () => {
    refuses(
      () => serializeSchema({ version: 1, fields: { f: { type: 'string', indexed: true } } }),
      'SCHEMA_INDEXES_UNSUPPORTED',
    );
    refuses(
      () =>
        serializeSchema({
          version: 1,
          fields: { f: 'string' },
          indexes: [{ name: 'by_f', fields: ['f'], unique: false }],
        }),
      'SCHEMA_INDEXES_UNSUPPORTED',
    );
    expect(serializeSchema({ version: 1, fields: { f: { type: 'string', indexed: false } } })).toBe(
      '{"version":1,"fields":{"f":"string"},"indexes":[],"required_fields":[]}',
    );
  });

  it('writes a field named __proto__ as a field', () => {
    const fields = JSON.parse('{"__proto__":"string"}');
    expect(serializeSchema({ version: 1, fields })).toBe(
      '{"version":1,"fields":{"__proto__":"string"},"indexes":[],"required_fields":[]}',
    );
  });

  it('round-trips every schema it writes through the chain\'s parse and write', () => {
    const schemas: SchemaDefinition[] = [
      { version: 1, fields: {} },
      { version: 3, fields: { name: { type: 'string', required: true }, score: 'number', active: 'boolean' } },
      { version: 1, fields: { tags: 'array', meta: 'object', blob: 'bytes', 'é': 'string' }, required_fields: ['tags', 'tags'] },
      { version: 1, fields: { 'a"b\\c\n': 'string' }, required_fields: ['a"b\\c\n'] },
    ];
    for (const s of schemas) {
      const sent = serializeSchema(s);
      expect(chainRoundTrip(sent)).toBe(sent);
      expect(() => registerSubgroveSignMessage({ ...dataTx(), schema: sent })).not.toThrow();
    }
  });
});

function dataTx(): RegisterSubgroveTx {
  return {
    subgroveId: 'notes-1',
    schema: '{}',
    ownerDid: OWNER,
    mode: { DataStorage: { name: 'notes' } },
    publicKeyId: KAT.public_key_id,
    nonce: 1,
  };
}

describe("a data or file registration's schema text", () => {
  const modes = {
    data: { DataStorage: { name: 'notes' } },
    file: { FileStorage: { name: 'files', max_file_size: 1024, replication_factor: 1 } },
  } as const;

  it.each([
    '{}',
    '[]',
    '{"version":0,"fields":{"a":"string"},"indexes":[],"required_fields":["a"]}',
    '{"fields":{"a":"bytes","b":"object"}}',
    '{"version":4294967295}',
    // The other JSON form of a unit variant: its name as an object's one key, valued null.
    '{"fields":{"a":{"string":null}}}',
    // A struct's positional form: [version, fields, indexes, required_fields].
    '[2,{"a":"number"},[],["a"]]',
    // Keys the chain doesn't read are ignored.
    '{"description":"x","fields":{}}',
  ])('takes %s, which the chain parses', (schema) => {
    for (const mode of Object.values(modes)) {
      expect(() => registerSubgroveSignMessage({ ...dataTx(), mode, schema })).not.toThrow();
    }
  });

  it.each([
    'not json',
    '"text"',
    '1',
    'null',
    // The field shape the SDK used to send.
    '{"fields":{"name":{"type":"string"}}}',
    '{"fields":{"a":"String"}}',
    '{"fields":{"a":"int"}}',
    '{"fields":{"a":null}}',
    '{"fields":{"a":{"string":1}}}',
    '{"fields":{"a":{"string":null,"number":null}}}',
    '{"fields":[]}',
    '{"fields":null}',
    '{"version":null}',
    '{"version":-1}',
    '{"version":4294967296}',
    '{"version":1.5}',
    '{"version":"1"}',
    '{"indexes":{}}',
    '{"indexes":null}',
    '{"required_fields":[1]}',
    '{"required_fields":"a"}',
    '{"required_fields":null}',
    '[1,{},[],[],5]',
    '{"fields":{"\\ud800":"string"}}',
  ])('refuses %s, which the chain does not parse', (schema) => {
    for (const mode of Object.values(modes)) {
      refuses(() => registerSubgroveSignMessage({ ...dataTx(), mode, schema }), 'INVALID_SCHEMA');
    }
  });

  it('refuses a schema that declares an index', () => {
    const schema = '{"fields":{"a":"string"},"indexes":[{"name":"i","fields":["a"],"unique":false}]}';
    for (const mode of Object.values(modes)) {
      refuses(() => registerSubgroveSignMessage({ ...dataTx(), mode, schema }), 'SCHEMA_INDEXES_UNSUPPORTED');
    }
  });
});

describe('client.registerSubgrove sends the schema in the chain\'s shape', () => {
  const originalFetch = global.fetch;
  afterEach(() => {
    global.fetch = originalFetch;
  });

  function stubFetch(current: number) {
    const submitted: string[] = [];
    global.fetch = jest.fn(async (url: string, init?: RequestInit) => {
      const body = url.includes('/nonce')
        ? { success: true, data: { nonce: current } }
        : { success: true, data: { tx_hash: 'AB12', code: 0, log: '' } };
      if (url.endsWith('/tx/submit')) submitted.push(init!.body as string);
      return {
        ok: true,
        status: 200,
        json: async () => body,
        text: async () => JSON.stringify(body),
      } as unknown as Response;
    }) as unknown as typeof fetch;
    return submitted;
  }

  function client(allocator = new NonceAllocator()) {
    const c = new WillowClient({
      apiUrl: 'http://api.test',
      consensusRpcUrl: 'http://rpc.test',
      nonceAllocator: allocator,
    });
    c.auth.setIdentity(OWNER, SEED, KAT.public_key_id, 'Ed25519');
    return c;
  }

  const request = {
    dataset_id: 'users',
    name: 'Users',
    schema: {
      version: 1,
      fields: {
        name: { type: 'string' as const, required: true },
        score: { type: 'number' as const },
        active: 'boolean' as const,
      },
    },
    owner_did: OWNER,
    writers: [OWNER],
    readers: [],
  };

  it('converts the fields, and signs the schema it sends', async () => {
    const submitted = stubFetch(3);
    await client().registerSubgrove(request);

    expect(submitted).toHaveLength(1);
    const w = parseExactJson(submitted[0]).RegisterSubgrove;
    expect(w.schema).toBe(
      '{"version":1,"fields":{"active":"boolean","name":"string","score":"number"},"indexes":[],"required_fields":["name"]}',
    );
    expect(chainRoundTrip(w.schema)).toBe(w.schema);
    // The signature verifies over the message built from the fields sent.
    const message = registerSubgroveSignMessage({
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
    });
    const signature = Buffer.from(w.signature as number[]).toString('hex');
    expect(verifyEd25519(message, signature, ED_PUB)).toBe(true);
  });

  it('refuses a field type the chain has none of without sending anything or taking a nonce', async () => {
    const submitted = stubFetch(3);
    const c = client();
    await expect(
      c.registerSubgrove({ ...request, schema: { version: 1, fields: { when: { type: 'date' as any } } } }),
    ).rejects.toMatchObject({ code: 'INVALID_SCHEMA' });
    await expect(
      c.registerSubgrove({ ...request, schema: { version: 1, fields: { name: { type: 'string', indexed: true } } } }),
    ).rejects.toMatchObject({ code: 'SCHEMA_INDEXES_UNSUPPORTED' });
    expect(submitted).toHaveLength(0);
    await c.registerSubgrove(request);
    expect(parseExactJson(submitted[0]).RegisterSubgrove.nonce).toBe(4);
  });

  it("consensus.registerSubgrove refuses schema text the chain can't parse", async () => {
    const submitted = stubFetch(3);
    const c = client();
    await expect(
      c.consensus.registerSubgrove(
        'users',
        JSON.stringify({ version: 1, fields: { name: { type: 'string' } } }),
        OWNER,
        c.auth.transactionSigner(),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_SCHEMA' });
    expect(submitted).toHaveLength(0);
  });
});
