/**
 * The schema of a DataStorage or FileStorage subgrove, as the chain reads it.
 *
 * A registration carries its schema as JSON text, which the chain parses as
 * its `SchemaDefinition`:
 *
 * ```
 * { "version": 1, "fields": { "title": "string" }, "indexes": [], "required_fields": ["title"] }
 * ```
 *
 * - `version`: a u32 (default 1), written as an integer (`1`, not `1.0`).
 * - `fields`: field name to field type (default `{}`, any JSON object). A
 *   field type is one of `string`, `number`, `boolean`, `array`, `object`,
 *   `bytes`, written as that lowercase string.
 * - `indexes`: a list of `{ name, fields, unique }` (default `[]`). A data or
 *   file subgrove's schema can't declare one: writes to it are refused.
 * - `required_fields`: field names (default `[]`).
 *
 * The chain ignores any other key and refuses a `null` for any of these, a
 * key written twice, or a string holding a lone UTF-16 surrogate. It refuses
 * a registration whose schema it can't parse in its block, which spends the
 * nonce.
 */

import type { SchemaDefinition, SchemaFieldType } from '../types';
import { WillowError } from '../types';
import { isWellFormed, uint } from './fields';

/** The chain's field types, as a schema writes them. */
export const SCHEMA_FIELD_TYPES: readonly SchemaFieldType[] = [
  'string',
  'number',
  'boolean',
  'array',
  'object',
  'bytes',
];

const INVALID = 'INVALID_SCHEMA';

function invalidSchema(message: string): WillowError {
  return new WillowError(message, INVALID);
}

function indexesUnsupported(): WillowError {
  return new WillowError(
    "Schema indexes are not supported: a data or file subgrove's schema can't declare indexes",
    'SCHEMA_INDEXES_UNSUPPORTED',
  );
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isFieldType(value: unknown): value is SchemaFieldType {
  return typeof value === 'string' && (SCHEMA_FIELD_TYPES as readonly string[]).includes(value);
}

function fieldTypeError(label: string, value: unknown): WillowError {
  return invalidSchema(
    `${label} is ${JSON.stringify(value) ?? String(value)}: a field's type is one of ` +
      `${SCHEMA_FIELD_TYPES.join(', ')}`,
  );
}

function name(label: string, value: unknown): string {
  if (typeof value !== 'string') throw invalidSchema(`${label} must be a string`);
  if (!isWellFormed(value)) throw invalidSchema(`${label} holds a lone UTF-16 surrogate`);
  return value;
}

/** A field's name: a string with a UTF-8 encoding. */
function fieldName(field: string): string {
  if (!isWellFormed(field)) {
    throw invalidSchema(`schema.fields names a field with a lone UTF-16 surrogate`);
  }
  return field;
}

function names(label: string, value: unknown): string[] {
  if (!Array.isArray(value)) throw invalidSchema(`${label} must be an array of strings`);
  return value.map((v, i) => name(`${label}[${i}]`, v));
}

/**
 * The order of the chain's field map (a `BTreeMap<String, _>`): by Unicode
 * code point, which is the order of the names' UTF-8 bytes.
 */
function codePointOrder(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    const d = x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * The JSON text of a DataStorage or FileStorage schema, in the shape the
 * chain parses: `{"version":…,"fields":{…},"indexes":[],"required_fields":[…]}`,
 * every key written out, the fields in the chain's order. It is the text the
 * chain writes back for the schema it parses from it.
 *
 * A field's type is the chain's own string (`'string'`) or a
 * {@link FieldType} (`{ type: 'string' }`), sent as its `type`; a field with
 * `required: true` is added to `required_fields`. An absent `version` is the
 * chain's default, 1.
 *
 * @throws WillowError `INVALID_SCHEMA` for a field type the chain has no
 *   variant for, a `version` outside u32, or a value of the wrong kind;
 *   `SCHEMA_INDEXES_UNSUPPORTED` for a schema that declares indexes or a
 *   field marked `indexed: true` (the chain's schema has no per-field index,
 *   and a data or file subgrove's schema can't declare indexes).
 */
export function serializeSchema(schema: SchemaDefinition): string {
  const s: unknown = schema ?? {};
  if (!isObject(s)) throw invalidSchema('schema must be an object');

  let version: bigint = 1n;
  if (s.version !== undefined && s.version !== null) {
    try {
      version = uint('schema.version', s.version, 32);
    } catch (e) {
      throw invalidSchema((e as Error).message);
    }
  }

  if (s.indexes !== undefined && s.indexes !== null) {
    if (!Array.isArray(s.indexes)) throw invalidSchema('schema.indexes must be an array');
    if (s.indexes.length > 0) throw indexesUnsupported();
  }

  const required =
    s.required_fields === undefined || s.required_fields === null
      ? []
      : names('schema.required_fields', s.required_fields);

  const fieldsIn = s.fields === undefined || s.fields === null ? {} : s.fields;
  if (!isObject(fieldsIn)) throw invalidSchema('schema.fields must be an object');
  const fields: Array<[string, SchemaFieldType]> = [];
  for (const [field, value] of Object.entries(fieldsIn)) {
    const label = `schema.fields[${JSON.stringify(fieldName(field))}]`;
    if (typeof value === 'string') {
      if (!isFieldType(value)) throw fieldTypeError(label, value);
      fields.push([field, value]);
    } else if (isObject(value)) {
      if (!isFieldType(value.type)) throw fieldTypeError(`${label}.type`, value.type);
      for (const flag of ['indexed', 'required'] as const) {
        const v = value[flag];
        if (v !== undefined && v !== null && typeof v !== 'boolean') {
          throw invalidSchema(`${label}.${flag} must be a boolean`);
        }
      }
      if (value.indexed === true) throw indexesUnsupported();
      fields.push([field, value.type]);
    } else {
      throw invalidSchema(
        `${label} must be a field type (one of ${SCHEMA_FIELD_TYPES.join(', ')}) or { type }`,
      );
    }
  }
  fields.sort(([a], [b]) => codePointOrder(a, b));
  for (const [field] of fields) {
    const value = fieldsIn[field];
    if (isObject(value) && value.required === true && !required.includes(field)) {
      required.push(field);
    }
  }

  const fieldsJson = fields.map(([f, t]) => `${JSON.stringify(f)}:${JSON.stringify(t)}`).join(',');
  return (
    `{"version":${version},"fields":{${fieldsJson}},"indexes":[],` +
    `"required_fields":${JSON.stringify(required)}}`
  );
}

/** The keys the chain's schema reads, in the order its positional form takes them. */
const SCHEMA_KEYS = ['version', 'fields', 'indexes', 'required_fields'] as const;
type SchemaKey = (typeof SCHEMA_KEYS)[number];

const U32_MAX = 4294967295n;

/**
 * A reader over JSON text that sees what `JSON.parse` hides: each number's
 * own token, every key of an object (repeats included), and each string as
 * written. `JSON.parse` has already accepted the text, so it is well-formed.
 */
class JsonText {
  private i = 0;

  constructor(private readonly s: string) {}

  ws(): void {
    while (this.i < this.s.length && ' \t\n\r'.includes(this.s[this.i])) this.i++;
  }

  /** The next character after whitespace, not consumed. */
  peek(): string {
    this.ws();
    return this.s[this.i] ?? '';
  }

  /** Consume `token` if it comes next. */
  eat(token: string): boolean {
    this.ws();
    if (this.s.startsWith(token, this.i)) {
      this.i += token.length;
      return true;
    }
    return false;
  }

  /** The raw text of the string token that comes next. */
  private stringToken(): string {
    this.ws();
    const start = this.i;
    let j = start + 1;
    while (j < this.s.length && this.s[j] !== '"') j += this.s[j] === '\\' ? 2 : 1;
    this.i = j + 1;
    return this.s.slice(start, this.i);
  }

  /** The string that comes next, decoded (a `\u` escape may decode to a lone surrogate). */
  string(): string {
    return JSON.parse(this.stringToken()) as string;
  }

  /** The number token that comes next, as written. */
  number(): string {
    this.ws();
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i));
    const token = m ? m[0] : '';
    this.i += token.length;
    return token;
  }

  /** Skip the value that comes next, however deeply nested. */
  skip(): void {
    let depth = 0;
    do {
      const c = this.peek();
      if (c === '') throw invalidSchema('The schema is not JSON');
      if (c === '"') this.stringToken();
      else if (c === '{' || c === '[') {
        depth++;
        this.i++;
      } else if (c === '}' || c === ']') {
        depth--;
        this.i++;
      } else if (c === ',' || c === ':') this.i++;
      else {
        while (this.i < this.s.length && !' \t\n\r,:]}'.includes(this.s[this.i])) this.i++;
      }
    } while (depth > 0);
  }

  /**
   * Read the object that comes next, calling `entry` with each key (repeats
   * included, in order) to read its value. False when no object comes next.
   */
  object(entry: (key: string) => void): boolean {
    if (!this.eat('{')) return false;
    if (this.eat('}')) return true;
    do {
      const key = this.string();
      this.eat(':');
      entry(key);
    } while (this.eat(','));
    this.eat('}');
    return true;
  }

  /** Read the array that comes next, calling `item` with each index. False when no array comes next. */
  array(item: (index: number) => void): boolean {
    if (!this.eat('[')) return false;
    if (this.eat(']')) return true;
    let index = 0;
    do {
      item(index++);
    } while (this.eat(','));
    this.eat(']');
    return true;
  }
}

/** Refuse a string the chain's parser refuses: one holding a lone surrogate (from a `\u` escape). */
function wellFormed(label: string, value: string): string {
  if (!isWellFormed(value)) throw invalidSchema(`${label} holds a lone UTF-16 surrogate`);
  return value;
}

function readVersion(json: JsonText): void {
  const c = json.peek();
  const token = c === '-' || (c >= '0' && c <= '9') ? json.number() : null;
  // The chain reads a u32 from an integer token only: `1.0`, `1e0`, and `-0`
  // are floats to it, and a negative number is outside u32.
  if (token === null || !/^(?:0|[1-9][0-9]*)$/.test(token) || BigInt(token) > U32_MAX) {
    throw invalidSchema(
      `schema.version must be an integer in u32 written as one (no sign, fraction, or exponent), ` +
        `got ${token ?? 'a value that is not a number'}`,
    );
  }
}

/**
 * A field's type, as the chain parses one: its lowercase name, or that name
 * as the one key of an object whose value is `null` (the other form a unit
 * enum variant takes in the chain's JSON).
 */
function readFieldType(json: JsonText, label: string): void {
  const c = json.peek();
  if (c === '"') {
    const name = json.string();
    if (!isFieldType(name)) throw fieldTypeError(label, name);
    return;
  }
  let entries = 0;
  const isObject = json.object((variant) => {
    entries++;
    if (!isFieldType(variant) || !json.eat('null')) {
      throw invalidSchema(
        `${label} must be a field type (one of ${SCHEMA_FIELD_TYPES.join(', ')}), ` +
          'or one such name as an object\'s one key valued null',
      );
    }
  });
  if (!isObject || entries !== 1) {
    throw invalidSchema(
      `${label} must be a field type (one of ${SCHEMA_FIELD_TYPES.join(', ')}), ` +
        "or one such name as an object's one key valued null",
    );
  }
}

function readSchemaPart(json: JsonText, key: SchemaKey): void {
  switch (key) {
    case 'version':
      readVersion(json);
      return;
    case 'fields':
      if (
        !json.object((field) => {
          const label = `schema.fields[${JSON.stringify(fieldName(field))}]`;
          readFieldType(json, label);
        })
      ) {
        throw invalidSchema('schema.fields must be an object');
      }
      return;
    case 'indexes':
      if (json.peek() !== '[') throw invalidSchema('schema.indexes must be an array');
      if (!json.eat('[') || !json.eat(']')) throw indexesUnsupported();
      return;
    case 'required_fields':
      if (
        !json.array((i) => {
          if (json.peek() !== '"') throw invalidSchema(`schema.required_fields[${i}] must be a string`);
          wellFormed(`schema.required_fields[${i}]`, json.string());
        })
      ) {
        throw invalidSchema('schema.required_fields must be an array of strings');
      }
      return;
  }
}

/**
 * Refuse schema JSON text the chain would not parse as a DataStorage or
 * FileStorage schema, or one that declares indexes. The text is read as the
 * chain's `serde_json` parse of its `SchemaDefinition` reads it: an object
 * (or the positional array form, `[version, fields, indexes,
 * required_fields]`, at most 4 elements) in which
 *
 * - `version` is an integer token in u32 (`1`, not `1.0`, `1e0`, `-0`, or
 *   `"1"`);
 * - `fields` is an object of field types; `indexes` an empty array;
 *   `required_fields` an array of strings;
 * - none of these keys appears twice;
 * - no key, field name, field type, or required field holds a lone UTF-16
 *   surrogate (a `\u` escape of one).
 *
 * Each of the four may be left out, and any other key is ignored (its value
 * is not read), as the chain does. A field named twice in `fields` is read
 * both times, the later one kept.
 *
 * @throws WillowError `INVALID_SCHEMA` or `SCHEMA_INDEXES_UNSUPPORTED`.
 */
export function checkStorageSchema(schema: string): void {
  try {
    JSON.parse(schema);
  } catch {
    throw invalidSchema('The schema is not JSON');
  }
  const json = new JsonText(schema);
  const c = json.peek();
  if (c === '{') {
    const seen = new Set<string>();
    json.object((key) => {
      wellFormed('A schema key', key);
      if (!(SCHEMA_KEYS as readonly string[]).includes(key)) {
        json.skip();
        return;
      }
      if (seen.has(key)) throw invalidSchema(`The schema has the key ${JSON.stringify(key)} twice`);
      seen.add(key);
      readSchemaPart(json, key as SchemaKey);
    });
  } else if (c === '[') {
    json.array((i) => {
      if (i >= SCHEMA_KEYS.length) {
        throw invalidSchema('A schema written as an array has at most 4 elements');
      }
      readSchemaPart(json, SCHEMA_KEYS[i]);
    });
  } else {
    throw invalidSchema('The schema must be a JSON object');
  }
}
