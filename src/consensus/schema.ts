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
 * - `version`: a u32 (default 1).
 * - `fields`: field name to field type (default `{}`, any JSON object). A
 *   field type is one of `string`, `number`, `boolean`, `array`, `object`,
 *   `bytes`, written as that lowercase string.
 * - `indexes`: a list of `{ name, fields, unique }` (default `[]`). A data or
 *   file subgrove's schema can't declare one: writes to it are refused.
 * - `required_fields`: field names (default `[]`).
 *
 * The chain ignores any other key and refuses a `null` for any of these. It
 * refuses a registration whose schema it can't parse in its block, which
 * spends the nonce.
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

/**
 * Whether `value` is a field type as the chain parses one: its lowercase
 * name, or that name as the one key of an object whose value is `null`
 * (the other form a unit enum variant takes in the chain's JSON).
 */
function isChainFieldType(value: unknown): boolean {
  if (isFieldType(value)) return true;
  if (!isObject(value)) return false;
  const entries = Object.entries(value);
  return entries.length === 1 && isFieldType(entries[0][0]) && entries[0][1] === null;
}

/**
 * Refuse schema JSON text the chain would not parse as a DataStorage or
 * FileStorage schema, or one that declares indexes. The text is checked as
 * `JSON.parse` reads it: an object (or the chain's positional array form,
 * `[version, fields, indexes, required_fields]`) whose `version` is an
 * integer in u32, `fields` an object of field types, `indexes` an empty
 * array, and `required_fields` an array of strings; each may be left out,
 * and any other key is ignored, as the chain does.
 *
 * @throws WillowError `INVALID_SCHEMA` or `SCHEMA_INDEXES_UNSUPPORTED`.
 */
export function checkStorageSchema(schema: string): void {
  let parsed: unknown;
  try {
    parsed = JSON.parse(schema);
  } catch {
    throw invalidSchema('The schema is not JSON');
  }
  let parts: Record<string, unknown>;
  if (Array.isArray(parsed)) {
    if (parsed.length > 4) {
      throw invalidSchema('A schema written as an array has at most 4 elements');
    }
    const keys = ['version', 'fields', 'indexes', 'required_fields'];
    parts = Object.fromEntries(parsed.map((v, i) => [keys[i], v]));
  } else if (isObject(parsed)) {
    parts = parsed;
  } else {
    throw invalidSchema('The schema must be a JSON object');
  }
  const has = (key: string) => Object.prototype.hasOwnProperty.call(parts, key);

  if (has('version')) {
    const v = parts.version;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0 || v > 0xffff_ffff) {
      throw invalidSchema(`schema.version must be an integer in u32, got ${JSON.stringify(v)}`);
    }
  }
  if (has('indexes')) {
    if (!Array.isArray(parts.indexes)) throw invalidSchema('schema.indexes must be an array');
    if (parts.indexes.length > 0) throw indexesUnsupported();
  }
  if (has('fields')) {
    const fields = parts.fields;
    if (!isObject(fields)) throw invalidSchema('schema.fields must be an object');
    for (const [field, value] of Object.entries(fields)) {
      const label = `schema.fields[${JSON.stringify(fieldName(field))}]`;
      if (!isChainFieldType(value)) throw fieldTypeError(label, value);
    }
  }
  if (has('required_fields')) names('schema.required_fields', parts.required_fields);
}
