/**
 * Verifying a query's whole result: the documents `POST /query/:subgrove`
 * returns are exactly the ones the API's query selects, in its order, from
 * the subgrove's data as the proof proves it.
 *
 * With a proof, the API proves the whole data tree (a `range_full` query on
 * the subgrove's data path) and selects from every item in it: each item that
 * parses as JSON, kept when it matches every exact-match filter (numbers by
 * exact decimal value), sorted by the one sort field (stably, in a total
 * order by kind), then `offset` and `limit` (default 100) applied. `total` is
 * the number selected before `offset` and `limit`. This module requires the
 * proof to reveal every entry of the data tree, runs that selection over them
 * as the API does, and requires the response's documents and `total` to be
 * it.
 *
 * A query the API refuses throws {@link QueryRefusedError} before anything is
 * sent (see {@link queryRefusal}). A query whose selection can't be
 * reproduced exactly (a filter value holding an object whose first key is
 * serde_json's private token) throws {@link QueryNotVerifiableError}, before
 * anything is sent. The proof's completeness and root are checked before the
 * selection is run, so a selection the data makes irreproducible (a document
 * the API's JSON reader may read differently) is reported, as
 * {@link QueryResultNotVerifiableError}, only for data at a checked root.
 */

import { QueryRequest, QueryResponse, WillowError } from '../types';
import { verifyCompleteLayer, CompleteEntry, hashToHex, bytesToHex } from '../grovedb';
import {
  NodeJson,
  NotReproducibleError,
  parseF64,
  parseNodeJson,
  parseNodeJsonText,
  nodeJsonEqual,
  nodeJsonTextLength,
  nodeJsonToJs,
  utf8Length,
} from './node-json';
import {
  decodeProofBytes,
  encodePath,
  enforceExpectedRoot,
  isExactJsonNumber,
  jsonDeepEqual,
  subgroveDataPath,
} from './shared';

/** The number of documents the API returns when a query gives no `limit`. */
export const DEFAULT_QUERY_LIMIT = 100;

const U32_MAX = 0xffff_ffff;

/** The keys of a `POST /query/:subgrove` body the API reads; it refuses any other. */
const QUERY_KEYS = new Set(['filters', 'search', 'sort', 'limit', 'offset', 'include_proof', 'includes']);

/** The most `filters` fields the API takes. */
const MAX_FILTER_FIELDS = 32;
/** The longest a filter value may be, as the API's JSON text of it. */
const MAX_FILTER_VALUE_BYTES = 4096;
/** The longest a filter field or the sort field may be. */
const MAX_FIELD_BYTES = 256;
/** MongoDB's logical operators, which the API refuses as filter fields. */
const LOGICAL_OPERATORS = new Set(['$and', '$or', '$not', '$nor']);

/**
 * A query the API refuses (code `QUERY_REFUSED`), so it is not sent:
 * `client.query` and `client.queryUnverified` throw it before sending
 * anything. See {@link queryRefusal} for what the API refuses.
 */
export class QueryRefusedError extends WillowError {
  constructor(message: string) {
    super(message, 'QUERY_REFUSED');
    this.name = 'QueryRefusedError';
  }
}

/**
 * A query whose result the SDK can't verify whatever the data, because the
 * API's selection for the query itself can't be reproduced exactly (code
 * `QUERY_NOT_VERIFIABLE`). `client.query` throws it before sending anything.
 * Its result may be read unverified (`queryUnverified`).
 */
export class QueryNotVerifiableError extends WillowError {
  constructor(message: string) {
    super(message, 'QUERY_NOT_VERIFIABLE');
    this.name = 'QueryNotVerifiableError';
  }
}

/**
 * A query result the SDK can't verify because of the data it is selected
 * from (code `QUERY_RESULT_NOT_VERIFIABLE`): the proof reveals the whole data
 * tree at `rootHash`, but the API's selection over those entries can't be
 * reproduced (a document holding an object whose first key is serde_json's
 * private token, say). `client.query` throws
 * it only once `rootHash` is the light client's root for the proof's
 * height; {@link verifyQuerySelection} checks
 * `rootHash` only against `expectedRootHash`, so without one it is the
 * proof's own root, to compare with a trusted root before acting on the
 * error.
 */
export class QueryResultNotVerifiableError extends WillowError {
  /** The root (hex) of the data the selection was run over. */
  readonly rootHash: string;

  constructor(message: string, rootHash: string) {
    super(message, 'QUERY_RESULT_NOT_VERIFIABLE');
    this.name = 'QueryResultNotVerifiableError';
    this.rootHash = rootHash;
  }
}

/** The selection the API makes for a `POST /query/:subgrove` body. */
export interface QuerySelection {
  /** The exact-match filters: documents whose every `field` equals its `value`. */
  filters: Array<{ field: string; value: NodeJson }>;
  /** The sort field and direction. */
  sort: { field: string; descending: boolean } | null;
  offset: number;
  limit: number;
}

function notVerifiable(reason: string): QueryNotVerifiableError {
  return new QueryNotVerifiableError(
    `This query's result can't be verified: ${reason}. Use queryUnverified to read it without verification.`,
  );
}

function refused(reason: string): QueryRefusedError {
  return new QueryRefusedError(`The API refuses this query: ${reason}`);
}

/** Whether `value` is an integer from 0 to 2^32 - 1 (or `null`, or absent), as the API reads `limit` and `offset`. */
function isU32(value: NodeJson | undefined): boolean {
  return (
    value === undefined ||
    value.t === 'null' ||
    (value.t === 'num' && /^[0-9]+$/.test(value.n) && Number(value.n) <= U32_MAX)
  );
}

function u32(value: NodeJson | undefined, fallback: number): number {
  return value === undefined || value.t !== 'num' ? fallback : Number(value.n);
}

/**
 * The body's members as the API reads the JSON text the SDK sends for it, or
 * why the SDK can't read it as the API does (an object whose first key is
 * serde_json's private token). Throws {@link QueryRefusedError} for text the
 * API can't read.
 */
function readBody(body: QueryRequest): { fields: Map<string, NodeJson> } | { irreproducible: string } {
  let parsed: NodeJson | null;
  try {
    parsed = parseNodeJsonText(JSON.stringify(body));
  } catch (error) {
    if (error instanceof NotReproducibleError) return { irreproducible: error.message };
    throw error;
  }
  if (!parsed || parsed.t !== 'obj') {
    throw refused('it cannot read the request as JSON (a lone surrogate in a string, say)');
  }
  return { fields: parsed.v };
}

/**
 * Why the API refuses a `POST /query/:subgrove` body it reads as `fields`, or
 * `undefined` when it takes it. It refuses a key it does not read; `filters`
 * other than an object (or `null`), with more than 32 fields, a field of
 * more than 256 bytes or named `$and`, `$or`, `$not`, or `$nor`, or a value
 * that is an object (a filter operator such as `{ $gt: 1 }`) or longer than
 * 4,096 bytes as JSON text; `search`; `includes` other than `[]`; `sort`
 * other than `{ field, order }` with `order` exactly `asc` or `desc` and a
 * `field` of at most 256 bytes; and a `limit` or `offset` other than an
 * integer from 0 to 2^32 - 1.
 */
export function queryRefusal(fields: Map<string, NodeJson>): string | undefined {
  for (const key of fields.keys()) {
    if (!QUERY_KEYS.has(key)) return `it reads no \`${key}\``;
  }

  const filters = fields.get('filters');
  if (filters && filters.t !== 'null') {
    if (filters.t !== 'obj') return '`filters` must be an object of fields and their exact values';
    if (filters.v.size > MAX_FILTER_FIELDS) {
      return `\`filters\` gives ${filters.v.size} fields; at most ${MAX_FILTER_FIELDS} are allowed`;
    }
    for (const [field, value] of filters.v) {
      if (LOGICAL_OPERATORS.has(field)) {
        return `logical operators are not supported (\`${field}\`): every filter field must match`;
      }
      if (utf8Length(field) > MAX_FIELD_BYTES) return `a filter field is longer than ${MAX_FIELD_BYTES} bytes`;
      if (nodeJsonTextLength(value) > MAX_FILTER_VALUE_BYTES) {
        return `the filter value for \`${field}\` is longer than ${MAX_FILTER_VALUE_BYTES} bytes`;
      }
      if (value.t === 'obj') {
        return `filter operators are not supported (\`${field}\` is given an object): a filter matches a field's exact value`;
      }
    }
  }

  const search = fields.get('search');
  if (search && search.t !== 'null') return '`search` is not supported';
  const includes = fields.get('includes');
  if (includes && !(includes.t === 'arr' && includes.v.length === 0)) return '`includes` is not supported';

  const sort = fields.get('sort');
  if (sort && sort.t !== 'null') {
    const field = sort.t === 'obj' ? sort.v.get('field') : undefined;
    const order = sort.t === 'obj' ? sort.v.get('order') : undefined;
    if (sort.t !== 'obj' || sort.v.size !== 2 || field?.t !== 'str' || order?.t !== 'str') {
      return "`sort` must be `{ field, order }`, nothing else";
    }
    if (utf8Length(field.v) > MAX_FIELD_BYTES) return `\`sort.field\` is longer than ${MAX_FIELD_BYTES} bytes`;
    if (order.v !== 'asc' && order.v !== 'desc') return '`sort.order` must be "asc" or "desc"';
  }

  for (const name of ['limit', 'offset']) {
    if (!isU32(fields.get(name))) return `\`${name}\` must be an integer from 0 to ${U32_MAX}`;
  }
  const includeProof = fields.get('include_proof');
  if (includeProof && includeProof.t !== 'null' && includeProof.t !== 'bool') return '`include_proof` must be a boolean';
  return undefined;
}

/**
 * Throws {@link QueryRefusedError} when the API refuses `body` (see
 * {@link queryRefusal}), read from the JSON text the SDK sends for it as the
 * API reads that text. `client.queryUnverified` runs it before sending.
 */
export function checkQueryAccepted(body: QueryRequest): void {
  const read = readBody(body);
  if ('irreproducible' in read) return;
  const reason = queryRefusal(read.fields);
  if (reason !== undefined) throw refused(reason);
}

/**
 * The selection the API makes for `body`, read from the JSON text the SDK
 * sends for it as the API reads that text. Throws {@link QueryRefusedError}
 * for a body the API refuses, and {@link QueryNotVerifiableError} for one
 * whose selection can't be reproduced.
 */
export function querySelection(body: QueryRequest): QuerySelection {
  const read = readBody(body);
  if ('irreproducible' in read) throw notVerifiable(read.irreproducible);
  const fields = read.fields;
  const reason = queryRefusal(fields);
  if (reason !== undefined) throw refused(reason);

  const filters: QuerySelection['filters'] = [];
  const given = fields.get('filters');
  if (given?.t === 'obj') {
    for (const [field, value] of given.v) filters.push({ field, value });
  }

  let sort: QuerySelection['sort'] = null;
  const sortSpec = fields.get('sort');
  if (sortSpec?.t === 'obj') {
    const field = sortSpec.v.get('field') as { t: 'str'; v: string };
    const order = sortSpec.v.get('order') as { t: 'str'; v: string };
    sort = { field: field.v, descending: order.v === 'desc' };
  }

  return {
    filters,
    sort,
    offset: u32(fields.get('offset'), 0),
    limit: u32(fields.get('limit'), DEFAULT_QUERY_LIMIT),
  };
}

/** A document's value at a dotted field path, as the API reads it. */
function fieldValue(doc: NodeJson, field: string): NodeJson | undefined {
  let current = doc;
  for (const part of field.split('.')) {
    if (current.t !== 'obj') return undefined;
    const next = current.v.get(part);
    if (next === undefined) return undefined;
    current = next;
  }
  return current;
}

/**
 * How the API's sort reads a document's sort field: its kind's rank
 * (missing, `null`, boolean, number, string, array, object), and a
 * boolean, a number's double (`null` when it has no finite one), or a
 * string.
 */
type SortKey =
  | { rank: 0 | 1 | 5 | 6 }
  | { rank: 2; b: boolean }
  | { rank: 3; f: number | null }
  | { rank: 4; s: string };

/**
 * How many significant digits a JSON number's text has: those of its
 * mantissa from the first digit other than `0` to the last, counted in one
 * pass (a regex stripping the zeros would take seconds over a long run of
 * them).
 */
function significantDigits(text: string): number {
  let count = 0;
  let zeros = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x65 || c === 0x45) break; // e, E: the exponent
    if (c === 0x30) {
      if (count > 0) zeros++;
    } else if (c > 0x30 && c <= 0x39) {
      count += zeros + 1;
      zeros = 0;
    }
  }
  return count;
}

/**
 * A number's value as the API sorts by it (Rust's `str::parse::<f64>` of its
 * text; `null` when not finite). JavaScript gives the correctly rounded value
 * for up to 20 significant digits; past that, {@link parseF64} computes it.
 */
function sortNumber(text: string): number | null {
  const f = significantDigits(text) > 20 ? parseF64(text) : Number(text);
  return Number.isFinite(f) ? f : null;
}

function sortKey(doc: NodeJson, field: string): SortKey {
  const value = fieldValue(doc, field);
  if (value === undefined) return { rank: 0 };
  switch (value.t) {
    case 'null':
      return { rank: 1 };
    case 'bool':
      return { rank: 2, b: value.v };
    case 'num':
      return { rank: 3, f: sortNumber(value.n) };
    case 'str':
      return { rank: 4, s: value.v };
    case 'arr':
      return { rank: 5 };
    case 'obj':
      return { rank: 6 };
  }
}

/** Strings in Unicode code point order (Rust's `str` order), not UTF-16's. */
function compareCodePoints(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length && j < b.length) {
    const ca = a.codePointAt(i)!;
    const cb = b.codePointAt(j)!;
    if (ca !== cb) return ca < cb ? -1 : 1;
    i += ca > 0xffff ? 2 : 1;
    j += cb > 0xffff ? 2 : 1;
  }
  if (i < a.length) return 1;
  if (j < b.length) return -1;
  return 0;
}

/**
 * The API's comparison (`SortKey::total_cmp`), a total order: by kind
 * (missing, `null`, `false`, `true`, numbers, strings, arrays, objects),
 * then numbers by value (one with no finite double first; `-0` and `0` tie)
 * and strings by code point. Two arrays, two objects, two `null`s, or two
 * missing fields tie.
 */
function compareKeys(a: SortKey, b: SortKey): number {
  if (a.rank !== b.rank) return a.rank < b.rank ? -1 : 1;
  switch (a.rank) {
    case 2:
      return Number(a.b) - Number((b as typeof a).b);
    case 3: {
      const x = a.f;
      const y = (b as typeof a).f;
      if (x === null || y === null) return x === y ? 0 : x === null ? -1 : 1;
      return x < y ? -1 : x > y ? 1 : 0;
    }
    case 4:
      return compareCodePoints(a.s, (b as typeof a).s);
    default:
      return 0;
  }
}

/** The API's stable sort: ties keep key order, in either direction. */
function sortDocuments(docs: NodeJson[], sort: NonNullable<QuerySelection['sort']>): NodeJson[] {
  const keyed = docs.map((doc, index) => ({ doc, index, key: sortKey(doc, sort.field) }));
  const direction = sort.descending ? -1 : 1;
  keyed.sort((a, b) => direction * compareKeys(a.key, b.key) || a.index - b.index);
  return keyed.map(({ doc }) => doc);
}

/**
 * The documents the API's query selects from a subgrove's data entries, in
 * its order, and how many it selects before `offset` and `limit`.
 *
 * @throws NotReproducibleError when the API's selection can't be reproduced.
 */
export function selectDocuments(
  entries: CompleteEntry[],
  selection: QuerySelection,
): { documents: NodeJson[]; total: number } {
  const selected: NodeJson[] = [];
  for (const entry of entries) {
    if (entry.element === null) {
      throw new NotReproducibleError(`the element at key 0x${bytesToHex(entry.key)} does not decode`);
    }
    // The API reads the entries raw: a reference is not an item.
    if (entry.reference || entry.element.type !== 'Item') continue;
    const doc = parseNodeJson(entry.element.value);
    if (doc === null) continue;
    const matches = selection.filters.every(({ field, value }) => {
      const held = fieldValue(doc, field);
      return held !== undefined && nodeJsonEqual(held, value);
    });
    if (matches) selected.push(doc);
  }
  const ordered = selection.sort ? sortDocuments(selected, selection.sort) : selected;
  return {
    documents: ordered.slice(selection.offset, selection.offset + selection.limit),
    total: ordered.length,
  };
}

export interface QuerySelectionOptions {
  /** When set, the proof's root must be this (hex). */
  expectedRootHash?: string;
}

/** The entries a query response's proof reveals at the data path, and its root. */
export interface ProvenQueryData {
  entries: CompleteEntry[];
  /** The proof's root (hex). */
  rootHash: string;
}

/**
 * The whole data tree a `POST /query/:subgrove` response's proof reveals at
 * `["subgroves", subgroveId, "data"]`, and the proof's root. Throws when the
 * proof is missing, does not verify, or leaves any entry there unrevealed.
 */
export function provenQueryData(subgroveId: string, response: QueryResponse): ProvenQueryData {
  if (!response.proof) throw new Error('Query response does not contain proof data');
  const layer = verifyCompleteLayer(
    decodeProofBytes(response.proof),
    encodePath(subgroveDataPath(subgroveId)),
  );
  return { entries: layer.entries, rootHash: hashToHex(layer.rootHash) };
}

/** The first number in `value` JavaScript can't carry exactly, if any. */
function inexactNumber(value: NodeJson): string | undefined {
  switch (value.t) {
    case 'num':
      return isExactJsonNumber(value.n) ? undefined : value.n;
    case 'arr':
      for (const item of value.v) {
        const found = inexactNumber(item);
        if (found !== undefined) return found;
      }
      return undefined;
    case 'obj':
      for (const item of value.v.values()) {
        const found = inexactNumber(item);
        if (found !== undefined) return found;
      }
      return undefined;
    default:
      return undefined;
  }
}

/**
 * Require `response` to be exactly what `selection` selects from the proven
 * entries: its `documents` (in order, each structurally equal to the proven
 * one, with every number one JavaScript carries exactly), `total`,
 * `offset`, and `limit`. Run it only once `data.rootHash` is checked, as the
 * error a selection the data makes irreproducible throws
 * ({@link QueryResultNotVerifiableError}) is about the data at that root.
 *
 * @throws QueryResultNotVerifiableError when the API's selection over these
 *   entries can't be reproduced.
 * @throws Error when the response is not the selection.
 */
export function checkQueryResult(
  data: ProvenQueryData,
  selection: QuerySelection,
  response: QueryResponse,
): void {
  let expected: { documents: NodeJson[]; total: number };
  try {
    expected = selectDocuments(data.entries, selection);
  } catch (error) {
    if (error instanceof NotReproducibleError) {
      throw new QueryResultNotVerifiableError(
        `This query's result can't be verified from the subgrove's data at root ${data.rootHash}: ` +
          `${error.message}`,
        data.rootHash,
      );
    }
    throw error;
  }

  if (response.total !== expected.total) {
    throw new Error(
      `The response's total (${response.total}) is not the ${expected.total} documents the query ` +
        'selects in the proven subgrove',
    );
  }
  if (response.offset !== selection.offset || response.limit !== selection.limit) {
    throw new Error(
      `The response's offset and limit (${response.offset}, ${response.limit}) are not the query's ` +
        `(${selection.offset}, ${selection.limit})`,
    );
  }
  const documents: unknown[] = Array.isArray(response.documents) ? response.documents : [];
  if (!Array.isArray(response.documents) || documents.length !== expected.documents.length) {
    throw new Error(
      `The response has ${documents.length} documents; the query selects ` +
        `${expected.documents.length} at this offset in the proven subgrove`,
    );
  }
  for (let i = 0; i < documents.length; i++) {
    const inexact = inexactNumber(expected.documents[i]);
    if (inexact !== undefined) {
      throw new Error(
        `Document at index ${i} holds the number ${inexact}, which JavaScript can't carry exactly; ` +
          'store such values as strings',
      );
    }
    if (!jsonDeepEqual(nodeJsonToJs(expected.documents[i]), documents[i])) {
      throw new Error(
        `Document at index ${i} is not the document the query selects there in the proven ` +
          'subgrove (or holds a number JavaScript cannot carry exactly)',
      );
    }
  }
}

/**
 * Verify that a `POST /query/:subgrove` response is exactly the API's answer
 * to `query` over the subgrove's data as the proof proves it, and return the
 * proof's root hash (hex), which the caller must compare to a trusted root.
 *
 * The proof must reveal every entry of the subgrove's data tree at
 * `["subgroves", subgroveId, "data"]` (no pruned or hidden node), and its
 * root must be `options.expectedRootHash` when that is given; only then is
 * the query's selection run over the entries. The response's `documents`
 * must be the documents the query selects, in order (each structurally
 * equal to the proven one, numbers exact: a document holding a number
 * whose text parses to a double JavaScript writes as another value, such as
 * `9007199254740993` (read as 2^53, written `9007199254740992`) or
 * `0.33333333333333331`, does not verify; every number JavaScript writes
 * does, at any magnitude), and its `total`, `offset`, and `limit` the
 * query's.
 *
 * `query` is the query as it was sent (without `include_proof`, which the
 * SDK sets).
 *
 * @throws QueryRefusedError when the API refuses this query.
 * @throws QueryNotVerifiableError when the API's selection for this query
 *   can't be reproduced, whatever the data.
 * @throws QueryResultNotVerifiableError when the selection over the proven
 *   data can't be reproduced; its `rootHash` is checked only against
 *   `expectedRootHash`.
 * @throws Error when the proof or the response does not verify.
 */
export async function verifyQuerySelection(
  subgroveId: string,
  query: QueryRequest,
  response: QueryResponse,
  options?: QuerySelectionOptions,
): Promise<string> {
  const selection = querySelection({ ...query, include_proof: true });
  const data = provenQueryData(subgroveId, response);
  enforceExpectedRoot(data.rootHash, options?.expectedRootHash);
  checkQueryResult(data, selection, response);
  return data.rootHash;
}
