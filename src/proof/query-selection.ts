/**
 * Verifying a query's whole result: the documents `POST /query/:subgrove`
 * returns are exactly the ones the API's query selects, in its order, from
 * the subgrove's data as the proof proves it.
 *
 * With a proof, the API proves the whole data tree (a `range_full` query on
 * the subgrove's data path) and selects from every item in it: each item that
 * parses as JSON, kept when it matches the one exact-match filter, sorted by
 * the one sort field (stably), then `offset` and `limit` (default 100)
 * applied. `total` is the number selected before `offset` and `limit`. This
 * module requires the proof to reveal every entry of the data tree, runs
 * that selection over them as the API does, and requires the response's
 * documents and `total` to be it.
 *
 * Where the API's selection can't be reproduced exactly, the query is not
 * verifiable and {@link QueryNotVerifiableError} is thrown: a filter on more
 * than one field (the API applies only one), a filter operator (the API
 * applies none), `search` (the API applies none), a sort over values that
 * are not all numbers or all strings (the API's order is then not
 * determined), or a document the API's JSON reader may read differently.
 */

import { QueryRequest, QueryResponse, WillowError } from '../types';
import { verifyCompleteLayer, CompleteEntry, hashToHex, bytesToHex } from '../grovedb';
import {
  NodeJson,
  NotReproducibleError,
  parseNodeJson,
  parseNodeJsonText,
  nodeJsonEqual,
  nodeJsonToJs,
} from './node-json';
import {
  decodeProofBytes,
  encodePath,
  enforceExpectedRoot,
  jsonDeepEqual,
  subgroveDataPath,
} from './shared';

/** The number of documents the API returns when a query gives no `limit`. */
export const DEFAULT_QUERY_LIMIT = 100;

const U32_MAX = 0xffff_ffff;

/** The keys of a `POST /query/:subgrove` body the API reads. */
const QUERY_KEYS = new Set(['filters', 'search', 'sort', 'limit', 'offset', 'include_proof', 'includes']);

/**
 * A query whose result the SDK can't verify, because the API's selection for
 * it can't be reproduced exactly (code `QUERY_NOT_VERIFIABLE`). Its result
 * may be read unverified (`queryUnverified`).
 */
export class QueryNotVerifiableError extends WillowError {
  constructor(message: string) {
    super(message, 'QUERY_NOT_VERIFIABLE');
    this.name = 'QueryNotVerifiableError';
  }
}

/** The selection the API makes for a `POST /query/:subgrove` body. */
export interface QuerySelection {
  /** The one exact-match filter: documents whose `field` equals `value`. */
  filter: { field: string; value: NodeJson } | null;
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

function u32(value: NodeJson | undefined, name: string, fallback: number): number {
  if (value === undefined || value.t === 'null') return fallback;
  if (value.t !== 'num' || !/^[0-9]+$/.test(value.n) || Number(value.n) > U32_MAX) {
    throw notVerifiable(`\`${name}\` is not an integer from 0 to ${U32_MAX}, which the API refuses`);
  }
  return Number(value.n);
}

/**
 * The selection the API makes for `body`, read from the JSON text the SDK
 * sends for it as the API reads that text. Throws
 * {@link QueryNotVerifiableError} for a body whose selection can't be
 * reproduced, or which asks for something the API does not do.
 */
export function querySelection(body: QueryRequest): QuerySelection {
  let parsed: NodeJson | null;
  try {
    parsed = parseNodeJsonText(JSON.stringify(body));
  } catch (error) {
    if (error instanceof NotReproducibleError) throw notVerifiable(error.message);
    throw error;
  }
  if (!parsed || parsed.t !== 'obj') {
    throw notVerifiable('the API cannot read the request as JSON (a lone surrogate in a string, say)');
  }
  const fields = parsed.v;
  for (const key of fields.keys()) {
    if (!QUERY_KEYS.has(key)) throw notVerifiable(`the API ignores \`${key}\``);
  }
  const present = (key: string): NodeJson | undefined => {
    const value = fields.get(key);
    return value && value.t !== 'null' ? value : undefined;
  };

  if (present('search')) throw notVerifiable('the API applies no `search`');
  const includes = fields.get('includes');
  if (includes && !(includes.t === 'arr' && includes.v.length === 0)) {
    throw notVerifiable('the API applies no `includes`');
  }

  let filter: QuerySelection['filter'] = null;
  const filters = present('filters');
  if (filters) {
    if (filters.t !== 'obj') throw notVerifiable('the API applies `filters` only as an object');
    if (filters.v.size > 1) {
      throw notVerifiable(
        'the API applies one filter field and ignores the rest; filter on one field and filter the ' +
          'verified documents further yourself',
      );
    }
    const [entry] = filters.v;
    if (entry) {
      const [field, value] = entry;
      if (value.t === 'obj') {
        throw notVerifiable(
          `the API applies no filter operator (\`${field}\` is given an object): it matches a field ` +
            'only by exact value',
        );
      }
      filter = { field, value };
    }
  }

  let sort: QuerySelection['sort'] = null;
  const sortSpec = present('sort');
  if (sortSpec) {
    const field = sortSpec.t === 'obj' ? sortSpec.v.get('field') : undefined;
    const order = sortSpec.t === 'obj' ? sortSpec.v.get('order') : undefined;
    if (field?.t !== 'str' || order?.t !== 'str' || (order.v !== 'asc' && order.v !== 'desc')) {
      throw notVerifiable("`sort` is not `{ field, order: 'asc' | 'desc' }`");
    }
    sort = { field: field.v, descending: order.v === 'desc' };
  }

  return {
    filter,
    sort,
    offset: u32(fields.get('offset'), 'offset', 0),
    limit: u32(fields.get('limit'), 'limit', DEFAULT_QUERY_LIMIT),
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

/** How the API's sort reads a document's sort field. */
type SortKey = { k: 'num'; f: number | null } | { k: 'str'; s: string } | { k: 'other' };

/**
 * A number's value as the API sorts by it (Rust's `str::parse::<f64>` of its
 * text; `null` when not finite). JavaScript must give it the correctly
 * rounded value, which it is bound to for up to 20 significant digits.
 */
function sortNumber(text: string): number | null {
  const digits = text
    .split('e')[0]
    .replace(/[-.]/g, '')
    .replace(/^0+/, '')
    .replace(/0+$/, '');
  if (digits.length > 20) {
    throw new NotReproducibleError(
      `the sort compares the number ${text}, which has more than 20 significant digits`,
    );
  }
  const f = Number(text);
  return Number.isFinite(f) ? f : null;
}

function sortKey(doc: NodeJson, field: string): SortKey {
  const value = fieldValue(doc, field);
  if (value?.t === 'num') return { k: 'num', f: sortNumber(value.n) };
  if (value?.t === 'str') return { k: 'str', s: value.v };
  return { k: 'other' };
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

/** The API's comparison: numbers with numbers, strings with strings, else equal. */
function compareKeys(a: SortKey, b: SortKey): number {
  if (a.k === 'num' && b.k === 'num') {
    if (a.f === null || b.f === null) return a.f === b.f ? 0 : a.f === null ? -1 : 1;
    return a.f < b.f ? -1 : a.f > b.f ? 1 : 0;
  }
  if (a.k === 'str' && b.k === 'str') return compareCodePoints(a.s, b.s);
  return 0;
}

/**
 * The API's stable sort. Its comparison calls a number and a string, or a
 * missing field and anything, equal, so it orders the documents consistently
 * only when their sort values are all numbers, or all strings, or every pair
 * compares equal; otherwise its order depends on the sort algorithm, and
 * this throws {@link NotReproducibleError}.
 */
function sortDocuments(docs: NodeJson[], sort: NonNullable<QuerySelection['sort']>): NodeJson[] {
  const keyed = docs.map((doc, index) => ({ doc, index, key: sortKey(doc, sort.field) }));
  const numbers = new Set<string>();
  const strings = new Set<string>();
  let others = 0;
  for (const { key } of keyed) {
    if (key.k === 'num') numbers.add(key.f === null ? 'none' : String(key.f === 0 ? 0 : key.f));
    else if (key.k === 'str') strings.add(key.s);
    else others++;
  }
  const consistent =
    (others === 0 && (numbers.size === 0 || strings.size === 0)) ||
    (numbers.size <= 1 && strings.size <= 1);
  if (!consistent) {
    throw new NotReproducibleError(
      `the documents' "${sort.field}" values are not all numbers or all strings, so the API's sort ` +
        'order is not determined',
    );
  }
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
    if (selection.filter) {
      const value = fieldValue(doc, selection.filter.field);
      if (value === undefined || !nodeJsonEqual(value, selection.filter.value)) continue;
    }
    selected.push(doc);
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

/**
 * Verify that a `POST /query/:subgrove` response is exactly the API's answer
 * to `query` over the subgrove's data as the proof proves it, and return the
 * proof's root hash (hex), which the caller must compare to a trusted root.
 *
 * The proof must reveal every entry of the subgrove's data tree at
 * `["subgroves", subgroveId, "data"]` (no pruned or hidden node). The
 * response's `documents` must be the documents the query selects, in order
 * (each structurally equal to the proven one, numbers exact), and its
 * `total`, `offset`, and `limit` the query's.
 *
 * `query` is the query as given to `client.query` (without `include_proof`,
 * which the SDK sets).
 *
 * @throws QueryNotVerifiableError when the API's selection for this query
 *   or these documents can't be reproduced.
 * @throws Error when the proof or the response does not verify.
 */
export async function verifyQuerySelection(
  subgroveId: string,
  query: QueryRequest,
  response: QueryResponse,
  options?: QuerySelectionOptions,
): Promise<string> {
  const selection = querySelection({ ...query, include_proof: true });
  if (!response.proof) throw new Error('Query response does not contain proof data');
  const layer = verifyCompleteLayer(
    decodeProofBytes(response.proof),
    encodePath(subgroveDataPath(subgroveId)),
  );

  let expected: { documents: NodeJson[]; total: number };
  try {
    expected = selectDocuments(layer.entries, selection);
  } catch (error) {
    if (error instanceof NotReproducibleError) throw notVerifiable(error.message);
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
    if (!jsonDeepEqual(nodeJsonToJs(expected.documents[i]), documents[i])) {
      throw new Error(
        `Document at index ${i} is not the document the query selects there in the proven ` +
          'subgrove (or holds a number JavaScript cannot carry exactly)',
      );
    }
  }

  const computed = hashToHex(layer.rootHash);
  enforceExpectedRoot(computed, options?.expectedRootHash);
  return computed;
}
