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
 * A query whose selection can't be reproduced exactly is not verifiable and
 * throws {@link QueryNotVerifiableError}, before anything is sent: a filter
 * on more than one field (the API applies only one), a filter operator (the
 * API applies none), or `search` (the API applies none). The proof's
 * completeness and root are checked before the selection is run, so a
 * selection the data makes irreproducible (a sort over values that are not
 * all numbers or all strings, whose order is then not determined, or a
 * document the API's JSON reader may read differently) is reported, as
 * {@link QueryResultNotVerifiableError}, only for data at a checked root.
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
  isExactJsonNumber,
  jsonDeepEqual,
  subgroveDataPath,
} from './shared';

/** The number of documents the API returns when a query gives no `limit`. */
export const DEFAULT_QUERY_LIMIT = 100;

const U32_MAX = 0xffff_ffff;

/** The keys of a `POST /query/:subgrove` body the API reads. */
const QUERY_KEYS = new Set(['filters', 'search', 'sort', 'limit', 'offset', 'include_proof', 'includes']);

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
 * reproduced (a sort over values that are not all numbers or all strings,
 * say). `client.query` throws it only once `rootHash` is the light client's
 * root for the proof's height; {@link verifyQuerySelection} checks
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
 * JavaScript can't carry exactly, such as an integer beyond 2^53 − 1 or a
 * decimal of more than 15 significant digits, does not verify), and its
 * `total`, `offset`, and `limit` the query's.
 *
 * `query` is the query as it was sent (without `include_proof`, which the
 * SDK sets).
 *
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
