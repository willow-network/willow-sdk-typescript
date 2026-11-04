/**
 * JSON as the node reads it: `serde_json::from_slice::<Value>` with the
 * `arbitrary_precision` feature, which the API server builds with.
 *
 * The node's query selection runs over `serde_json::Value`s, which differ
 * from what `JSON.parse` gives in ways that change which documents a query
 * selects and in what order:
 *
 * - A number keeps its text. `1` and `1.0` are different numbers (equality
 *   compares the text), and nothing is rounded. The text is normalized: the
 *   exponent marker is written `e` with a sign (`1E5` is `1e+5`), and an
 *   integer that fits a u64 (or, negative, an i64) is written in decimal, so
 *   `-0` is `0`.
 * - Bytes that are not UTF-8, a string escape of a lone UTF-16 surrogate, a
 *   byte-order mark, or more than 127 nested arrays and objects are refused
 *   (the node skips such a document); `JSON.parse` takes them.
 * - An object whose first key is serde_json's private number (or raw value)
 *   token is read as a number. A document with such a key is reported as one
 *   this module can't reproduce.
 */

/** A JSON value as the node holds it. */
export type NodeJson =
  | { t: 'null' }
  | { t: 'bool'; v: boolean }
  /** `n`: the number's text as the node keeps it (see {@link canonicalNumber}). */
  | { t: 'num'; n: string }
  | { t: 'str'; v: string }
  | { t: 'arr'; v: NodeJson[] }
  /** Duplicate keys keep the last value, as the node's map does. */
  | { t: 'obj'; v: Map<string, NodeJson> };

/**
 * Thrown when the node's reading of a value can't be reproduced exactly; a
 * caller must then not present a result that depends on it as verified.
 */
export class NotReproducibleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotReproducibleError';
  }
}

/** serde_json's recursion limit: it refuses the 128th nested array or object. */
const MAX_NESTING = 127;

/** serde_json's private keys (`$serde_json::private::Number`, `…::RawValue`). */
const PRIVATE_KEY_PREFIX = '$serde_json::private::';

const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);

class Refused extends Error {}
const REFUSED = new Refused('refused');

/**
 * The text serde_json (with `arbitrary_precision`) keeps for a JSON number
 * token: the exponent marker as `e` followed by its sign (`+` when the token
 * has none), and an integer that parses as a u64 (or, negative, an i64)
 * written as that integer in decimal (`-0` is `0`). Equal numbers, for the
 * node, are equal texts.
 */
export function canonicalNumber(token: string): string {
  const buf = token.replace(/[eE]([+-]?)/, (_, sign: string) => `e${sign || '+'}`);
  if (/^-?[0-9]+$/.test(buf)) {
    const value = BigInt(buf);
    if (buf.startsWith('-') ? value >= I64_MIN : value <= U64_MAX) return value.toString();
  }
  return buf;
}

/**
 * Read `bytes` as the node does. Returns `null` when the node refuses them
 * (it then skips the document); throws {@link NotReproducibleError} when the
 * node's reading can't be reproduced.
 */
export function parseNodeJson(bytes: Uint8Array): NodeJson | null {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
  return parseNodeJsonText(text);
}

/** {@link parseNodeJson} of text that is already UTF-8 decoded. */
export function parseNodeJsonText(text: string): NodeJson | null {
  const parser = new Parser(text);
  try {
    const value = parser.value(0);
    parser.ws();
    if (parser.i !== text.length) return null;
    return value;
  } catch (error) {
    if (error instanceof Refused) return null;
    throw error;
  }
}

class Parser {
  i = 0;

  constructor(private readonly s: string) {}

  ws(): void {
    const s = this.s;
    while (this.i < s.length) {
      const c = s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x0a || c === 0x09 || c === 0x0d) this.i++;
      else break;
    }
  }

  value(nesting: number): NodeJson {
    this.ws();
    if (this.i >= this.s.length) throw REFUSED;
    const c = this.s[this.i];
    switch (c) {
      case 'n':
        this.literal('null');
        return { t: 'null' };
      case 't':
        this.literal('true');
        return { t: 'bool', v: true };
      case 'f':
        this.literal('false');
        return { t: 'bool', v: false };
      case '"':
        return { t: 'str', v: this.string() };
      case '[':
        return this.array(nesting + 1);
      case '{':
        return this.object(nesting + 1);
      default:
        if (c === '-' || (c >= '0' && c <= '9')) return { t: 'num', n: this.number() };
        throw REFUSED;
    }
  }

  private literal(word: string): void {
    if (this.s.startsWith(word, this.i)) this.i += word.length;
    else throw REFUSED;
  }

  private digits(): number {
    const start = this.i;
    while (this.i < this.s.length && this.s[this.i] >= '0' && this.s[this.i] <= '9') this.i++;
    return this.i - start;
  }

  private number(): string {
    const start = this.i;
    if (this.s[this.i] === '-') this.i++;
    if (this.s[this.i] === '0') {
      this.i++;
      // There can be only one leading '0'.
      if (this.digits() > 0) throw REFUSED;
    } else if (this.digits() === 0) {
      throw REFUSED;
    }
    if (this.s[this.i] === '.') {
      this.i++;
      if (this.digits() === 0) throw REFUSED;
    }
    if (this.s[this.i] === 'e' || this.s[this.i] === 'E') {
      this.i++;
      if (this.s[this.i] === '+' || this.s[this.i] === '-') this.i++;
      if (this.digits() === 0) throw REFUSED;
    }
    return canonicalNumber(this.s.slice(start, this.i));
  }

  private hex4(): number {
    const h = this.s.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw REFUSED;
    this.i += 4;
    return parseInt(h, 16);
  }

  private string(): string {
    const s = this.s;
    this.i++; // the opening quote
    let out = '';
    let start = this.i;
    for (;;) {
      if (this.i >= s.length) throw REFUSED;
      const c = s.charCodeAt(this.i);
      if (c === 0x22) {
        out += s.slice(start, this.i);
        this.i++;
        return out;
      }
      if (c < 0x20) throw REFUSED;
      if (c !== 0x5c) {
        this.i++;
        continue;
      }
      out += s.slice(start, this.i);
      this.i++;
      const e = s[this.i++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          const n = this.hex4();
          // A string's surrogates must pair: a trailing one alone, or a
          // leading one not followed by `\u` and a trailing one, is refused.
          if (n >= 0xdc00 && n <= 0xdfff) throw REFUSED;
          if (n >= 0xd800 && n <= 0xdbff) {
            if (s[this.i] !== '\\' || s[this.i + 1] !== 'u') throw REFUSED;
            this.i += 2;
            const n2 = this.hex4();
            if (n2 < 0xdc00 || n2 > 0xdfff) throw REFUSED;
            out += String.fromCharCode(n, n2);
          } else {
            out += String.fromCharCode(n);
          }
          break;
        }
        default:
          throw REFUSED;
      }
      start = this.i;
    }
  }

  private array(nesting: number): NodeJson {
    if (nesting > MAX_NESTING) throw REFUSED;
    this.i++; // [
    const items: NodeJson[] = [];
    this.ws();
    if (this.s[this.i] === ']') {
      this.i++;
      return { t: 'arr', v: items };
    }
    for (;;) {
      items.push(this.value(nesting));
      this.ws();
      const c = this.s[this.i++];
      if (c === ']') return { t: 'arr', v: items };
      if (c !== ',') throw REFUSED;
    }
  }

  private object(nesting: number): NodeJson {
    if (nesting > MAX_NESTING) throw REFUSED;
    this.i++; // {
    const entries = new Map<string, NodeJson>();
    this.ws();
    if (this.s[this.i] === '}') {
      this.i++;
      return { t: 'obj', v: entries };
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') throw REFUSED;
      const key = this.string();
      if (key.startsWith(PRIVATE_KEY_PREFIX)) {
        throw new NotReproducibleError(
          `an object key starts with "${PRIVATE_KEY_PREFIX}", which the node may read as a number`,
        );
      }
      this.ws();
      if (this.s[this.i++] !== ':') throw REFUSED;
      entries.set(key, this.value(nesting));
      this.ws();
      const c = this.s[this.i++];
      if (c === '}') return { t: 'obj', v: entries };
      if (c !== ',') throw REFUSED;
    }
  }
}

/** The node's `Value` equality: numbers by their text, objects by key. */
export function nodeJsonEqual(a: NodeJson, b: NodeJson): boolean {
  if (a.t !== b.t) return false;
  switch (a.t) {
    case 'null':
      return true;
    case 'bool':
      return a.v === (b as typeof a).v;
    case 'num':
      return a.n === (b as typeof a).n;
    case 'str':
      return a.v === (b as typeof a).v;
    case 'arr': {
      const bv = (b as typeof a).v;
      return a.v.length === bv.length && a.v.every((x, i) => nodeJsonEqual(x, bv[i]));
    }
    case 'obj': {
      const bv = (b as typeof a).v;
      if (a.v.size !== bv.size) return false;
      for (const [k, x] of a.v) {
        const y = bv.get(k);
        if (y === undefined || !nodeJsonEqual(x, y)) return false;
      }
      return true;
    }
  }
}

/**
 * The value `JSON.parse` gives for the node's serialization of `value` (the
 * text the API sends back): numbers from their kept text, objects as plain
 * objects with own properties (a `__proto__` key included).
 */
export function nodeJsonToJs(value: NodeJson): unknown {
  switch (value.t) {
    case 'null':
      return null;
    case 'bool':
    case 'str':
      return value.v;
    case 'num':
      return Number(value.n);
    case 'arr':
      return value.v.map(nodeJsonToJs);
    case 'obj': {
      const out: Record<string, unknown> = {};
      for (const [k, v] of value.v) {
        Object.defineProperty(out, k, {
          value: nodeJsonToJs(v),
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      return out;
    }
  }
}
