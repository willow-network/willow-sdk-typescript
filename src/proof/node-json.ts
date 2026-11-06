/**
 * JSON as the node reads it: `serde_json::from_slice::<Value>` with the
 * `arbitrary_precision` feature, which the API server builds with.
 *
 * The node's query selection runs over `serde_json::Value`s, which differ
 * from what `JSON.parse` gives in ways that change which documents a query
 * selects and in what order:
 *
 * - A number keeps its text, and nothing is rounded. The text is normalized:
 *   the exponent marker is written `e` with a sign (`1E5` is `1e+5`), and an
 *   integer that fits a u64 (or, negative, an i64) is written in decimal, so
 *   `-0` is `0`. The query's filter compares numbers by their exact decimal
 *   value (`1`, `1.0`, and `1e0` are equal; see {@link nodeJsonEqual}), and
 *   its sort by the double Rust parses from the text ({@link parseF64}).
 * - Bytes that are not UTF-8, a string escape of a lone UTF-16 surrogate, a
 *   byte-order mark, or more than 127 nested arrays and objects are refused
 *   (the node skips such a document); `JSON.parse` takes them.
 * - An object whose first key is exactly serde_json's private number token
 *   (`$serde_json::private::Number`) or raw-value token
 *   (`$serde_json::private::RawValue`) is read as that number or raw value,
 *   not as an object. A document holding such an object is reported as one
 *   this module can't reproduce. Any other key, and these tokens as a later
 *   key, are ordinary keys.
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

/**
 * serde_json's private tokens: an object whose first key is exactly one of
 * these is read as a number (with `arbitrary_precision`) or a raw value
 * (with `raw_value`).
 */
const PRIVATE_TOKENS = new Set(['$serde_json::private::Number', '$serde_json::private::RawValue']);

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
    for (let first = true; ; first = false) {
      this.ws();
      if (this.s[this.i] !== '"') throw REFUSED;
      const key = this.string();
      // serde_json reads only an object's first key as its token.
      if (first && PRIVATE_TOKENS.has(key)) {
        throw new NotReproducibleError(
          `an object's first key is "${key}", which the node reads as a number or raw value, not an object`,
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

const I128_MAX = (1n << 127n) - 1n;
const I128_MIN = -(1n << 127n);

/** The index of the first character other than `0` in `text` from `start` to `end`, in one pass. */
function skipZeros(text: string, start: number, end: number): number {
  while (start < end && text.charCodeAt(start) === 0x30) start++;
  return start;
}

/** `end`, moved back over the `0`s before it (down to `start`), in one pass. */
function dropZeros(text: string, start: number, end: number): number {
  while (end > start && text.charCodeAt(end - 1) === 0x30) end--;
  return end;
}

/**
 * A number's text as the node's `exact_decimal` reads it: its sign, its
 * significant digits (no leading or trailing `0`; none for zero, which has no
 * sign), and the power of ten of the last of them. `null` when the exponent,
 * or a step of the node's arithmetic on it (`exponent - fraction digits`,
 * then `+ trailing zeros`), does not fit an i128; the node then compares the
 * numbers' texts.
 */
export function nodeExactDecimal(
  text: string,
): { negative: boolean; digits: string; exponent: bigint } | null {
  const negative = text.startsWith('-');
  const rest = negative ? text.slice(1) : text;
  const e = rest.search(/[eE]/);
  const mantissa = e < 0 ? rest : rest.slice(0, e);
  let exponent = 0n;
  if (e >= 0) {
    const literal = rest.slice(e + 1);
    const m = /^([+-]?)([0-9]+)$/.exec(literal);
    if (!m) return null;
    // More than 39 digits (past its leading zeros) is past an i128 either way.
    const first = skipZeros(m[2], 0, m[2].length);
    if (m[2].length - first > 39) return null;
    const magnitude = BigInt(m[2].slice(first) || '0');
    exponent = m[1] === '-' ? -magnitude : magnitude;
    if (exponent > I128_MAX || exponent < I128_MIN) return null;
  }
  const dot = mantissa.indexOf('.');
  const int = dot < 0 ? mantissa : mantissa.slice(0, dot);
  const frac = dot < 0 ? '' : mantissa.slice(dot + 1);
  if (int === '' || !/^[0-9]*$/.test(int + frac)) return null;
  const digits = int + frac;
  const start = skipZeros(digits, 0, digits.length);
  if (start === digits.length) return { negative: false, digits: '', exponent: 0n };
  const end = dropZeros(digits, start, digits.length);
  exponent -= BigInt(frac.length);
  if (exponent < I128_MIN) return null;
  exponent += BigInt(digits.length - end);
  if (exponent > I128_MAX) return null;
  return { negative, digits: digits.slice(start, end), exponent };
}

/**
 * The node's number equality (`numbers_equal`): the same text, or the same
 * exact decimal value when both texts have one ({@link nodeExactDecimal}).
 */
export function nodeNumbersEqual(a: string, b: string): boolean {
  if (a === b) return true;
  const x = nodeExactDecimal(a);
  const y = nodeExactDecimal(b);
  return (
    x !== null &&
    y !== null &&
    x.negative === y.negative &&
    x.digits === y.digits &&
    x.exponent === y.exponent
  );
}

/** Past this many significant digits, a digit moves a double's rounding only as a non-zero tail (767 suffice). */
const MAX_ROUNDING_DIGITS = 800;

function bitLength(n: bigint): number {
  return n.toString(2).length;
}

/**
 * Rust's `str::parse::<f64>` of a JSON number's text (what the node's sort
 * compares): the double nearest its exact value, ties to even, and
 * ±`Infinity` past the largest. Computed in integers, so it does not depend
 * on how JavaScript rounds a literal of more than 20 significant digits,
 * which the language leaves open. `NaN` for text that is not a JSON number.
 */
export function parseF64(text: string): number {
  const m = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?)([0-9]+))?$/.exec(text);
  if (!m) return NaN;
  const [, sign, whole, fraction = '', expSign = '', expDigits = '0'] = m;
  const negative = sign === '-';
  const signed = (x: number) => (negative ? -x : x);
  const all = whole + fraction;
  const start = skipZeros(all, 0, all.length);
  if (start === all.length) return signed(0);
  const end = dropZeros(all, start, all.length);
  let digits = all.slice(start, end);

  const expStart = skipZeros(expDigits, 0, expDigits.length);
  // An exponent of 16 digits or more is far past a double's range either way.
  if (expDigits.length - expStart > 15) return signed(expSign === '-' ? 0 : Infinity);
  // The value is digits × 10^exponent.
  let exponent =
    (expSign === '-' ? -1 : 1) * Number(expDigits.slice(expStart) || '0') -
    fraction.length +
    (all.length - end);
  if (digits.length - 1 + exponent >= 309) return signed(Infinity); // at least 1e309
  if (digits.length + exponent <= -324) return signed(0); // below 1e-324, half the least subnormal
  if (digits.length > MAX_ROUNDING_DIGITS) {
    exponent += digits.length - (MAX_ROUNDING_DIGITS + 1);
    digits = `${digits.slice(0, MAX_ROUNDING_DIGITS)}1`;
  }

  const num = BigInt(digits) * (exponent > 0 ? 10n ** BigInt(exponent) : 1n);
  const den = exponent < 0 ? 10n ** BigInt(-exponent) : 1n;
  // q = floor(num / (den × 2^e)), in [2^52, 2^53) for a normal double.
  const quotient = (e: number): [bigint, bigint, bigint] => {
    const [n, d] = e >= 0 ? [num, den << BigInt(e)] : [num << BigInt(-e), den];
    return [n / d, n % d, d];
  };
  let e = Math.max(bitLength(num) - bitLength(den) - 53, -1074);
  let [q, r, d] = quotient(e);
  if (q >= 1n << 53n) {
    e += 1;
    [q, r, d] = quotient(e);
  }
  if (2n * r > d || (2n * r === d && (q & 1n) === 1n)) q += 1n;
  if (q === 1n << 53n) {
    q >>= 1n;
    e += 1;
  }
  if (e > 971) return signed(Infinity);
  const biased = q >= 1n << 52n ? BigInt(e + 1075) : 0n;
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, (negative ? 1n << 63n : 0n) | (biased << 52n) | (q & ((1n << 52n) - 1n)));
  return view.getFloat64(0);
}

/**
 * The node's filter equality (`json_values_equal`): numbers by their exact
 * decimal value ({@link nodeNumbersEqual}: `1`, `1.0`, and `1e0` are
 * equal), in arrays and objects too; objects by key; every other kind as
 * `Value` compares it.
 */
export function nodeJsonEqual(a: NodeJson, b: NodeJson): boolean {
  if (a.t !== b.t) return false;
  switch (a.t) {
    case 'null':
      return true;
    case 'bool':
      return a.v === (b as typeof a).v;
    case 'num':
      return nodeNumbersEqual(a.n, (b as typeof a).n);
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

/** The length of `text` in UTF-8 bytes (a lone surrogate, which no read value holds, as 3). */
export function utf8Length(text: string): number {
  let length = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) length += 1;
    else if (c < 0x800) length += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        length += 4;
        i++;
      } else {
        length += 3;
      }
    } else length += 3;
  }
  return length;
}

/** The length of a string in serde_json's text: quoted, with `"`, `\`, and control characters escaped. */
function quotedLength(text: string): number {
  let length = utf8Length(text) + 2;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22 || c === 0x5c || c === 0x08 || c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d) {
      length += 1; // `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`
    } else if (c < 0x20) {
      length += 5; // `\u00XX`
    }
  }
  return length;
}

/** The length in bytes of `serde_json::to_string(value)`: compact, numbers as their kept text. */
export function nodeJsonTextLength(value: NodeJson): number {
  switch (value.t) {
    case 'null':
      return 4;
    case 'bool':
      return value.v ? 4 : 5;
    case 'num':
      return value.n.length;
    case 'str':
      return quotedLength(value.v);
    case 'arr': {
      let length = 2 + Math.max(value.v.length - 1, 0);
      for (const item of value.v) length += nodeJsonTextLength(item);
      return length;
    }
    case 'obj': {
      let length = 2 + Math.max(value.v.size - 1, 0);
      for (const [k, v] of value.v) length += quotedLength(k) + 1 + nodeJsonTextLength(v);
      return length;
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
