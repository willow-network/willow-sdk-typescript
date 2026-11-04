/**
 * A JSON reader that keeps big integers exact: an integer within
 * Number.MAX_SAFE_INTEGER reads as a number, a larger one as a bigint (the
 * SDK's convention for the u64 and u128 values it sends). `JSON.parse`
 * would round them.
 */
export function parseExactJson(text: string): any {
  let i = 0;

  const fail = (what: string): never => {
    throw new SyntaxError(`${what} at ${i} in JSON`);
  };
  const ws = () => {
    while (i < text.length && ' \t\n\r'.includes(text[i])) i++;
  };

  function value(): any {
    ws();
    const c = text[i];
    if (c === '{') return object();
    if (c === '[') return array();
    if (c === '"') return string();
    if (c === '-' || (c >= '0' && c <= '9')) return number();
    for (const [word, v] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    return fail('unexpected token');
  }

  function object(): Record<string, any> {
    const out: Record<string, any> = {};
    i++;
    ws();
    if (text[i] === '}') {
      i++;
      return out;
    }
    for (;;) {
      ws();
      const k = string();
      ws();
      if (text[i++] !== ':') fail('expected :');
      out[k] = value();
      ws();
      const c = text[i++];
      if (c === '}') return out;
      if (c !== ',') fail('expected , or }');
    }
  }

  function array(): any[] {
    const out: any[] = [];
    i++;
    ws();
    if (text[i] === ']') {
      i++;
      return out;
    }
    for (;;) {
      out.push(value());
      ws();
      const c = text[i++];
      if (c === ']') return out;
      if (c !== ',') fail('expected , or ]');
    }
  }

  function string(): string {
    const start = i;
    if (text[i++] !== '"') fail('expected string');
    while (text[i] !== '"') {
      if (i >= text.length) fail('unterminated string');
      i += text[i] === '\\' ? 2 : 1;
    }
    i++;
    return JSON.parse(text.slice(start, i));
  }

  function number(): number | bigint {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) return fail('bad number');
    i += m[0].length;
    if (m[2] === undefined && m[3] === undefined) {
      const n = BigInt(m[0]);
      return n >= BigInt(Number.MIN_SAFE_INTEGER) && n <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(n)
        : n;
    }
    return Number(m[0]);
  }

  const out = value();
  ws();
  if (i !== text.length) fail('trailing text');
  return out;
}
