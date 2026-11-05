/**
 * JSON text for a transaction body.
 *
 * `JSON.stringify` refuses a `bigint`, and a JS number is exact only up to
 * 2^53 - 1, while the chain's u64 and u128 fields go well past that. A
 * transaction carries such a value as a `bigint`, and this writes it as the
 * JSON number of its exact decimal digits, which the API decodes without
 * rounding. Every other value is written as `JSON.stringify` writes it.
 */
export function toJson(value: unknown): string {
  const text = write(value, false);
  if (text === undefined) {
    throw new TypeError('A transaction body must be a JSON value');
  }
  return text;
}

function write(value: unknown, inArray: boolean): string | undefined {
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as { toJSON?: unknown }).toJSON === 'function'
  ) {
    value = (value as { toJSON: () => unknown }).toJSON();
    if (typeof value === 'bigint') return value.toString();
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => write(v, true) ?? 'null').join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const parts: string[] = [];
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      const text = write(v, false);
      if (text !== undefined) parts.push(`${JSON.stringify(k)}:${text}`);
    }
    return `{${parts.join(',')}}`;
  }
  const text = JSON.stringify(value);
  return text === undefined && inArray ? 'null' : text;
}
