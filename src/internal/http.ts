/**
 * Minimal typed HTTP client for the SDK's JSON APIs.
 *
 * Built on the global `fetch` available in Node >= 18 and all modern
 * browsers — no dependencies. Requests carry a JSON body, responses are
 * parsed as JSON, and non-2xx statuses throw `HttpError` so call sites
 * can map failures to their own error types.
 */

const DEFAULT_TIMEOUT_MS = 30_000;

/** Thrown on any non-2xx response (and on unparseable 2xx JSON bodies). */
export class HttpError extends Error {
  /** HTTP status code of the response. */
  readonly status: number;
  /** Raw response body text (may be empty). */
  readonly body: string;
  /** `error` field of the JSON error envelope, when the body carried one. */
  readonly apiError?: string;

  constructor(status: number, body: string, url: string) {
    let apiError: string | undefined;
    try {
      const parsed = JSON.parse(body) as { error?: unknown };
      if (parsed && typeof parsed.error === 'string') apiError = parsed.error;
    } catch {
      // body is not JSON; leave apiError unset
    }
    super(`HTTP ${status} from ${url}${apiError ? `: ${apiError}` : ''}`);
    this.name = 'HttpError';
    this.status = status;
    this.body = body;
    this.apiError = apiError;
  }
}

/**
 * Makes the headers that sign one request: given the method, the path and
 * query the server receives, and the exact body string sent (`undefined` for
 * none). Called once per request attempt, after the URL and body are final.
 * `WillowAuth.getSignedHeaders` (nonce form) and `WillowAuth.getAuthHeaders`
 * (older form) both fit.
 */
export type RequestSigner = (
  method: string,
  pathAndQuery: string,
  body?: string,
) => Record<string, string>;

/** A request URL as it goes on the wire, and the target the API receives. */
export interface ResolvedRequest {
  /** The URL to fetch, serialized exactly as `fetch` will send it. */
  href: string;
  /**
   * The request line's path and query (percent-encoded as sent), less any
   * path the base URL carries: a proxy mounted under a path strips it before
   * the API sees the request.
   */
  target: string;
}

/** The page URL in a browser, against which a relative base URL resolves. */
function documentURL(): string | undefined {
  return (globalThis as { location?: { href?: string } }).location?.href;
}

/**
 * Resolve `path` against `baseURL` into the URL `fetch` sends and the request
 * target the API receives. `path` may also be an absolute URL. A relative
 * base URL (a same-origin proxy such as `/willow`) resolves against the page.
 *
 * Returns `undefined` when no absolute URL results (a relative path with no
 * page to resolve it against); `fetch` cannot send such a request either.
 */
export function resolveRequest(baseURL: string, path: string): ResolvedRequest | undefined {
  const base = baseURL.replace(/\/+$/, '');
  let url: URL;
  try {
    url = new URL(/^https?:\/\//i.test(path) ? path : `${base}${path}`, documentURL());
  } catch {
    return undefined;
  }
  // Whether a bare "?" reaches the wire depends on the runtime; drop it so
  // the signed target is what any runtime sends.
  if (url.search === '') url.search = '';
  let target = url.pathname + url.search;
  let basePath = '';
  try {
    basePath = new URL(base, documentURL()).pathname.replace(/\/+$/, '');
  } catch {
    basePath = '';
  }
  if (basePath !== '' && target.startsWith(`${basePath}/`)) {
    target = target.slice(basePath.length);
  }
  return { href: url.href, target };
}

export interface HttpClientOptions {
  /** Base URL prepended to relative request paths. */
  baseURL?: string;
  /** Default headers sent with every request. */
  headers?: Record<string, string>;
  /** Default request timeout in milliseconds. Default: 30 000. */
  timeoutMs?: number;
}

export interface HttpRequestOptions {
  /** Extra headers for this request (merged over the defaults). */
  headers?: Record<string, string>;
  /** Timeout override for this request (milliseconds). */
  timeoutMs?: number;
  /**
   * Signs this request. It is called with the final method, request target,
   * and body string, and its headers are sent over all others.
   */
  sign?: RequestSigner;
}

export class HttpClient {
  private baseURL: string;
  private headers: Record<string, string>;
  private timeoutMs: number;

  constructor(options: HttpClientOptions = {}) {
    this.baseURL = (options.baseURL ?? '').replace(/\/+$/, '');
    this.headers = { ...(options.headers ?? {}) };
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Set (or remove, when `value` is undefined) a default header. */
  setHeader(name: string, value: string | undefined): void {
    if (value === undefined) {
      delete this.headers[name];
    } else {
      this.headers[name] = value;
    }
  }

  get<T>(path: string, options?: HttpRequestOptions): Promise<T> {
    return this.request<T>('GET', path, undefined, options);
  }

  post<T>(path: string, body?: unknown, options?: HttpRequestOptions): Promise<T> {
    return this.request<T>('POST', path, body, options);
  }

  put<T>(path: string, body?: unknown, options?: HttpRequestOptions): Promise<T> {
    return this.request<T>('PUT', path, body, options);
  }

  delete<T>(path: string, options?: HttpRequestOptions): Promise<T> {
    return this.request<T>('DELETE', path, undefined, options);
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
    options?: HttpRequestOptions,
  ): Promise<T> {
    const resolved = resolveRequest(this.baseURL, path);
    const url = resolved?.href ?? (/^https?:\/\//i.test(path) ? path : `${this.baseURL}${path}`);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    // Signed last, over the URL and body exactly as they are sent.
    const signature =
      options?.sign && resolved ? options.sign(method, resolved.target, payload) : {};
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
        ...(options?.headers ?? {}),
        ...signature,
      },
      body: payload,
      signal: AbortSignal.timeout(options?.timeoutMs ?? this.timeoutMs),
    });

    const text = await response.text();
    if (!response.ok) {
      throw new HttpError(response.status, text, url);
    }
    if (text === '') {
      return undefined as T;
    }
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new HttpError(response.status, text, `${url} (invalid JSON body)`);
    }
  }
}
