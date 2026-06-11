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
    const url = /^https?:\/\//i.test(path) ? path : `${this.baseURL}${path}`;
    const response = await fetch(url, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...this.headers,
        ...(options?.headers ?? {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
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
