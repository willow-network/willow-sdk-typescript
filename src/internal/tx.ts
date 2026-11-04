/**
 * Shared transaction submission.
 *
 * `POST /tx/submit` on the API server is the chain's single tx ingress: it
 * accepts a JSON-encoded `Transaction` wrapper, bincode-encodes it (the
 * actual wire format), and forwards to CometBFT. Clients must never push
 * JSON bytes at CometBFT directly — the chain would reject (or worse,
 * misparse) them. Every SDK module that broadcasts goes through here.
 */

import { BroadcastResult } from '../consensus/types';
import { toJson } from './json';

export interface SubmitTxOptions {
  apiKey?: string;
  timeoutMs?: number;
  /** Extra headers (e.g. DID auth) to send with the request. */
  headers?: Record<string, string>;
}

/**
 * Transport- or HTTP-level failure (non-2xx, or a body the API server can't
 * have produced). Distinct from a chain-level rejection: it is potentially
 * transient (proxy 502/504, network blip), so the consensus retry loop should
 * retry it rather than treat it as a deterministic outcome.
 */
export class TxTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TxTransportError';
  }
}

/**
 * CometBFT's answer to a transaction its mempool cache already holds: the
 * same bytes were accepted before (pending, or committed without a refusal),
 * so a repeat of a signed transaction that gets it was accepted.
 */
const TX_IN_CACHE = 'tx already exists in cache';

/**
 * Submit a wrapped transaction to `POST /tx/submit`.
 *
 * Distinguishes two failure classes so callers can react correctly:
 *   - **Transport/HTTP failures** (non-2xx, or a non-JSON / malformed body —
 *     e.g. an HTML 502/504 from a proxy) THROW {@link TxTransportError}. These
 *     are non-deterministic; the consensus retry loop retries them, and direct
 *     callers surface them as an error.
 *   - **Chain-level rejections** (a well-formed JSON envelope reporting failure,
 *     or a CheckTx `code !== 0`) return `BroadcastResult{ success: false }`.
 *     These are deterministic, so retrying is pointless.
 *
 * A repeat of a transaction CometBFT already holds ("tx already exists in
 * cache", which the API relays as an RPC error) returns
 * `BroadcastResult{ success: true }` without a `txHash`: the same signed
 * bytes were accepted before.
 */
export async function submitTxToApi(
  apiUrl: string,
  txWrapper: Record<string, unknown>,
  opts: SubmitTxOptions = {},
): Promise<BroadcastResult> {
  const url = `${apiUrl.replace(/\/+$/, '')}/tx/submit`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(opts.apiKey ? { 'X-API-Key': opts.apiKey } : {}),
      ...(opts.headers ?? {}),
    },
    // A u64 or u128 above 2^53 is carried as a bigint and sent as its exact
    // digits, which `JSON.stringify` can't write.
    body: toJson(txWrapper),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
  });

  const text = await response.text();
  let body: {
    success?: boolean;
    data?: { tx_hash: string; code: number; log: string };
    error?: string;
  };
  try {
    body = text === '' ? {} : JSON.parse(text);
  } catch {
    // A non-JSON body means we didn't reach the API server's tx handler
    // (proxy/gateway error page) — transport-level, so throw to allow retry.
    throw new TxTransportError(`HTTP ${response.status} from ${url}: non-JSON response body`);
  }

  if (typeof body.error === 'string' && body.error.includes(TX_IN_CACHE)) {
    return { success: true, rawLog: body.error };
  }

  if (!response.ok) {
    throw new TxTransportError(
      `HTTP ${response.status} from ${url}${body.error ? `: ${body.error}` : ''}`,
    );
  }

  if (!body.success || !body.data) {
    const msg = body.error || `HTTP ${response.status}`;
    return { success: false, errorMessage: msg, rawLog: msg };
  }

  const code = body.data.code;
  return {
    success: code === 0,
    txHash: body.data.tx_hash,
    errorCode: code !== 0 ? code : undefined,
    errorMessage: code !== 0 ? body.data.log : undefined,
    rawLog: body.data.log,
  };
}
