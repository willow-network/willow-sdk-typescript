/**
 * Shared transaction submission.
 *
 * `POST /tx/submit` on the API server is the chain's single tx ingress: it
 * accepts a JSON-encoded `Transaction` wrapper, bincode-encodes it (the
 * actual wire format), and forwards to CometBFT. Clients must never push
 * JSON bytes at CometBFT directly — the chain would reject (or worse,
 * misparse) them. Every SDK module that broadcasts goes through here.
 */

import { BroadcastResult, TransactionSubmitError } from '../consensus/types';
import { toJson } from './json';

export interface SubmitTxOptions {
  apiKey?: string;
  timeoutMs?: number;
  /** Extra headers (e.g. DID auth) to send with the request. */
  headers?: Record<string, string>;
  /**
   * An earlier post of the same signed transaction may have reached
   * CometBFT: it threw after it was sent, or this is a resubmission. A 4xx
   * answers this request only, not the transaction, so it is then `pending`.
   */
  repeat?: boolean;
}

/**
 * Transport- or HTTP-level failure (a non-2xx status other than a 4xx, or a
 * body the API server can't have produced). Distinct from a chain-level
 * rejection: it is potentially transient (proxy 502/504, network blip), so
 * the consensus retry loop should retry it rather than treat it as a
 * deterministic outcome.
 */
export class TxTransportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TxTransportError';
  }
}

/**
 * CometBFT's answer to a transaction its mempool cache already holds. It
 * caches a transaction before CheckTx runs and drops it again if CheckTx
 * refuses it, so the answer means only that the same bytes were seen: they
 * may be in CheckTx, in the mempool, committed, or about to be refused. The
 * outcome is unknown.
 */
const TX_IN_CACHE = 'tx already exists in cache';

/**
 * Submit a wrapped transaction to `POST /tx/submit`.
 *
 * Distinguishes three outcomes other than acceptance so callers can react
 * correctly:
 *   - **Transport/HTTP failures** (a non-2xx status other than a 4xx, or a
 *     non-JSON body with any status but a 4xx — e.g. an HTML 502/504 from a
 *     proxy) THROW {@link TxTransportError}. These are non-deterministic; the
 *     consensus retry loop retries them, and direct callers surface them as an
 *     error.
 *   - **Refusals** return `BroadcastResult{ success: false }`: a chain-level
 *     rejection (a well-formed JSON envelope reporting failure, or a CheckTx
 *     `code !== 0`), and, on the first post of a transaction, a 4xx a body
 *     causes (400, 413, 415, 422: a body the API can't read or encode, or one
 *     too large), with whatever body: the API (or the gateway in front of it)
 *     refused this body, so this transaction never reached CheckTx and never
 *     will. These are not retried, and the nonce of a refusal that does not
 *     say it is held, used, or spent is free again.
 *   - **Pending** returns `BroadcastResult{ success: false, pending: true }`
 *     without a `txHash`, its nonce held: a repeat of a transaction CometBFT
 *     already holds ("tx already exists in cache", which the API relays as an
 *     RPC error): the same signed bytes were seen, but whether they are
 *     accepted is unknown; any other 4xx (401, 402, 403, 408, 429, …: an API
 *     key refused, a rate limit), which refuses the request, not the
 *     transaction, and which the same body may pass later; and any 4xx to a
 *     `repeat`, which reached no CheckTx itself but says nothing about the
 *     earlier post, which may still land. Confirm by the account's nonce
 *     state (`ConsensusClient.isNonceUsed`) before posting it again.
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
    if (isClientError(response.status)) {
      return text.includes(TX_IN_CACHE) ? alreadyInCache(text) : clientError(response.status, text, opts);
    }
    // A non-JSON body means we didn't reach the API server's tx handler
    // (proxy/gateway error page) — transport-level, so throw to allow retry.
    throw new TxTransportError(`HTTP ${response.status} from ${url}: non-JSON response body`);
  }

  if (typeof body.error === 'string' && body.error.includes(TX_IN_CACHE)) {
    return alreadyInCache(body.error);
  }

  if (isClientError(response.status)) {
    return clientError(response.status, typeof body.error === 'string' ? body.error : text, opts);
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

/** The result of a repeat of a transaction CometBFT already holds: pending. */
function alreadyInCache(rawLog: string): BroadcastResult {
  return {
    success: false,
    pending: true,
    errorMessage:
      'unconfirmed: CometBFT already holds this transaction, which is in CheckTx, in the mempool, ' +
      "committed, or about to be refused; confirm it by the account's nonce state",
    rawLog,
  };
}

/** A 4xx: this request was refused before it reached CheckTx. */
function isClientError(status: number): boolean {
  return status >= 400 && status < 500;
}

/**
 * The 4xx statuses a request's body causes (a body the API can't read or
 * encode, one too large, one of another media type): the same body is
 * refused every time.
 */
const BODY_REFUSALS = new Set([400, 413, 415, 422]);

/** The longest part of a refused request's body a result carries. */
const MAX_REFUSAL_DETAIL = 500;

/**
 * The result of a request the API (or a gateway in front of it) refused with
 * a 4xx, `detail` being its error or body text. The request never reached
 * CheckTx, but that says nothing of an earlier post of the same transaction,
 * which may still land, so only the first post of one, refused for its body,
 * is a refusal whose nonce is given back. Any other is pending, its nonce
 * held: a 4xx to a repeat, and one the body doesn't cause (an API key
 * refused, a rate limit), which the same body may pass later. Neither is a
 * transport failure to retry at once.
 */
function clientError(status: number, detail: string, opts: SubmitTxOptions): BroadcastResult {
  const trimmed = detail.trim().slice(0, MAX_REFUSAL_DETAIL);
  const answer = `HTTP ${status}${trimmed ? `: ${trimmed}` : ''}`;
  if (opts.repeat) {
    return {
      success: false,
      pending: true,
      errorMessage:
        `${answer}; this post was refused before CheckTx, but an earlier post of the same transaction ` +
        "may still land, so its nonce stays held; confirm it by the account's nonce state",
      rawLog: answer,
    };
  }
  if (!BODY_REFUSALS.has(status)) {
    return {
      success: false,
      pending: true,
      errorMessage:
        `${answer}; the request was refused before CheckTx for a reason other than its body, so its ` +
        'nonce stays held to post the same transaction again',
      rawLog: answer,
    };
  }
  return { success: false, errorMessage: answer, rawLog: answer };
}

/**
 * The error a write's result that is not `success` is thrown as by the
 * `WillowClient` and `WillowData` writes: a {@link TransactionSubmitError}
 * (`TX_SUBMIT_FAILED`) carrying the result and its submission (DID, nonce,
 * and signed body), so a pending write can be confirmed and a refused one
 * sent again. A result without a submission gives a plain `Error`.
 */
export function writeNotAccepted(what: string, result: BroadcastResult): Error {
  const message = `${what} failed: ${result.errorMessage ?? result.rawLog ?? 'unknown'}`;
  if (!result.submission) return new Error(message);
  return new TransactionSubmitError(message, 'TX_SUBMIT_FAILED', { ...result.submission, result });
}
