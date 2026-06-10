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

export interface SubmitTxOptions {
  apiKey?: string;
  timeoutMs?: number;
  /** Extra headers (e.g. DID auth) to send with the request. */
  headers?: Record<string, string>;
}

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
    body: JSON.stringify(txWrapper),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30_000),
  });

  const body = (await response.json().catch(() => ({}))) as {
    success?: boolean;
    data?: { tx_hash: string; code: number; log: string };
    error?: string;
  };

  if (!response.ok || !body.success || !body.data) {
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
