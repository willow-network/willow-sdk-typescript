/**
 * End-to-end client-side completeness check.
 *
 * Composes the two halves of Willow's crypto-completeness protocol on top of
 * the pure {@link verifyServedEvents} re-hash:
 *
 *   1. The on-chain ANCHOR — the per-`(subgrove, block)` `events_commitment`,
 *      read from the validator via a CometBFT `abci_query` against the
 *      `/store/events_commitment/{subgrove}/{block}` path. This is the trusted
 *      32-byte keccak-256 the chain attests to.
 *   2. The indexer-served PREIMAGE — the filter-matched logs for that block,
 *      fetched over HTTP from `/completeness/{subgrove}/{block}/matched-logs`.
 *
 * {@link CompletenessClient.verifyBlockCompleteness} fetches both, rebuilds the
 * canonical {@link Log} set from the served logs, re-hashes, and compares — so a
 * `true` means the indexer served exactly the complete, untampered set the chain
 * committed to, with no trust in the indexer.
 *
 * The validator RPC and the indexer base URL are distinct endpoints (the chain
 * holds the anchor; the indexer holds the preimage), so both are configured
 * separately here.
 */

import { HttpClient, HttpError } from "../internal/http";
import { base64ToBytes, hexToBytes } from "../internal/bytes";
import { type BlockNumber, type Log, verifyServedEvents } from "./index";

/** The on-chain anchor was found and decoded to a 32-byte commitment. */
const COMMITMENT_LEN = 32;

/**
 * One filter-matched log as served by the indexer's `matched-logs` endpoint.
 *
 * The endpoint returns many per-log fields (block/tx identifiers, indices,
 * `removed`); only `address`, `topics`, and `data` — the consensus-derivable,
 * commitment-bound fields — are read here. All three are `0x`-prefixed hex.
 */
export interface IndexedLog {
  /** Emitting contract address, `0x` + 40 hex (20 bytes). */
  address: string;
  /** Indexed topics, each `0x` + 64 hex (32 bytes). */
  topics: string[];
  /** Non-indexed event data, `0x`-prefixed hex (may be `"0x"` for empty). */
  data: string;
  /** Remaining fields (block_number, tx_hash, log_index, removed, …) ignored. */
  [extra: string]: unknown;
}

/** Shape of the indexer's `matched-logs` 200 response body. */
export interface MatchedLogsResponse {
  subgrove_id: string;
  block_number: number;
  count: number;
  matched_logs: IndexedLog[];
}

/** Shape of the `events_commitment` ABCI store-query value (JSON). */
interface AnchorValue {
  subgrove_id: string;
  block_number: number;
  events_commitment: string;
}

/** The CometBFT `abci_query` result shape this client reads. */
interface AbciQueryResult {
  response?: {
    code?: number;
    log?: string;
    info?: string;
    value?: string | null;
  };
}

/** Raised when the completeness check cannot be performed (no anchor, no preimage). */
export class CompletenessUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CompletenessUnavailableError";
  }
}

/**
 * Build the canonical {@link Log} set from a parsed `matched-logs` response
 * body. Pure (no I/O) so it can be gated directly against the authoritative
 * cross-language vector: pass a response body, get the exact `Log[]` that
 * {@link verifyServedEvents} re-hashes.
 *
 * Order is preserved as served — the commitment binds log order, so the
 * indexer's order is the canonical one.
 */
export function logsFromMatchedResponse(body: MatchedLogsResponse): Log[] {
  if (!body || !Array.isArray(body.matched_logs)) {
    throw new Error("matched-logs response missing `matched_logs` array");
  }
  return body.matched_logs.map((log, i) => {
    if (typeof log.address !== "string") {
      throw new Error(`matched log ${i}: address must be a hex string`);
    }
    if (!Array.isArray(log.topics)) {
      throw new Error(`matched log ${i}: topics must be an array`);
    }
    if (typeof log.data !== "string") {
      throw new Error(`matched log ${i}: data must be a hex string`);
    }
    return {
      address: hexToBytes(log.address),
      topics: log.topics.map((t, j) => {
        if (typeof t !== "string") {
          throw new Error(`matched log ${i}: topic ${j} must be a hex string`);
        }
        return hexToBytes(t);
      }),
      data: hexToBytes(log.data),
    };
  });
}

export interface CompletenessClientOptions {
  /** CometBFT RPC URL of a validator (for the `events_commitment` anchor). */
  consensusRpcUrl: string;
  /** Base URL of the indexer serving the `matched-logs` preimage. */
  indexerBaseUrl: string;
  /** Managed-tier API key, sent as `X-API-Key` to both endpoints. */
  apiKey?: string;
  /** Request timeout in milliseconds. Default: 30 000. */
  timeoutMs?: number;
  /** Injectable HTTP client for the indexer GET (mainly for tests). */
  http?: HttpClient;
}

/**
 * Fetches the on-chain anchor and the indexer-served preimage, then verifies
 * the served log set against the anchor — the full client-side completeness
 * check, end to end.
 */
export class CompletenessClient {
  private readonly consensusRpcUrl: string;
  private readonly indexerBaseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;
  private readonly http: HttpClient;

  constructor(options: CompletenessClientOptions) {
    if (!options.consensusRpcUrl) {
      throw new Error("CompletenessClient requires a consensusRpcUrl");
    }
    if (!options.indexerBaseUrl) {
      throw new Error("CompletenessClient requires an indexerBaseUrl");
    }
    this.consensusRpcUrl = options.consensusRpcUrl;
    this.indexerBaseUrl = options.indexerBaseUrl.replace(/\/+$/, "");
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.http =
      options.http ??
      new HttpClient({
        baseURL: this.indexerBaseUrl,
        headers: this.apiKey ? { "X-API-Key": this.apiKey } : {},
        timeoutMs: this.timeoutMs,
      });
  }

  /**
   * Read the on-chain `events_commitment` anchor for `(subgroveId, blockNumber)`
   * via a CometBFT `abci_query`.
   *
   * @returns the trusted 32-byte commitment.
   * @throws {CompletenessUnavailableError} if the chain has no commitment for
   *   the block (ABCI `code != 0`), i.e. the result is not verifiable.
   */
  async fetchAnchorCommitment(
    subgroveId: string,
    blockNumber: BlockNumber,
  ): Promise<Uint8Array> {
    const path = `/store/events_commitment/${subgroveId}/${blockNumber.toString()}`;
    const result = (await this.rpcRequest("abci_query", {
      path,
      data: "",
      prove: false,
    })) as AbciQueryResult;

    const response = result.response ?? {};
    const code = response.code ?? 0;
    if (code !== 0) {
      const detail = response.log || response.info || `code ${code}`;
      throw new CompletenessUnavailableError(
        `no on-chain events_commitment for ${subgroveId} block ${blockNumber}: ${detail}`,
      );
    }
    if (!response.value) {
      throw new CompletenessUnavailableError(
        `empty events_commitment value for ${subgroveId} block ${blockNumber}`,
      );
    }

    let anchor: AnchorValue;
    try {
      anchor = JSON.parse(
        new TextDecoder().decode(base64ToBytes(response.value)),
      ) as AnchorValue;
    } catch (err) {
      throw new Error(
        `failed to decode events_commitment value: ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }

    const commitment = hexToBytes(anchor.events_commitment);
    if (commitment.length !== COMMITMENT_LEN) {
      throw new Error(
        `events_commitment must be ${COMMITMENT_LEN} bytes, got ${commitment.length}`,
      );
    }
    return commitment;
  }

  /**
   * Fetch the indexer-served filter-matched logs for `(subgroveId, blockNumber)`.
   *
   * @throws {CompletenessUnavailableError} if the indexer has no retained
   *   matched logs for the block (404 / block not finalized).
   */
  async fetchMatchedLogs(
    subgroveId: string,
    blockNumber: BlockNumber,
  ): Promise<MatchedLogsResponse> {
    const path = `/completeness/${subgroveId}/${blockNumber.toString()}/matched-logs`;
    try {
      return await this.http.get<MatchedLogsResponse>(path);
    } catch (err) {
      if (
        err instanceof HttpError &&
        (err.status === 404 || err.status === 409)
      ) {
        throw new CompletenessUnavailableError(
          `no retained matched logs for ${subgroveId} block ${blockNumber}: ${
            err.apiError ?? `HTTP ${err.status}`
          }`,
        );
      }
      throw err;
    }
  }

  /**
   * Full client-side completeness check for `(subgroveId, blockNumber)`:
   * fetch the on-chain anchor, fetch the indexer's matched-log preimage,
   * rebuild the canonical log set, and verify it re-hashes to the anchor.
   *
   * @returns `true` iff the served logs are exactly the complete, untampered
   *   set the chain committed to.
   * @throws {CompletenessUnavailableError} if either the anchor or the preimage
   *   is unavailable (then the result is not verifiable, not "incomplete").
   */
  async verifyBlockCompleteness(
    subgroveId: string,
    blockNumber: BlockNumber,
  ): Promise<boolean> {
    const [commitment, response] = await Promise.all([
      this.fetchAnchorCommitment(subgroveId, blockNumber),
      this.fetchMatchedLogs(subgroveId, blockNumber),
    ]);
    const logs = logsFromMatchedResponse(response);
    return verifyServedEvents(commitment, blockNumber, logs);
  }

  /** Minimal CometBFT JSON-RPC call over `fetch` (matches ConsensusClient). */
  private async rpcRequest(method: string, params: unknown): Promise<unknown> {
    const response = await fetch(this.consensusRpcUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.apiKey ? { "X-API-Key": this.apiKey } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`RPC ${method}: HTTP ${response.status}`);
    }
    const data = (await response.json()) as {
      error?: unknown;
      result?: unknown;
    };
    if (data.error) {
      throw new Error(`RPC ${method} error: ${JSON.stringify(data.error)}`);
    }
    return data.result ?? {};
  }
}
