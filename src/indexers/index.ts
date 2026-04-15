// Indexer discovery client
//
// Wraps the validator's `GET /indexers` endpoint and exposes a cached view
// that SDK query routers use to pick a backend for a given subgrove.
//
// When the SDK is constructed with an explicit `indexerUrl`, discovery is
// bypassed and every lookup returns a synthetic single-entry list pointing
// at that URL. The routing layer treats the "explicit" and "discovered"
// cases uniformly via `effectiveQueryEndpoint`.

import axios, { AxiosInstance } from "axios";
import { ApiResponse } from "../types";

/**
 * Matches `ApiIndexerInfo` on the server side.
 * See `crates/indexing/src/indexing_service.rs`.
 */
export interface ApiIndexerInfo {
  indexer_did: string;
  subgroves: string[];
  stake_amount: number;
  /** Monitoring / health endpoint. */
  endpoint: string;
  /** Preferred query endpoint. When absent, callers fall back to `endpoint`. */
  query_endpoint?: string;
  status: string;
  performance_score: number;
  last_update: number;
}

/** Returns the URL a client should POST GraphQL / SQL queries to. */
export function effectiveQueryEndpoint(info: ApiIndexerInfo): string {
  return info.query_endpoint ?? info.endpoint;
}

/** How long a successful `/indexers` response is reused before re-fetching. */
const DEFAULT_CACHE_TTL_MS = 30_000;

interface CacheEntry {
  data: ApiIndexerInfo[];
  fetchedAt: number;
}

export interface WillowIndexersOptions {
  /**
   * When set, skip discovery and return this URL for every query. Useful for
   * pinning a specific indexer (local dev, testing, enterprise deployments).
   */
  indexerUrl?: string;
  /** Cache TTL override (milliseconds). Default: 30 000. */
  cacheTtlMs?: number;
}

/**
 * Client for the validator's indexer-discovery endpoint.
 *
 * Usage:
 * ```ts
 * const indexers = new WillowIndexers("http://validator:3031");
 * const servers = await indexers.forSubgrove("my-subgrove");
 * // servers is sorted by performance_score desc
 * ```
 */
export class WillowIndexers {
  private api: AxiosInstance;
  private apiUrl: string;
  private indexerUrl?: string;
  private cacheTtlMs: number;
  private cache?: CacheEntry;
  private inflight?: Promise<ApiIndexerInfo[]>;

  constructor(apiUrl: string, options: WillowIndexersOptions = {}) {
    this.apiUrl = apiUrl;
    this.indexerUrl = options.indexerUrl;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.api = axios.create({
      baseURL: apiUrl,
      headers: { "Content-Type": "application/json" },
    });
  }

  /**
   * Whether the SDK was configured with an explicit indexer URL. When true,
   * `list`/`forSubgrove` return a synthetic single-entry list and never hit
   * the validator's `/indexers` endpoint.
   */
  hasExplicitOverride(): boolean {
    return !!this.indexerUrl;
  }

  /** Force the next lookup to re-fetch from `/indexers`. */
  invalidate(): void {
    this.cache = undefined;
    this.inflight = undefined;
  }

  /**
   * Return all registered indexers, cached for `cacheTtlMs`.
   */
  async list(): Promise<ApiIndexerInfo[]> {
    if (this.indexerUrl) {
      return [this.syntheticEntry(this.indexerUrl)];
    }

    const now = Date.now();
    if (this.cache && now - this.cache.fetchedAt < this.cacheTtlMs) {
      return this.cache.data;
    }

    if (this.inflight) return this.inflight;

    this.inflight = (async () => {
      try {
        const resp = await this.api.get<ApiResponse<ApiIndexerInfo[]>>("/indexers");
        const data = resp.data?.data ?? [];
        this.cache = { data, fetchedAt: Date.now() };
        return data;
      } finally {
        this.inflight = undefined;
      }
    })();

    return this.inflight;
  }

  /**
   * Return active indexers that serve `subgroveId`, sorted by
   * `performance_score` descending (best candidate first).
   *
   * When an explicit `indexerUrl` override is set, always returns a single
   * synthetic entry — the caller doesn't need to special-case this.
   */
  async forSubgrove(subgroveId: string): Promise<ApiIndexerInfo[]> {
    if (this.indexerUrl) {
      return [this.syntheticEntry(this.indexerUrl)];
    }

    const all = await this.list();
    return all
      .filter(
        (i) => i.status === "active" && i.subgroves.includes(subgroveId),
      )
      .sort((a, b) => b.performance_score - a.performance_score);
  }

  /**
   * Evict an indexer from the cache (e.g., after a 5xx response). Next
   * lookup will re-fetch from the validator.
   */
  evict(indexerDid: string): void {
    if (!this.cache) return;
    this.cache = {
      data: this.cache.data.filter((i) => i.indexer_did !== indexerDid),
      fetchedAt: this.cache.fetchedAt,
    };
  }

  private syntheticEntry(url: string): ApiIndexerInfo {
    return {
      indexer_did: "explicit-override",
      subgroves: [],           // matched via forSubgrove short-circuit
      stake_amount: 0,
      endpoint: url,
      query_endpoint: url,
      status: "active",
      performance_score: 100,
      last_update: 0,
    };
  }
}
