// GraphQL subscriptions over WebSocket.
//
// Thin wrapper around `/graphql/ws` on either the validator or an indexer,
// speaking the `graphql-transport-ws` protocol:
//
// 1. Client connects and sends `connection_init`
// 2. Server responds with `connection_ack`
// 3. Client sends `subscribe` with a GraphQL subscription query
// 4. Server streams `next` messages as matching events arrive
// 5. Either side sends `complete` to end the subscription
//
// The `source` option picks which server:
//   - `'validator'` (default): consensus-verified chain-tip events
//   - `'indexer'`: the indexer's own event bus (e.g. `IndexedDataStored`
//     when it submits a new chain-tip block). Useful for subgroves where
//     the validator's retention is too short (or `VerifyOnly`) to see the
//     tail.
//
// Reconnection: by default the subscription reconnects automatically on
// unexpected disconnect with exponential backoff. For `source: 'indexer'`
// reconnects pick the next-best indexer via discovery (the failing
// indexer is evicted from the cache), so a dead indexer won't keep the
// caller pinned to it. Set `reconnect: false` to opt out.

import type { WillowIndexers } from "../indexers";
import { effectiveQueryEndpoint } from "../indexers";
import { WillowError } from "../types";

export type UnsubscribeFn = () => void;

export type SubscribeSource = "validator" | "indexer";

/**
 * Minimal WebSocket surface the subscription client needs. Satisfied by
 * the browser/Node 22+ global `WebSocket` and by the `ws` package.
 */
export interface WebSocketLike {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(type: string, listener: (event: any) => void): void;
}

/** Constructor shape for an injectable WebSocket implementation. */
export type WebSocketConstructor = new (
  url: string,
  protocols?: string | string[],
) => WebSocketLike;

export interface WillowSubscriptionsOptions {
  /**
   * WebSocket implementation to use. Defaults to `globalThis.WebSocket`,
   * which exists in browsers and Node 22+. On older Node versions there is
   * no global — pass an implementation (e.g. the `ws` package's `WebSocket`
   * class) or `subscribe` throws `WEBSOCKET_UNAVAILABLE`.
   */
  webSocket?: WebSocketConstructor;
}

// readyState OPEN per the WHATWG WebSocket spec (shared by every implementation).
const WS_OPEN = 1;

export interface SubscribeOptions {
  /** Optional GraphQL variables. */
  variables?: Record<string, any>;
  /** Optional operation name. */
  operationName?: string;
  /** Called on connection-level errors (parse, transport). */
  onError?: (err: unknown) => void;
  /**
   * Called when the subscription is definitively over and will not be
   * reconnected — either because the server sent `complete`, the caller
   * unsubscribed, or reconnection gave up / was disabled. Not called on
   * transient disconnects when `reconnect: true`.
   */
  onComplete?: () => void;
  /** Arbitrary payload forwarded on `connection_init` (e.g., auth). */
  connectionPayload?: Record<string, any>;
  /**
   * Which server to open the WebSocket against.
   *
   * - `'validator'` (default): `{apiUrl}/graphql/ws`. Consensus-verified
   *   chain-tip events. Use this for real-time data on subgroves that
   *   have chain-tip retention.
   * - `'indexer'`: picks the best-performing indexer for the subgrove via
   *   discovery (or the configured `indexerUrl` override) and connects
   *   to its `/graphql/ws`. The indexer fires `IndexedDataStored` events
   *   at submission time — useful for `VerifyOnly` subgroves where the
   *   validator has no tail, or for chart UIs that want to react to the
   *   indexer's ingest pace rather than the consensus commit pace.
   */
  source?: SubscribeSource;
  /**
   * Automatically reconnect on unexpected disconnects. Defaults to
   * `true`. Set to `false` for the classic "subscription ends on
   * close" behavior.
   *
   * This is reconnect-only — messages that were in flight when the
   * socket dropped are not replayed, and the new connection may
   * redeliver events the old one already emitted. Callers that need
   * exactly-once should dedupe by a stable field (e.g., block number
   * or entity id) themselves.
   */
  reconnect?: boolean;
  /**
   * Maximum number of reconnection attempts before giving up. Defaults
   * to `Infinity` (keep trying forever). When exhausted, `onComplete`
   * fires.
   */
  maxReconnectAttempts?: number;
  /**
   * Initial reconnect delay in milliseconds. Doubles on each failure up
   * to `maxReconnectBackoffMs`. Defaults to 500.
   */
  reconnectBackoffMs?: number;
  /**
   * Maximum reconnect delay in milliseconds. Defaults to 30 000
   * (30 seconds).
   */
  maxReconnectBackoffMs?: number;
  /**
   * Called when a reconnection attempt is scheduled. `attempt` is
   * 1-indexed (first retry is `1`). Useful for surfacing "reconnecting…"
   * UI without polluting `onError`.
   */
  onReconnect?: (attempt: number, delayMs: number) => void;
}

interface ClientMessage {
  type: string;
  id?: string;
  payload?: unknown;
}

interface ServerMessage {
  type: string;
  id?: string;
  payload?: {
    data?: any;
    errors?: any[];
  };
}

/** Convert an http(s)://host/path URL into its ws(s) counterpart. */
function toWsUrl(apiUrl: string): string {
  if (apiUrl.startsWith("https://")) return "wss://" + apiUrl.slice("https://".length);
  if (apiUrl.startsWith("http://")) return "ws://" + apiUrl.slice("http://".length);
  // Relative URL (e.g., "/willow-api" in Vite dev proxy): build from window.location
  if (apiUrl.startsWith("/") && typeof globalThis !== "undefined" && (globalThis as any).location) {
    const loc = (globalThis as any).location;
    const scheme = loc.protocol === "https:" ? "wss:" : "ws:";
    return `${scheme}//${loc.host}${apiUrl}`;
  }
  return apiUrl;
}

export class WillowSubscriptions {
  private apiUrl: string;
  private indexers?: WillowIndexers;
  private counter = 0;
  private webSocketImpl?: WebSocketConstructor;

  constructor(apiUrl: string, indexers?: WillowIndexers, options?: WillowSubscriptionsOptions) {
    this.apiUrl = apiUrl;
    this.indexers = indexers;
    this.webSocketImpl = options?.webSocket;
  }

  /**
   * Subscribe to a GraphQL subscription and receive streamed updates.
   *
   * Returns an unsubscribe function that sends `complete`, closes the
   * WebSocket, and cancels any pending reconnection. Callers should
   * invoke it on component unmount / cleanup.
   *
   * With `source: 'indexer'`, this async-resolves the best-performing
   * indexer for the subgrove via discovery (or the configured
   * `indexerUrl` override) before opening the socket. On a reconnect,
   * the SDK re-resolves — the previously-used indexer is evicted from
   * the discovery cache first so failover to a different indexer is
   * automatic.
   *
   * Requires a WebSocket implementation: the global `WebSocket` (browsers,
   * Node 22+) or one injected via the constructor's `webSocket` option.
   * Throws a `WillowError` with code `WEBSOCKET_UNAVAILABLE` when neither
   * is present (e.g. Node ≤ 20 without the `ws` package).
   *
   * @param subgroveId - Subgrove ID — used for indexer selection when
   *   `source: 'indexer'`; otherwise informational.
   * @param query - GraphQL subscription document
   * @param onNext - Called with each incoming data payload
   * @param options - Optional variables, operation name, error handlers,
   *   `source` selection, and reconnection behavior
   */
  subscribe(
    subgroveId: string,
    query: string,
    onNext: (payload: { data?: any; errors?: any[] }) => void,
    options: SubscribeOptions = {},
  ): UnsubscribeFn {
    const WebSocketImpl =
      this.webSocketImpl ??
      ((globalThis as any).WebSocket as WebSocketConstructor | undefined);
    if (!WebSocketImpl) {
      throw new WillowError(
        "No WebSocket implementation available. A global WebSocket exists in " +
          "browsers and Node 22+; on older Node versions pass one (e.g. the " +
          "`ws` package's WebSocket class) via `new WillowSubscriptions(url, " +
          "indexers, { webSocket })` or the WillowClient `webSocket` config.",
        "WEBSOCKET_UNAVAILABLE",
      );
    }

    const source: SubscribeSource = options.source ?? "validator";
    const reconnectEnabled = options.reconnect ?? true;
    const maxAttempts = options.maxReconnectAttempts ?? Infinity;
    const initialBackoff = options.reconnectBackoffMs ?? 500;
    const maxBackoff = options.maxReconnectBackoffMs ?? 30_000;

    // Keep the subscription ID stable across reconnects. The graphql-ws
    // `id` is only meaningful within a single socket — reusing it on a
    // new socket is fine (the server treats it as a fresh subscribe).
    // Using a stable id keeps `next`/`error`/`complete` filtering
    // consistent across both paths in the switch below.
    const id = `sub-${++this.counter}-${Date.now()}`;

    let socket: WebSocketLike | null = null;
    let closedByClient = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempts = 0;
    // The last indexer we successfully wired up against, so we can evict
    // it on reconnect failover. `null` for validator mode or before the
    // first indexer resolve.
    let lastIndexerDid: string | null = null;

    const sendOn = (s: WebSocketLike, msg: ClientMessage) => {
      if (s.readyState === WS_OPEN) {
        s.send(JSON.stringify(msg));
      }
    };

    const clearReconnectTimer = () => {
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const scheduleReconnect = () => {
      if (closedByClient || !reconnectEnabled) {
        options.onComplete?.();
        return;
      }
      if (attempts >= maxAttempts) {
        options.onComplete?.();
        return;
      }
      attempts += 1;
      const delay = Math.min(
        initialBackoff * Math.pow(2, attempts - 1),
        maxBackoff,
      );
      options.onReconnect?.(attempts, delay);
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        void openConnection();
      }, delay);
    };

    const wireSocket = (wsUrl: string) => {
      if (closedByClient) return;
      socket = new WebSocketImpl(wsUrl, "graphql-transport-ws");
      const s = socket;

      s.addEventListener("open", () => {
        sendOn(s, { type: "connection_init", payload: options.connectionPayload ?? {} });
      });

      s.addEventListener("message", (ev: { data?: unknown }) => {
        let msg: ServerMessage;
        try {
          msg = JSON.parse(String(ev.data));
        } catch (err) {
          options.onError?.(err);
          return;
        }

        switch (msg.type) {
          case "connection_ack":
            // Connection is usable — reset the retry counter so a later
            // disconnect after a good run doesn't inherit a stale
            // backoff from earlier failed attempts.
            attempts = 0;
            sendOn(s, {
              type: "subscribe",
              id,
              payload: {
                query,
                ...(options.variables ? { variables: options.variables } : {}),
                ...(options.operationName ? { operationName: options.operationName } : {}),
              },
            });
            break;
          case "next":
            if (msg.id === id && msg.payload) onNext(msg.payload);
            break;
          case "error":
            if (msg.id === id) options.onError?.(msg.payload);
            break;
          case "complete":
            // Server said the subscription is finished — this is a
            // definitive end, not a transient failure. Don't reconnect.
            if (msg.id === id) {
              closedByClient = true;
              options.onComplete?.();
            }
            break;
          case "ping":
            sendOn(s, { type: "pong" });
            break;
          case "pong":
            // no-op
            break;
          default:
            // Unknown type — ignore
            break;
        }
      });

      s.addEventListener("error", (ev) => {
        options.onError?.(ev);
      });

      s.addEventListener("close", () => {
        if (closedByClient) {
          return;
        }
        // Socket closed unexpectedly. Either reconnect, or give up and
        // surface completion depending on options.
        scheduleReconnect();
      });
    };

    const openConnection = async () => {
      if (closedByClient) return;

      if (source === "validator") {
        wireSocket(toWsUrl(this.apiUrl.replace(/\/$/, "")) + "/graphql/ws");
        return;
      }

      // `indexer`: resolve an endpoint, then open. An explicit
      // `indexerUrl` override on the client surfaces via
      // `WillowIndexers.forSubgrove` as a single synthetic entry, so we
      // don't need special-casing here.
      if (!this.indexers) {
        options.onError?.(
          new Error(
            "Cannot subscribe with source='indexer': no WillowIndexers " +
              "client was provided. Either pass one to WillowSubscriptions " +
              "directly, or construct via WillowClient which wires it up.",
          ),
        );
        closedByClient = true;
        options.onComplete?.();
        return;
      }

      // On reconnect, evict the indexer we just lost so the discovery
      // layer picks a different one. For the first attempt this is a
      // no-op (lastIndexerDid is null).
      if (lastIndexerDid) {
        this.indexers.evict(lastIndexerDid);
      }

      try {
        const candidates = await this.indexers.forSubgrove(subgroveId);
        if (candidates.length === 0) {
          options.onError?.(
            new Error(
              `No indexer serves subgrove "${subgroveId}" — cannot open ` +
                "indexer subscription",
            ),
          );
          // No indexers reachable. If reconnect is on we'll retry on
          // backoff (discovery cache may refresh in the meantime); if
          // off, this is terminal.
          if (reconnectEnabled) {
            scheduleReconnect();
          } else {
            closedByClient = true;
            options.onComplete?.();
          }
          return;
        }
        const chosen = candidates[0];
        lastIndexerDid = chosen.indexer_did;
        const endpoint = effectiveQueryEndpoint(chosen).replace(/\/$/, "");
        wireSocket(toWsUrl(endpoint) + "/graphql/ws");
      } catch (err) {
        options.onError?.(err);
        // Discovery itself failed (validator unreachable, etc.). Same
        // fork: schedule a retry if reconnect is on.
        if (reconnectEnabled) {
          scheduleReconnect();
        } else {
          closedByClient = true;
          options.onComplete?.();
        }
      }
    };

    void openConnection();

    return () => {
      closedByClient = true;
      clearReconnectTimer();
      if (socket && socket.readyState === WS_OPEN) {
        sendOn(socket, { type: "complete", id });
      }
      try {
        socket?.close();
      } catch {
        // ignore
      }
    };
  }
}
