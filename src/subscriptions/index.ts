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

import type { WillowIndexers } from "../indexers";
import { effectiveQueryEndpoint } from "../indexers";

export type UnsubscribeFn = () => void;

export type SubscribeSource = "validator" | "indexer";

export interface SubscribeOptions {
  /** Optional GraphQL variables. */
  variables?: Record<string, any>;
  /** Optional operation name. */
  operationName?: string;
  /** Called on connection-level errors (parse, transport). */
  onError?: (err: unknown) => void;
  /** Called when the server sends a `complete` message or the socket closes cleanly. */
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

  constructor(apiUrl: string, indexers?: WillowIndexers) {
    this.apiUrl = apiUrl;
    this.indexers = indexers;
  }

  /**
   * Subscribe to a GraphQL subscription and receive streamed updates.
   *
   * Returns an unsubscribe function that sends `complete` and closes the
   * WebSocket. Callers should invoke it on component unmount / cleanup.
   *
   * With `source: 'indexer'`, this async-resolves the best-performing
   * indexer for the subgrove via discovery (or the configured indexer URL
   * override) before opening the socket. Connection failures during
   * discovery surface through `options.onError`.
   *
   * @param subgroveId - Subgrove ID — used for indexer selection when
   *   `source: 'indexer'`; otherwise informational.
   * @param query - GraphQL subscription document
   * @param onNext - Called with each incoming data payload
   * @param options - Optional variables, operation name, error handlers,
   *   and `source` selection
   */
  subscribe(
    subgroveId: string,
    query: string,
    onNext: (payload: { data?: any; errors?: any[] }) => void,
    options: SubscribeOptions = {},
  ): UnsubscribeFn {
    const source: SubscribeSource = options.source ?? "validator";

    // For validator mode we can open the socket synchronously. For indexer
    // mode we need a round-trip (or cache hit) to resolve the endpoint, so
    // the socket open is deferred. Either way, the returned unsubscribe
    // function is valid immediately — it cancels a pending connect if
    // called before the socket is up.
    let socket: WebSocket | null = null;
    let closedByClient = false;
    const id = `sub-${++this.counter}-${Date.now()}`;

    const sendOn = (s: WebSocket, msg: ClientMessage) => {
      if (s.readyState === WebSocket.OPEN) {
        s.send(JSON.stringify(msg));
      }
    };

    const wireSocket = (wsUrl: string) => {
      if (closedByClient) return;
      socket = new WebSocket(wsUrl, "graphql-transport-ws");
      const s = socket;

      s.addEventListener("open", () => {
        sendOn(s, { type: "connection_init", payload: options.connectionPayload ?? {} });
      });

      s.addEventListener("message", (ev: MessageEvent) => {
        let msg: ServerMessage;
        try {
          msg = JSON.parse(String((ev as any).data));
        } catch (err) {
          options.onError?.(err);
          return;
        }

        switch (msg.type) {
          case "connection_ack":
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
            if (msg.id === id) options.onComplete?.();
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
        if (!closedByClient) options.onComplete?.();
      });
    };

    if (source === "validator") {
      wireSocket(toWsUrl(this.apiUrl.replace(/\/$/, "")) + "/graphql/ws");
    } else {
      // `indexer`: resolve an endpoint, then open. An explicit `indexerUrl`
      // override on the client surfaces via `WillowIndexers.for_subgrove`
      // as a single synthetic entry, so we don't need special-casing here.
      if (!this.indexers) {
        options.onError?.(
          new Error(
            "Cannot subscribe with source='indexer': no WillowIndexers " +
              "client was provided. Either pass one to WillowSubscriptions " +
              "directly, or construct via WillowClient which wires it up.",
          ),
        );
        return () => {
          closedByClient = true;
        };
      }

      void (async () => {
        try {
          const candidates = await this.indexers!.forSubgrove(subgroveId);
          if (candidates.length === 0) {
            options.onError?.(
              new Error(
                `No indexer serves subgrove "${subgroveId}" — cannot open ` +
                  "indexer subscription",
              ),
            );
            return;
          }
          // Use the best-performing candidate. Failover-on-disconnect is a
          // follow-up — the WebSocket contract makes that nontrivial
          // because replayed messages from the new socket would duplicate.
          const endpoint = effectiveQueryEndpoint(candidates[0]).replace(/\/$/, "");
          wireSocket(toWsUrl(endpoint) + "/graphql/ws");
        } catch (err) {
          options.onError?.(err);
        }
      })();
    }

    return () => {
      closedByClient = true;
      if (socket && socket.readyState === WebSocket.OPEN) {
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
