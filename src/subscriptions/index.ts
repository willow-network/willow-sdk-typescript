// GraphQL subscriptions over WebSocket.
//
// Thin wrapper around the validator's `/graphql/ws` endpoint implementing
// the `graphql-transport-ws` protocol:
//
// 1. Client connects and sends `connection_init`
// 2. Server responds with `connection_ack`
// 3. Client sends `subscribe` with a GraphQL subscription query
// 4. Server streams `next` messages as matching events arrive
// 5. Either side sends `complete` to end the subscription
//
// Validator-only today. Indexer WebSocket support is deferred (tracked as
// follow-up) — the live-chart UX pattern is: initial load from indexer for
// history + ongoing updates from validator for chain-tip.

export type UnsubscribeFn = () => void;

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
  private counter = 0;

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl;
  }

  /**
   * Subscribe to a GraphQL subscription and receive streamed updates.
   *
   * Returns an unsubscribe function that sends `complete` and closes the
   * WebSocket. Callers should invoke it on component unmount / cleanup.
   *
   * @param subgroveId - Subgrove ID (not used by the wire protocol today,
   *   but reserved for future per-subgrove routing)
   * @param query - GraphQL subscription document
   * @param onNext - Called with each incoming data payload
   * @param options - Optional variables, operation name, error handlers
   */
  subscribe(
    _subgroveId: string,
    query: string,
    onNext: (payload: { data?: any; errors?: any[] }) => void,
    options: SubscribeOptions = {},
  ): UnsubscribeFn {
    const wsUrl = toWsUrl(this.apiUrl.replace(/\/$/, "")) + "/graphql/ws";
    const socket = new WebSocket(wsUrl, "graphql-transport-ws");
    const id = `sub-${++this.counter}-${Date.now()}`;
    let initialized = false;
    let closedByClient = false;

    const send = (msg: ClientMessage) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify(msg));
      }
    };

    socket.addEventListener("open", () => {
      send({ type: "connection_init", payload: options.connectionPayload ?? {} });
    });

    socket.addEventListener("message", (ev: MessageEvent) => {
      let msg: ServerMessage;
      try {
        msg = JSON.parse(String((ev as any).data));
      } catch (err) {
        options.onError?.(err);
        return;
      }

      switch (msg.type) {
        case "connection_ack":
          initialized = true;
          send({
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
          send({ type: "pong" });
          break;
        case "pong":
          // no-op
          break;
        default:
          // Unknown type — ignore
          break;
      }
    });

    socket.addEventListener("error", (ev) => {
      options.onError?.(ev);
    });

    socket.addEventListener("close", () => {
      if (!closedByClient) options.onComplete?.();
    });

    return () => {
      closedByClient = true;
      if (initialized && socket.readyState === WebSocket.OPEN) {
        send({ type: "complete", id });
      }
      try {
        socket.close();
      } catch {
        // ignore
      }
    };
  }
}
