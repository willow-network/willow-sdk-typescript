// Tests for WillowSubscriptions — subscribe + source routing.
//
// We don't have a real WebSocket server here, so we substitute a fake
// WebSocket class into `globalThis` for the duration of each test. The
// fake captures the URL the client connected to (which is the core
// behavior we care about: does `source: 'indexer'` connect to the
// indexer endpoint, not the validator?) and lets us drive messages from
// the test body to exercise the `graphql-transport-ws` state machine.

import { WillowSubscriptions } from '../src/subscriptions';
import { WillowIndexers } from '../src/indexers';

// Mock the global fetch used by WillowIndexers' HttpClient so indexer
// discovery doesn't hit the network.
const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

class FakeWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static instances: FakeWebSocket[] = [];

  url: string;
  protocol: string;
  readyState: number = 0; // CONNECTING
  private listeners: Record<string, Array<(ev: any) => void>> = {};
  sent: string[] = [];

  constructor(url: string, protocol?: string) {
    this.url = url;
    this.protocol = protocol ?? '';
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, fn: (ev: any) => void) {
    (this.listeners[type] ||= []).push(fn);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.readyState = FakeWebSocket.CLOSED;
    this.fire('close', {});
  }

  // Test helpers:
  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.fire('open', {});
  }

  message(payload: any) {
    this.fire('message', { data: JSON.stringify(payload) });
  }

  fire(type: string, ev: any) {
    (this.listeners[type] ?? []).forEach((fn) => fn(ev));
  }

  static reset() {
    FakeWebSocket.instances = [];
  }
}

beforeEach(() => {
  FakeWebSocket.reset();
  (globalThis as any).WebSocket = FakeWebSocket;
  jest.clearAllMocks();
});

describe('WillowSubscriptions — validator source (default)', () => {
  it('connects to {apiUrl}/graphql/ws and completes the connect/subscribe handshake', () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    const seen: any[] = [];

    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { blockFinalized { height } }',
      (payload) => seen.push(payload),
    );

    // One socket, pointed at the validator.
    expect(FakeWebSocket.instances).toHaveLength(1);
    const ws = FakeWebSocket.instances[0];
    expect(ws.url).toBe('ws://validator:3031/graphql/ws');
    expect(ws.protocol).toBe('graphql-transport-ws');

    // Drive the graphql-transport-ws handshake.
    ws.open();
    expect(ws.sent).toHaveLength(1);
    expect(JSON.parse(ws.sent[0])).toEqual({
      type: 'connection_init',
      payload: {},
    });

    ws.message({ type: 'connection_ack' });
    expect(ws.sent).toHaveLength(2);
    const subMsg = JSON.parse(ws.sent[1]);
    expect(subMsg.type).toBe('subscribe');
    expect(subMsg.payload.query).toBe(
      'subscription { blockFinalized { height } }',
    );

    // Server streams a `next` event; onNext fires with the data payload.
    ws.message({
      type: 'next',
      id: subMsg.id,
      payload: { data: { blockFinalized: { height: 42 } } },
    });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({ data: { blockFinalized: { height: 42 } } });

    // Unsubscribe sends `complete` and closes the socket.
    unsubscribe();
    const completeMsg = JSON.parse(ws.sent[2]);
    expect(completeMsg).toEqual({ type: 'complete', id: subMsg.id });
  });

  it('passes variables and operationName through the subscribe payload', () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    subs.subscribe(
      'sg',
      'subscription Foo($a: String) { x(a: $a) }',
      () => {},
      { variables: { a: 'hello' }, operationName: 'Foo' },
    );

    const ws = FakeWebSocket.instances[0];
    ws.open();
    ws.message({ type: 'connection_ack' });
    const subMsg = JSON.parse(ws.sent[1]);
    expect(subMsg.payload.variables).toEqual({ a: 'hello' });
    expect(subMsg.payload.operationName).toBe('Foo');
  });
});

describe('WillowSubscriptions — indexer source', () => {
  function stubDiscovery(endpoint: string) {
    mockFetch.mockResolvedValue(
      jsonResponse({
        success: true,
        data: [
          {
            indexer_did: 'did:willow:indexer-1',
            subgroves: ['my-subgrove'],
            stake_amount: 1,
            endpoint,
            query_endpoint: endpoint,
            status: 'active',
            performance_score: 100,
            last_update: 0,
          },
        ],
      }),
    );
  }

  it('resolves an indexer via discovery and connects to its /graphql/ws', async () => {
    stubDiscovery('http://my-indexer:3032');
    const indexers = new WillowIndexers('http://validator:3031');
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    subs.subscribe('my-subgrove', 'subscription { x }', () => {}, {
      source: 'indexer',
    });

    // Discovery is async; wait for the macrotask queue to drain.
    await new Promise((r) => setTimeout(r, 0));

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].url).toBe(
      'ws://my-indexer:3032/graphql/ws',
    );
  });

  it('honors the explicit indexerUrl override without calling discovery', async () => {
    const indexers = new WillowIndexers('http://validator:3031', {
      indexerUrl: 'http://pinned:3032',
    });
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    subs.subscribe('any-subgrove', 'subscription { x }', () => {}, {
      source: 'indexer',
    });

    await new Promise((r) => setTimeout(r, 0));

    // Discovery endpoint must not have been called.
    expect(mockFetch).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].url).toBe('ws://pinned:3032/graphql/ws');
  });

  it('calls onError when no indexer serves the subgrove', async () => {
    mockFetch.mockResolvedValue(jsonResponse({ success: true, data: [] }));
    const indexers = new WillowIndexers('http://validator:3031');
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    let err: unknown = null;
    // `reconnect: false` so the test doesn't leak a retry timer —
    // with reconnect enabled the no-candidates case schedules a
    // backoff retry (covered separately in the reconnect test block).
    subs.subscribe('unserved', 'subscription { x }', () => {}, {
      source: 'indexer',
      reconnect: false,
      onError: (e) => {
        err = e;
      },
    });

    await new Promise((r) => setTimeout(r, 0));

    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(err).toBeInstanceOf(Error);
    expect(String(err)).toMatch(/unserved/);
  });

  it("calls onError when source='indexer' but no WillowIndexers was provided", () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    let err: unknown = null;
    subs.subscribe('sg', 'subscription { x }', () => {}, {
      source: 'indexer',
      onError: (e) => {
        err = e;
      },
    });

    expect(err).toBeInstanceOf(Error);
    expect(String(err)).toMatch(/no WillowIndexers/i);
  });
});

describe('WillowSubscriptions — reconnect', () => {
  // Use fake timers so we can deterministically advance the backoff
  // without waiting half a second per test.
  beforeEach(() => {
    jest.useFakeTimers();
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  it('reconnects on unexpected close by default (validator source)', () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
    );

    expect(FakeWebSocket.instances).toHaveLength(1);
    const first = FakeWebSocket.instances[0];

    // Simulate unexpected disconnect before any complete frame arrives.
    first.close();

    // Reconnect is scheduled — no new socket yet, the timer hasn't fired.
    expect(FakeWebSocket.instances).toHaveLength(1);

    // Advance past the initial backoff (500ms by default).
    jest.advanceTimersByTime(500);

    expect(FakeWebSocket.instances).toHaveLength(2);
    // Second socket points at the same URL — validator mode.
    expect(FakeWebSocket.instances[1].url).toBe(
      'ws://validator:3031/graphql/ws',
    );

    unsubscribe();
  });

  it('stops reconnecting when the caller unsubscribes mid-backoff', () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
    );

    FakeWebSocket.instances[0].close();
    // Cancel before the timer fires.
    unsubscribe();
    jest.advanceTimersByTime(10_000);

    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('does not reconnect when options.reconnect is false', () => {
    const completes: number[] = [];
    const subs = new WillowSubscriptions('http://validator:3031');
    subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      { reconnect: false, onComplete: () => completes.push(Date.now()) },
    );

    FakeWebSocket.instances[0].close();
    // Even after any backoff window, no reconnect.
    jest.advanceTimersByTime(60_000);

    expect(FakeWebSocket.instances).toHaveLength(1);
    // onComplete fired on the disconnect (no reconnect = definitive end).
    expect(completes).toHaveLength(1);
  });

  it('does not reconnect after a server-sent `complete` frame', () => {
    const subs = new WillowSubscriptions('http://validator:3031');
    const completes: number[] = [];
    subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      { onComplete: () => completes.push(Date.now()) },
    );

    const ws = FakeWebSocket.instances[0];
    ws.open();
    ws.message({ type: 'connection_ack' });
    const subId = JSON.parse(ws.sent[1]).id;

    // Server says the subscription is finished — definitive end,
    // no reconnect.
    ws.message({ type: 'complete', id: subId });
    ws.close();
    jest.advanceTimersByTime(60_000);

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(completes).toHaveLength(1);
  });

  it('uses exponential backoff between attempts', () => {
    const onReconnect = jest.fn();
    const subs = new WillowSubscriptions('http://validator:3031');
    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      {
        onReconnect,
        // Smaller params to keep the test fast & predictable.
        reconnectBackoffMs: 100,
        maxReconnectBackoffMs: 1_000,
      },
    );

    // First close — backoff = 100ms.
    FakeWebSocket.instances[0].close();
    expect(onReconnect).toHaveBeenLastCalledWith(1, 100);
    jest.advanceTimersByTime(100);
    expect(FakeWebSocket.instances).toHaveLength(2);

    // Second close before ack — backoff = 200ms.
    FakeWebSocket.instances[1].close();
    expect(onReconnect).toHaveBeenLastCalledWith(2, 200);
    jest.advanceTimersByTime(200);
    expect(FakeWebSocket.instances).toHaveLength(3);

    // Third close — backoff = 400ms.
    FakeWebSocket.instances[2].close();
    expect(onReconnect).toHaveBeenLastCalledWith(3, 400);

    unsubscribe();
  });

  it('caps backoff at maxReconnectBackoffMs', () => {
    const onReconnect = jest.fn();
    const subs = new WillowSubscriptions('http://validator:3031');
    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      {
        onReconnect,
        reconnectBackoffMs: 100,
        maxReconnectBackoffMs: 250,
      },
    );

    // After a few failures the cap should kick in.
    for (let i = 0; i < 5; i++) {
      const last = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
      last.close();
      jest.advanceTimersByTime(250);
    }

    // Later calls should all be <= 250.
    const delays = onReconnect.mock.calls.map((c) => c[1]);
    for (const d of delays) {
      expect(d).toBeLessThanOrEqual(250);
    }

    unsubscribe();
  });

  it('resets the attempt counter after a successful connection_ack', () => {
    const onReconnect = jest.fn();
    const subs = new WillowSubscriptions('http://validator:3031');
    const unsubscribe = subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      { onReconnect, reconnectBackoffMs: 100 },
    );

    // Fail once (backoff = 100).
    FakeWebSocket.instances[0].close();
    expect(onReconnect).toHaveBeenLastCalledWith(1, 100);
    jest.advanceTimersByTime(100);

    // Succeed: open + ack on the replacement socket.
    const second = FakeWebSocket.instances[1];
    second.open();
    second.message({ type: 'connection_ack' });

    // Then fail again. Counter should have reset — next attempt = 1
    // (delay 100), not 2 (delay 200).
    second.close();
    expect(onReconnect).toHaveBeenLastCalledWith(1, 100);

    unsubscribe();
  });

  it('gives up after maxReconnectAttempts and calls onComplete', () => {
    const onComplete = jest.fn();
    const subs = new WillowSubscriptions('http://validator:3031');
    subs.subscribe(
      'my-subgrove',
      'subscription { x }',
      () => {},
      {
        maxReconnectAttempts: 2,
        reconnectBackoffMs: 100,
        onComplete,
      },
    );

    // First close: attempt 1 scheduled.
    FakeWebSocket.instances[0].close();
    jest.advanceTimersByTime(100);
    expect(FakeWebSocket.instances).toHaveLength(2);

    // Second close: attempt 2 scheduled (the last one allowed).
    FakeWebSocket.instances[1].close();
    jest.advanceTimersByTime(200);
    expect(FakeWebSocket.instances).toHaveLength(3);

    // Third close: we've used 2 attempts, next schedule should give up
    // and call onComplete instead of opening a new socket.
    FakeWebSocket.instances[2].close();
    jest.advanceTimersByTime(10_000);

    expect(FakeWebSocket.instances).toHaveLength(3);
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it('evicts the dead indexer and fails over to a different one', async () => {
    // Two indexers serve the subgrove. After the first one drops, the
    // SDK should evict it and pick the second.
    mockFetch.mockResolvedValue(
      jsonResponse({
        success: true,
        data: [
          {
            indexer_did: 'did:willow:indexer-primary',
            subgroves: ['sg'],
            stake_amount: 1,
            endpoint: 'http://primary:3032',
            query_endpoint: 'http://primary:3032',
            status: 'active',
            performance_score: 100,
            last_update: 0,
          },
          {
            indexer_did: 'did:willow:indexer-backup',
            subgroves: ['sg'],
            stake_amount: 1,
            endpoint: 'http://backup:3032',
            query_endpoint: 'http://backup:3032',
            status: 'active',
            performance_score: 50,
            last_update: 0,
          },
        ],
      }),
    );
    const indexers = new WillowIndexers('http://validator:3031');
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    const unsubscribe = subs.subscribe(
      'sg',
      'subscription { x }',
      () => {},
      { source: 'indexer', reconnectBackoffMs: 100 },
    );

    // Real timers briefly so the async discovery fetch can resolve and
    // the first socket opens. Then fake timers for the backoff.
    jest.useRealTimers();
    await new Promise((r) => setTimeout(r, 10));
    jest.useFakeTimers();

    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].url).toContain('primary');

    // Drop the primary. The SDK evicts it from the discovery cache and
    // the next call to forSubgrove returns only the backup.
    FakeWebSocket.instances[0].close();

    // Timer + async discovery: advance timers then drain microtasks.
    jest.advanceTimersByTime(100);
    jest.useRealTimers();
    await new Promise((r) => setTimeout(r, 10));

    expect(FakeWebSocket.instances).toHaveLength(2);
    expect(FakeWebSocket.instances[1].url).toContain('backup');

    unsubscribe();
  });
});
