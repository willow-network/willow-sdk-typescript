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

// Minimal jest mock for axios so WillowIndexers construction doesn't
// blow up — the indexer tests use a more elaborate setup, we just need
// `axios.create()` to return something with a `get` method.
jest.mock('axios', () => {
  const mockInstance = { get: jest.fn() };
  return {
    __esModule: true,
    default: { create: jest.fn(() => mockInstance) },
    _mockInstance: mockInstance,
  };
});

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
    const axios = require('axios')._mockInstance;
    axios.get.mockResolvedValue({
      data: {
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
      },
    });
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
    const axios = require('axios')._mockInstance;
    const indexers = new WillowIndexers('http://validator:3031', {
      indexerUrl: 'http://pinned:3032',
    });
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    subs.subscribe('any-subgrove', 'subscription { x }', () => {}, {
      source: 'indexer',
    });

    await new Promise((r) => setTimeout(r, 0));

    // Discovery endpoint must not have been called.
    expect(axios.get).not.toHaveBeenCalled();
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(FakeWebSocket.instances[0].url).toBe('ws://pinned:3032/graphql/ws');
  });

  it('calls onError when no indexer serves the subgrove', async () => {
    const axios = require('axios')._mockInstance;
    axios.get.mockResolvedValue({ data: { success: true, data: [] } });
    const indexers = new WillowIndexers('http://validator:3031');
    const subs = new WillowSubscriptions('http://validator:3031', indexers);

    let err: unknown = null;
    subs.subscribe('unserved', 'subscription { x }', () => {}, {
      source: 'indexer',
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
