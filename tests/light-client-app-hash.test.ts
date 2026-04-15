/**
 * Regression tests for LightClient.getVerifiedRootHashAtHeight.
 *
 * Background (the bugs these lock in):
 *
 *   1. CometBFT 0.38+ does NOT populate `app_hash` in `/block_results`.
 *      Earlier SDK versions fetched it from there and always got null →
 *      client thought the chain was unreachable.
 *
 *   2. `status.latest_app_hash` is `block <latest>.header.app_hash`, which
 *      represents state AFTER block `latest - 1` (the standard CometBFT
 *      1-block header lag). Using it as a fallback for `height = latest`
 *      returns a hash one block behind the proof and causes "root hash
 *      mismatch" even on a perfectly-working chain.
 *
 * The correct source for "app_hash of state after block H" is
 * `/block?height=H+1.header.app_hash`. These tests lock in that behavior
 * and guard against regressing to either of the above.
 */

import { LightClient } from '../src/light-client/client';
import { createTrustThreshold } from '../src/light-client/types';

type FetchMock = jest.MockedFunction<typeof fetch>;

function mockResponse(body: any, ok = true): Response {
  return {
    ok,
    status: ok ? 200 : 500,
    json: async () => body,
  } as unknown as Response;
}

function headerResponse(height: number, appHashHex: string): Response {
  return mockResponse({
    result: {
      block: {
        header: { height: String(height), app_hash: appHashHex.toUpperCase() },
      },
    },
  });
}

function statusResponse(latestHeight: number, latestAppHashHex: string): Response {
  return mockResponse({
    result: {
      sync_info: {
        latest_block_height: String(latestHeight),
        latest_app_hash: latestAppHashHex.toUpperCase(),
      },
    },
  });
}

function makeClient() {
  return new LightClient({
    chainId: 'test-chain',
    validatorEndpoints: ['http://validator:26657'],
    requestTimeoutSecs: 2,
    syncIntervalSecs: 30,
    autoSync: false,
    trustThreshold: createTrustThreshold(),
  });
}

describe('LightClient.getVerifiedRootHashAtHeight', () => {
  let fetchMock: FetchMock;

  beforeEach(() => {
    fetchMock = jest.fn() as unknown as FetchMock;
    (global as any).fetch = fetchMock;
  });

  afterEach(() => {
    jest.restoreAllMocks();
    delete (global as any).fetch;
  });

  it('returns block H+1 header.app_hash for the state after block H', async () => {
    const expected = 'af3fc00d6359537c1bbc0506ca461cc4ddcd21d366ecae151469d28691eb6dcb';
    fetchMock.mockResolvedValueOnce(headerResponse(3536, expected));

    const client = makeClient();
    const result = await client.getVerifiedRootHashAtHeight(3535);

    expect(result).toBe(expected);
    // Must request H+1, not H.
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('/block?height=3536');
  });

it('polls when H+1 does not exist yet, then succeeds once it is produced', async () => {
    const expected = '1111111111111111111111111111111111111111111111111111111111111111';

    // First attempt: /block?height=H+1 fails (not found).
    fetchMock.mockResolvedValueOnce(mockResponse({}, false));
    // Status says chain is exactly at H — block H+1 doesn't exist yet.
    fetchMock.mockResolvedValueOnce(
      statusResponse(5, '2222222222222222222222222222222222222222222222222222222222222222'),
    );
    // Second attempt: /block?height=H+1 now returns the real header.
    fetchMock.mockResolvedValueOnce(headerResponse(6, expected));

    const client = makeClient();
    const result = await client.getVerifiedRootHashAtHeight(5);
    expect(result).toBe(expected);
  });

  it('does NOT fall back to status.latest_app_hash (which lags by one block)', async () => {
    // Simulate: /block?height=H+1 keeps failing AND chain stays at H.
    // Old code used to return `status.latest_app_hash` as a fallback here.
    // That's WRONG: status.latest_app_hash = block H.header.app_hash = state
    // after H-1, not state after H. Returning it causes a silent mismatch
    // that the caller misattributes to a bad proof.
    const misleadingHash = 'deadbeef' + '00'.repeat(28);

    // Return failure + status repeatedly; after timeout expires we should
    // throw, not return the misleading hash.
    for (let i = 0; i < 200; i++) {
      fetchMock.mockResolvedValueOnce(mockResponse({}, false));
      fetchMock.mockResolvedValueOnce(statusResponse(5, misleadingHash));
    }

    const client = makeClient();
    await expect(client.getVerifiedRootHashAtHeight(5)).rejects.toThrow(
      /Could not fetch app_hash for height 5/,
    );

    // Confirm we never returned the misleading fallback.
    // (If we had, the .rejects.toThrow above would have failed.)
  });

  it('does NOT query /block_results (deprecated in CometBFT 0.38+; app_hash is null there)', async () => {
    const expected = 'abcd' + '00'.repeat(30);
    fetchMock.mockResolvedValueOnce(headerResponse(101, expected));

    const client = makeClient();
    await client.getVerifiedRootHashAtHeight(100);

    for (const call of fetchMock.mock.calls) {
      const url = call[0] as string;
      expect(url).not.toContain('/block_results');
    }
  });
});
