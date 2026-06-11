// Tests that the "secure by default" data API fails closed: a server that
// omits the proof must not get its unverified data silently accepted.
//
// Mocking strategy mirrors routing.test.ts — the global fetch behind the
// SDK's HttpClient is stubbed and routed by request URL.

import { WillowData } from '../src/data';
import { WillowAuth } from '../src/auth';
import { WillowIndexers } from '../src/indexers';
import { WillowError } from '../src/types';

const mockFetch = jest.fn();
global.fetch = mockFetch as unknown as typeof fetch;

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(body),
  } as Response;
}

const auth = new WillowAuth('http://validator:3031');

function makeData(): WillowData {
  const indexers = new WillowIndexers('http://validator:3031');
  return new WillowData('http://validator:3031', auth, indexers);
}

beforeEach(() => {
  mockFetch.mockReset();
});

describe('getData fails closed without a proof', () => {
  it('throws MISSING_PROOF when the proof endpoint returns no proof', async () => {
    mockFetch.mockImplementation((url: string) => {
      if (url.startsWith('http://validator:3031/data/')) {
        return Promise.resolve(jsonResponse({ success: true, data: { id: '1', balance: 1000 } }));
      }
      // Proof endpoint succeeds but carries no proof — the fail-open vector.
      return Promise.resolve(jsonResponse({ success: true, data: {} }));
    });

    await expect(makeData().getData('balances', 'alice')).rejects.toMatchObject({
      code: 'MISSING_PROOF',
    });
  });

  it('getDataUnverified returns the data without touching the proof endpoint', async () => {
    mockFetch.mockImplementation((url: string) => {
      if (url.startsWith('http://validator:3031/data/')) {
        return Promise.resolve(jsonResponse({ success: true, data: { id: '1', balance: 1000 } }));
      }
      throw new Error(`unexpected request to ${url}`);
    });

    const data = await makeData().getDataUnverified('balances', 'alice');
    expect(data).toEqual({ id: '1', balance: 1000 });
  });
});

describe('query fails closed without a proof', () => {
  it('throws MISSING_PROOF when the query response omits the proof', async () => {
    mockFetch.mockImplementation(() =>
      Promise.resolve(
        jsonResponse({ success: true, data: { documents: [{ id: '1' }], total: 1 } }),
      ),
    );

    await expect(
      makeData().query('balances', {}),
    ).rejects.toMatchObject({ code: 'MISSING_PROOF' });
  });

  it('queryUnverified returns documents without requiring a proof', async () => {
    mockFetch.mockImplementation(() =>
      Promise.resolve(
        jsonResponse({ success: true, data: { documents: [{ id: '1' }], total: 1 } }),
      ),
    );

    const result = await makeData().queryUnverified('balances', {});
    expect(result.documents).toEqual([{ id: '1' }]);
  });

  it('reports a WillowError so the caller gets a signal, not a silent return', async () => {
    mockFetch.mockImplementation(() =>
      Promise.resolve(
        jsonResponse({ success: true, data: { documents: [{ id: '1' }], total: 1 } }),
      ),
    );

    await expect(makeData().query('balances', {})).rejects.toBeInstanceOf(WillowError);
  });
});
