import {
  CompletenessClient,
  CompletenessUnavailableError,
  logsFromMatchedResponse,
  verifyServedEvents,
} from "../src/completeness";
import type { MatchedLogsResponse } from "../src/completeness";
import { bytesToBase64 } from "../src/internal/bytes";

// Authoritative cross-language vector (same as completeness.test.ts vector B):
// block 7, two matched logs -> this exact commitment.
const VECTOR_B_HASH =
  "e1544ae919458663e8fce14bdcd06df6a777410c068302c0584dff1587524dfd";

// The exact `matched-logs` response body from the task contract. The
// JSON->Log parse is gated against the authoritative vector through this body.
const MATCHED_LOGS_BODY: MatchedLogsResponse = {
  subgrove_id: "sg",
  block_number: 7,
  count: 2,
  matched_logs: [
    {
      block_number: 7,
      block_hash:
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      transaction_hash:
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      transaction_index: 0,
      log_index: "0x0",
      address: "0x4242424242424242424242424242424242424242",
      topics: [
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "0x1111111111111111111111111111111111111111111111111111111111111111",
      ],
      data: "0x01020304",
      removed: false,
    },
    {
      block_number: 7,
      block_hash:
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      transaction_hash:
        "0x0000000000000000000000000000000000000000000000000000000000000000",
      transaction_index: 0,
      log_index: "0x1",
      address: "0x4343434343434343434343434343434343434343",
      topics: [
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      ],
      data: "0x",
      removed: false,
    },
  ],
};

describe("logsFromMatchedResponse", () => {
  it("parses the authoritative matched-logs body into a verifying Log[]", () => {
    const logs = logsFromMatchedResponse(MATCHED_LOGS_BODY);

    expect(logs).toHaveLength(2);
    expect(logs[0].address).toBeInstanceOf(Uint8Array);
    expect((logs[0].address as Uint8Array).length).toBe(20);
    expect(logs[0].topics).toHaveLength(2);
    expect((logs[0].data as Uint8Array).length).toBe(4);
    // The empty-data log decodes "0x" to a zero-length array.
    expect((logs[1].data as Uint8Array).length).toBe(0);

    // The gate: the parsed set must re-hash to the authoritative anchor.
    expect(verifyServedEvents(VECTOR_B_HASH, 7, logs)).toBe(true);
  });

  it("ignores block/tx/index/removed fields (only address,topics,data bind)", () => {
    const noisy: MatchedLogsResponse = {
      ...MATCHED_LOGS_BODY,
      matched_logs: MATCHED_LOGS_BODY.matched_logs.map((l) => ({
        ...l,
        block_number: 999,
        log_index: "0xdeadbeef",
        removed: true,
      })),
    };
    expect(
      verifyServedEvents(VECTOR_B_HASH, 7, logsFromMatchedResponse(noisy)),
    ).toBe(true);
  });

  it("throws on a malformed body (no matched_logs array)", () => {
    expect(() =>
      logsFromMatchedResponse({
        subgrove_id: "sg",
      } as unknown as MatchedLogsResponse),
    ).toThrow(/matched_logs/);
  });
});

describe("CompletenessClient.verifyBlockCompleteness (mocked transport)", () => {
  const mockFetch = jest.fn();
  global.fetch = mockFetch as unknown as typeof fetch;

  const RPC_URL = "http://localhost:26657";
  const INDEXER_URL = "http://localhost:3051";

  /** ABCI store-query value: { subgrove_id, block_number, events_commitment }. */
  function anchorAbciResponse(commitmentHex: string, code = 0, log = "") {
    const valueJson = JSON.stringify({
      subgrove_id: "sg",
      block_number: 7,
      events_commitment: commitmentHex,
    });
    const value = bytesToBase64(new TextEncoder().encode(valueJson));
    return {
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: "2.0",
        id: 1,
        result: { response: { code, log, value: code === 0 ? value : null } },
      }),
      text: async () => "",
    } as unknown as Response;
  }

  /** Indexer GET response goes through HttpClient (reads response.text()). */
  function matchedLogsResponse(body: unknown, status = 200) {
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(body),
    } as unknown as Response;
  }

  /** Route the single global fetch mock by URL: RPC POST vs indexer GET. */
  function route(handlers: {
    anchor: () => Response;
    logs: () => Response;
  }): void {
    mockFetch.mockImplementation((url: string) => {
      if (url === RPC_URL) return Promise.resolve(handlers.anchor());
      if (url.startsWith(INDEXER_URL)) return Promise.resolve(handlers.logs());
      throw new Error(`unexpected fetch URL: ${url}`);
    });
  }

  beforeEach(() => mockFetch.mockReset());

  function client(): CompletenessClient {
    return new CompletenessClient({
      consensusRpcUrl: RPC_URL,
      indexerBaseUrl: INDEXER_URL,
    });
  }

  it("verifies true when anchor + served logs match the commitment", async () => {
    route({
      anchor: () => anchorAbciResponse(VECTOR_B_HASH),
      logs: () => matchedLogsResponse(MATCHED_LOGS_BODY),
    });

    await expect(client().verifyBlockCompleteness("sg", 7)).resolves.toBe(true);

    // Confirm the wrapper hit the exact ABCI path + matched-logs URL.
    const rpcBody = JSON.parse(
      mockFetch.mock.calls.find((c) => c[0] === RPC_URL)![1].body as string,
    );
    expect(rpcBody.method).toBe("abci_query");
    expect(rpcBody.params.path).toBe("/store/events_commitment/sg/7");
    const getUrl = mockFetch.mock.calls.find((c) =>
      (c[0] as string).startsWith(INDEXER_URL),
    )![0];
    expect(getUrl).toBe(`${INDEXER_URL}/completeness/sg/7/matched-logs`);
  });

  it("returns false when served logs are tampered (anchor unchanged)", async () => {
    const tampered: MatchedLogsResponse = {
      ...MATCHED_LOGS_BODY,
      matched_logs: [MATCHED_LOGS_BODY.matched_logs[0]], // dropped a log
    };
    route({
      anchor: () => anchorAbciResponse(VECTOR_B_HASH),
      logs: () => matchedLogsResponse(tampered),
    });

    await expect(client().verifyBlockCompleteness("sg", 7)).resolves.toBe(
      false,
    );
  });

  it("throws CompletenessUnavailableError when the chain has no anchor", async () => {
    route({
      anchor: () =>
        anchorAbciResponse("", 1, "No events commitment for block 7"),
      logs: () => matchedLogsResponse(MATCHED_LOGS_BODY),
    });

    await expect(
      client().verifyBlockCompleteness("sg", 7),
    ).rejects.toBeInstanceOf(CompletenessUnavailableError);
  });

  it("throws CompletenessUnavailableError when the indexer has no preimage", async () => {
    route({
      anchor: () => anchorAbciResponse(VECTOR_B_HASH),
      logs: () =>
        matchedLogsResponse({ error: "no retained matched logs" }, 404),
    });

    await expect(
      client().verifyBlockCompleteness("sg", 7),
    ).rejects.toBeInstanceOf(CompletenessUnavailableError);
  });
});
