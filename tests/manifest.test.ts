import {
  SUPPORTED_CHAINS,
  MANIFEST_SPEC_VERSION,
  serializeManifest,
  parseManifest,
  validateManifest,
  ManifestValidationError,
  chainFamily,
  evmChainId,
  fromEvmChainId,
  isSupportedChain,
  type WillowManifest,
} from "../src/manifest";

function goodManifest(): WillowManifest {
  return {
    spec_version: MANIFEST_SPEC_VERSION,
    data_sources: [
      {
        name: "UniswapV3Pool",
        network: "mainnet",
        address: "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
        abi: "UniswapV3Pool",
        start_block: 12369621,
        events: ["Swap(address,address,int256,int256,uint160,uint128,int24)"],
      },
    ],
  };
}

describe("WillowManifest serialization", () => {
  it("round-trips a canonical manifest", () => {
    const bytes = serializeManifest(goodManifest());
    const parsed = parseManifest(bytes);
    expect(parsed.spec_version).toBe(MANIFEST_SPEC_VERSION);
    expect(parsed.data_sources).toHaveLength(1);
    expect(parsed.data_sources[0].network).toBe("mainnet");
  });

  it("normalizes mixed-case addresses to lowercase on serialize", () => {
    const m = goodManifest();
    m.data_sources[0].address = "0x88E6A0C2DDD26FEEB64F039A2C41296FCB3F5640";
    const bytes = serializeManifest(m);
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640");
  });

  it("accepts each EVM canonical chain", () => {
    for (const chain of SUPPORTED_CHAINS) {
      if (chainFamily(chain) !== "evm") continue;
      const m = goodManifest();
      m.data_sources[0].network = chain;
      expect(() => validateManifest(m)).not.toThrow();
    }
  });

  it("rejects unsupported chain", () => {
    const m = goodManifest();
    (m.data_sources[0] as any).network = "frobnitz";
    expect(() => validateManifest(m)).toThrow(ManifestValidationError);
  });

  it("rejects legacy 'ethereum' alias", () => {
    const m = goodManifest();
    (m.data_sources[0] as any).network = "ethereum";
    expect(() => validateManifest(m)).toThrow(/not a canonical chain/);
  });

  it("rejects Solana data sources via the EVM builder", () => {
    // The v1 EVM-only manifest builder rejects Solana chains; a separate
    // Solana data source shape will be added in a follow-up.
    const m = goodManifest();
    m.data_sources[0].network = "solana-mainnet";
    expect(() => validateManifest(m)).toThrow(/non-EVM/);
  });

  it("rejects wrong spec_version", () => {
    const m = goodManifest();
    (m as any).spec_version = "2.0.0";
    expect(() => validateManifest(m)).toThrow(/spec_version/);
  });

  it("rejects empty data_sources", () => {
    const m = goodManifest();
    m.data_sources = [];
    expect(() => validateManifest(m)).toThrow(/at least one/);
  });

  it("rejects unknown root types", () => {
    expect(() => parseManifest("null")).toThrow(ManifestValidationError);
    expect(() => parseManifest("[]")).toThrow(ManifestValidationError);
    expect(() => parseManifest("42")).toThrow(ManifestValidationError);
    expect(() => parseManifest('"string"')).toThrow(ManifestValidationError);
  });

  it("rejects malformed address", () => {
    const m = goodManifest();
    m.data_sources[0].address = "0x123";
    expect(() => validateManifest(m)).toThrow(/40 hex/);
  });

  it("rejects malformed event signature", () => {
    const m = goodManifest();
    m.data_sources[0].events = ["NotASignature"];
    expect(() => validateManifest(m)).toThrow(/missing '\('/);

    m.data_sources[0].events = ["Transfer(address, address, uint256)"]; // whitespace
    expect(() => validateManifest(m)).toThrow(/invalid parameter type/);
  });

  it("rejects data source name with bad charset", () => {
    const m = goodManifest();
    m.data_sources[0].name = "Has Space";
    expect(() => validateManifest(m)).toThrow(/alphanumeric/);
  });

  it("attributes errors to the offending field", () => {
    const m = goodManifest();
    m.data_sources.push({ ...m.data_sources[0], name: "" });
    try {
      validateManifest(m);
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ManifestValidationError);
      expect((e as ManifestValidationError).field).toBe("data_sources[1].name");
    }
  });
});

describe("SupportedChain helpers", () => {
  it("isSupportedChain recognises every canonical id", () => {
    for (const chain of SUPPORTED_CHAINS) {
      expect(isSupportedChain(chain)).toBe(true);
    }
  });

  it("isSupportedChain rejects aliases", () => {
    expect(isSupportedChain("ethereum")).toBe(false);
    expect(isSupportedChain("MAINNET")).toBe(false);
    expect(isSupportedChain("")).toBe(false);
  });

  it("evmChainId / fromEvmChainId round-trip for every EVM chain", () => {
    for (const chain of SUPPORTED_CHAINS) {
      if (chainFamily(chain) !== "evm") {
        expect(evmChainId(chain)).toBeNull();
        continue;
      }
      const id = evmChainId(chain);
      expect(id).not.toBeNull();
      expect(fromEvmChainId(id!)).toBe(chain);
    }
  });

  it("chainFamily classifies known chains", () => {
    expect(chainFamily("mainnet")).toBe("evm");
    expect(chainFamily("arbitrum-one")).toBe("evm");
    expect(chainFamily("solana-mainnet")).toBe("solana");
  });
});
