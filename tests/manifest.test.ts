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
  isEvmDataSource,
  isSolanaDataSource,
  type EvmDataSource,
  type SolanaDataSource,
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

function solanaManifest(): WillowManifest {
  return {
    spec_version: MANIFEST_SPEC_VERSION,
    data_sources: [
      {
        name: "SplToken",
        network: "solana-mainnet",
        program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        start_slot: 100_000_000,
        instructions: ["0x03"],
      },
    ],
  };
}

function asEvm(ds: WillowManifest["data_sources"][number]): EvmDataSource {
  return ds as EvmDataSource;
}

function asSolana(ds: WillowManifest["data_sources"][number]): SolanaDataSource {
  return ds as SolanaDataSource;
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
    asEvm(m.data_sources[0]).address = "0x88E6A0C2DDD26FEEB64F039A2C41296FCB3F5640";
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

  it("rejects EVM fields on a Solana-network data source", () => {
    const m = goodManifest();
    m.data_sources[0].network = "solana-mainnet";
    expect(() => validateManifest(m)).toThrow(/Solana-family.*missing 'program_id'/);
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
    asEvm(m.data_sources[0]).address = "0x123";
    expect(() => validateManifest(m)).toThrow(/40 hex/);
  });

  it("rejects malformed event signature", () => {
    const m = goodManifest();
    asEvm(m.data_sources[0]).events = ["NotASignature"];
    expect(() => validateManifest(m)).toThrow(/missing '\('/);

    asEvm(m.data_sources[0]).events = ["Transfer(address, address, uint256)"]; // whitespace
    expect(() => validateManifest(m)).toThrow(/invalid parameter type/);
  });

  it("rejects data source name with bad charset", () => {
    const m = goodManifest();
    m.data_sources[0].name = "Has Space";
    expect(() => validateManifest(m)).toThrow(/alphanumeric/);
  });

  it("attributes errors to the offending field", () => {
    const m = goodManifest();
    m.data_sources.push({ ...asEvm(m.data_sources[0]), name: "" });
    try {
      validateManifest(m);
      fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ManifestValidationError);
      expect((e as ManifestValidationError).field).toBe("data_sources[1].name");
    }
  });
});

describe("Solana data sources", () => {
  it("round-trips a native SPL Token manifest", () => {
    const bytes = serializeManifest(solanaManifest());
    const parsed = parseManifest(bytes);
    const ds = parsed.data_sources[0];
    expect(isSolanaDataSource(ds)).toBe(true);
    expect(asSolana(ds).program_id).toBe("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
    expect(asSolana(ds).instructions).toEqual(["0x03"]);
  });

  it("accepts an 8-byte Anchor discriminator", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0xc1209b3341d69c81"];
    expect(() => validateManifest(m)).not.toThrow();
  });

  it("accepts a 4-byte System program tag", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0x02000000"];
    expect(() => validateManifest(m)).not.toThrow();
  });

  it("accepts multiple discriminators of different lengths", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0x03", "0x07", "0xc1209b3341d69c81"];
    expect(() => validateManifest(m)).not.toThrow();
  });

  it("normalizes discriminator hex to lowercase on serialize", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0xABCD"];
    const round = parseManifest(serializeManifest(m));
    expect(asSolana(round.data_sources[0]).instructions).toEqual(["0xabcd"]);
  });

  it("rejects discriminator with odd hex chars", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0x123"];
    expect(() => validateManifest(m)).toThrow(/even.*non-zero number of hex/);
  });

  it("rejects empty discriminator", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["0x"];
    expect(() => validateManifest(m)).toThrow(/even.*non-zero number of hex/);
  });

  it("rejects discriminator without 0x prefix", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = ["03"];
    expect(() => validateManifest(m)).toThrow(/even.*non-zero number of hex/);
  });

  it("rejects empty instructions array", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).instructions = [];
    expect(() => validateManifest(m)).toThrow(/at least one discriminator/);
  });

  it("rejects negative start_slot", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).start_slot = -1;
    expect(() => validateManifest(m)).toThrow(/non-negative/);
  });

  it("rejects program_id with non-base58 characters", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).program_id = "Tokenkeg0feZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    expect(() => validateManifest(m)).toThrow(/invalid base58 character/);
  });

  it("rejects program_id with wrong length", () => {
    const m = solanaManifest();
    asSolana(m.data_sources[0]).program_id = "Token";
    expect(() => validateManifest(m)).toThrow(/base58-encoded 32-byte/);
  });

  it("rejects EVM fields on a Solana-network data source", () => {
    const m: WillowManifest = {
      spec_version: MANIFEST_SPEC_VERSION,
      data_sources: [
        {
          name: "Mixed",
          network: "solana-mainnet",
          address: "0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
          abi: "Whatever",
          start_block: 0,
          events: ["Transfer(address,address,uint256)"],
        } as EvmDataSource,
      ],
    };
    expect(() => validateManifest(m)).toThrow(/Solana-family.*missing 'program_id'/);
  });

  it("accepts a mixed EVM + Solana manifest", () => {
    const m: WillowManifest = {
      spec_version: MANIFEST_SPEC_VERSION,
      data_sources: [
        ...goodManifest().data_sources,
        ...solanaManifest().data_sources,
      ],
    };
    expect(() => validateManifest(m)).not.toThrow();
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
