/**
 * Canonical chain identifiers accepted by Willow's consensus validator.
 *
 * Mirrors `willow_types::consensus::SupportedChain` in the Rust workspace —
 * any new chain must land in both places at the same time. Identifiers are
 * lowercase kebab-case (subgraph convention); no aliases are accepted by
 * the validator, so callers must use the exact string here.
 */
export const SUPPORTED_CHAINS = [
  // EVM family
  "mainnet",
  "sepolia",
  "holesky",
  "bsc",
  "optimism",
  "arbitrum-one",
  "base",
  "polygon",
  // Solana family
  "solana-mainnet",
] as const;

export type SupportedChain = (typeof SUPPORTED_CHAINS)[number];

export type ChainFamily = "evm" | "solana";

/** Family the chain belongs to. Drives manifest data-source dispatch. */
export function chainFamily(chain: SupportedChain): ChainFamily {
  return chain === "solana-mainnet" ? "solana" : "evm";
}

/** EIP-155 chain id for EVM-family chains, `null` for Solana. */
export function evmChainId(chain: SupportedChain): number | null {
  switch (chain) {
    case "mainnet":
      return 1;
    case "sepolia":
      return 11155111;
    case "holesky":
      return 17000;
    case "bsc":
      return 56;
    case "optimism":
      return 10;
    case "arbitrum-one":
      return 42161;
    case "base":
      return 8453;
    case "polygon":
      return 137;
    case "solana-mainnet":
      return null;
  }
}

/** Type guard — matches the Rust `SupportedChain::from_canonical_id` set. */
export function isSupportedChain(s: string): s is SupportedChain {
  return (SUPPORTED_CHAINS as readonly string[]).includes(s);
}

/** Map an EIP-155 chain id back to the canonical chain. */
export function fromEvmChainId(id: number): SupportedChain | null {
  for (const chain of SUPPORTED_CHAINS) {
    if (evmChainId(chain) === id) return chain;
  }
  return null;
}
