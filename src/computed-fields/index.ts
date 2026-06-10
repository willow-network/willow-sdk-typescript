/**
 * Computed Fields Module
 *
 * This module provides SDK-layer computation of derived fields from proven data.
 * It enables drop-in compatibility with The Graph's query interfaces by computing
 * derived values (like price ratios) from cryptographically proven base data.
 *
 * Design Philosophy:
 * - GKR circuits prove the underlying data (reserves, volumes, balances)
 * - Division and other derived calculations are done client-side
 * - Same trust model: proven inputs + deterministic computation = trustworthy outputs
 * - Same API: queries return the same fields The Graph would return
 *
 * @example
 * ```typescript
 * // Register Uniswap V2 computed fields
 * client.registerComputedFields('pairs', UNISWAP_V2_PAIR_FIELDS);
 *
 * // Query returns computed prices alongside proven reserves
 * const pair = await client.query('pairs', { filters: { id: '0x...' } });
 * // pair.documents[0] contains:
 * // - reserve0, reserve1 (proven by GKR circuit)
 * // - token0Price, token1Price (computed from proven reserves)
 * ```
 */

import { DataRecord, QueryResponse } from "../types";

/**
 * A function that computes a derived value from a record's proven fields.
 * Returns undefined if the computation cannot be performed (e.g., division by zero).
 */
export type ComputeFunction = (
  record: DataRecord,
) => number | string | undefined;

/**
 * Definition of a single computed field.
 */
export interface ComputedFieldDefinition {
  /** The field name in the output record */
  name: string;
  /** Human-readable description of what this field represents */
  description: string;
  /** The proven fields this computation depends on */
  dependencies: string[];
  /** The computation function */
  compute: ComputeFunction;
}

/**
 * A set of computed field definitions for a dataset.
 */
export type ComputedFieldSet = ComputedFieldDefinition[];

/**
 * Registry of computed fields by dataset (subgrove).
 */
export class ComputedFieldRegistry {
  private registry: Map<string, ComputedFieldSet> = new Map();

  /**
   * Register computed fields for a specific dataset (subgrove).
   *
   * @param datasetId - The dataset (subgrove) ID
   * @param fields - The computed field definitions
   */
  register(datasetId: string, fields: ComputedFieldSet): void {
    this.registry.set(datasetId, fields);
  }

  /**
   * Get computed fields for a specific dataset.
   */
  get(datasetId: string): ComputedFieldSet | undefined {
    return this.registry.get(datasetId);
  }

  /**
   * Check if computed fields are registered for a dataset.
   */
  has(datasetId: string): boolean {
    return this.registry.has(datasetId);
  }

  /**
   * Remove computed fields for a dataset.
   */
  unregister(datasetId: string): boolean {
    return this.registry.delete(datasetId);
  }

  /**
   * Clear all registered computed fields.
   */
  clear(): void {
    this.registry.clear();
  }
}

/**
 * Apply computed fields to a single record.
 *
 * @param record - The data record with proven fields
 * @param fields - The computed field definitions to apply
 * @returns A new record with computed fields added
 */
export function applyComputedFields(
  record: DataRecord,
  fields: ComputedFieldSet,
): DataRecord {
  const result = { ...record };

  for (const field of fields) {
    // Check if all dependencies are present
    const hasDependencies = field.dependencies.every(
      (dep) => record[dep] !== undefined && record[dep] !== null,
    );

    if (hasDependencies) {
      const computed = field.compute(record);
      if (computed !== undefined) {
        result[field.name] = computed;
      }
    }
  }

  return result;
}

/**
 * Apply computed fields to a query response.
 * Modifies documents in place for efficiency.
 *
 * @param response - The query response with proven data
 * @param fields - The computed field definitions to apply
 * @returns The response with computed fields added to documents
 */
export function applyComputedFieldsToResponse(
  response: QueryResponse,
  fields: ComputedFieldSet,
): QueryResponse {
  return {
    ...response,
    documents: response.documents.map((doc) =>
      applyComputedFields(doc, fields),
    ),
  };
}

// ============================================================================
// Pre-built Field Sets for Common Protocols
// ============================================================================

/**
 * Safely parse a numeric value from various formats.
 * Handles strings (including BigInt-like strings), numbers, and BigInt.
 */
function parseNumeric(value: unknown): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value === "number") {
    return value;
  }

  if (typeof value === "bigint") {
    return Number(value);
  }

  if (typeof value === "string") {
    // Handle hex strings
    if (value.startsWith("0x")) {
      return Number(BigInt(value));
    }
    // Handle decimal strings (potentially very large)
    const parsed = parseFloat(value);
    if (!isNaN(parsed)) {
      return parsed;
    }
  }

  return undefined;
}

/**
 * Uniswap V2 Pair computed fields.
 *
 * These fields are computed from proven reserve data to match
 * The Graph's Uniswap V2 subgraph schema.
 *
 * Proven fields required:
 * - reserve0: Token 0 reserve amount
 * - reserve1: Token 1 reserve amount
 * - token0.decimals: Token 0 decimals (optional, defaults to 18)
 * - token1.decimals: Token 1 decimals (optional, defaults to 18)
 */
export const UNISWAP_V2_PAIR_FIELDS: ComputedFieldSet = [
  {
    name: "token0Price",
    description: "Price of token0 in terms of token1 (reserve1 / reserve0)",
    dependencies: ["reserve0", "reserve1"],
    compute: (record) => {
      const reserve0 = parseNumeric(record.reserve0);
      const reserve1 = parseNumeric(record.reserve1);

      if (reserve0 === undefined || reserve1 === undefined) {
        return undefined;
      }

      // Avoid division by zero
      if (reserve0 === 0) {
        return undefined;
      }

      // Apply decimal adjustment if available
      const decimals0 = parseNumeric(record.token0?.decimals) ?? 18;
      const decimals1 = parseNumeric(record.token1?.decimals) ?? 18;
      const decimalAdjustment = Math.pow(10, decimals0 - decimals1);

      return (reserve1 / reserve0) * decimalAdjustment;
    },
  },
  {
    name: "token1Price",
    description: "Price of token1 in terms of token0 (reserve0 / reserve1)",
    dependencies: ["reserve0", "reserve1"],
    compute: (record) => {
      const reserve0 = parseNumeric(record.reserve0);
      const reserve1 = parseNumeric(record.reserve1);

      if (reserve0 === undefined || reserve1 === undefined) {
        return undefined;
      }

      // Avoid division by zero
      if (reserve1 === 0) {
        return undefined;
      }

      // Apply decimal adjustment if available
      const decimals0 = parseNumeric(record.token0?.decimals) ?? 18;
      const decimals1 = parseNumeric(record.token1?.decimals) ?? 18;
      const decimalAdjustment = Math.pow(10, decimals1 - decimals0);

      return (reserve0 / reserve1) * decimalAdjustment;
    },
  },
];

/**
 * Uniswap V2 Token computed fields.
 *
 * These fields compute derived ETH prices from proven stablecoin pool reserves.
 *
 * Proven fields required:
 * - For WETH: Just use 1.0 as derivedETH (detected by isWeth or symbol)
 * - For tokens: ethPairReserve0, ethPairReserve1 (reserves from WETH pair)
 */
export const UNISWAP_V2_TOKEN_FIELDS: ComputedFieldSet = [
  {
    name: "derivedETH",
    description: "Price of token in ETH (derived from WETH pair reserves)",
    // Empty dependencies - we handle the logic internally since WETH is a special case
    dependencies: [],
    compute: (record) => {
      // If this is WETH itself, return 1
      if (record.isWeth === true || record.symbol === "WETH") {
        return 1.0;
      }

      // For other tokens, we need the WETH pair reserves
      const reserve0 = parseNumeric(record.ethPairReserve0);
      const reserve1 = parseNumeric(record.ethPairReserve1);

      // If we don't have pair reserves, we can't compute derivedETH
      if (reserve0 === undefined || reserve1 === undefined) {
        return undefined;
      }

      // Determine which reserve is WETH
      const token0IsWeth = record.ethPairToken0IsWeth === true;

      if (token0IsWeth) {
        // WETH is token0, so price = reserve0 / reserve1
        if (reserve1 === 0) return undefined;
        return reserve0 / reserve1;
      } else {
        // WETH is token1, so price = reserve1 / reserve0
        if (reserve0 === 0) return undefined;
        return reserve1 / reserve0;
      }
    },
  },
];

/**
 * Uniswap V2 daily/hourly data computed fields.
 *
 * These compute USD values from proven ETH amounts and ETH price.
 */
export const UNISWAP_V2_AGGREGATION_FIELDS: ComputedFieldSet = [
  {
    name: "dailyVolumeUSD",
    description: "Daily volume in USD (dailyVolumeETH * ethPriceUSD)",
    dependencies: ["dailyVolumeETH", "ethPriceUSD"],
    compute: (record) => {
      const volumeETH = parseNumeric(record.dailyVolumeETH);
      const ethPrice = parseNumeric(record.ethPriceUSD);

      if (volumeETH === undefined || ethPrice === undefined) {
        return undefined;
      }

      return volumeETH * ethPrice;
    },
  },
  {
    name: "totalLiquidityUSD",
    description: "Total liquidity in USD (totalLiquidityETH * ethPriceUSD)",
    dependencies: ["totalLiquidityETH", "ethPriceUSD"],
    compute: (record) => {
      const liquidityETH = parseNumeric(record.totalLiquidityETH);
      const ethPrice = parseNumeric(record.ethPriceUSD);

      if (liquidityETH === undefined || ethPrice === undefined) {
        return undefined;
      }

      return liquidityETH * ethPrice;
    },
  },
];

/**
 * Generic AMM pair fields (works for Uniswap V2, Sushiswap, etc.).
 *
 * A simplified version of pair fields without decimal adjustment.
 */
export const GENERIC_AMM_PAIR_FIELDS: ComputedFieldSet = [
  {
    name: "token0Price",
    description: "Price of token0 in terms of token1",
    dependencies: ["reserve0", "reserve1"],
    compute: (record) => {
      const reserve0 = parseNumeric(record.reserve0);
      const reserve1 = parseNumeric(record.reserve1);

      if (reserve0 === undefined || reserve1 === undefined || reserve0 === 0) {
        return undefined;
      }

      return reserve1 / reserve0;
    },
  },
  {
    name: "token1Price",
    description: "Price of token1 in terms of token0",
    dependencies: ["reserve0", "reserve1"],
    compute: (record) => {
      const reserve0 = parseNumeric(record.reserve0);
      const reserve1 = parseNumeric(record.reserve1);

      if (reserve0 === undefined || reserve1 === undefined || reserve1 === 0) {
        return undefined;
      }

      return reserve0 / reserve1;
    },
  },
];

/**
 * Lending protocol fields (for Aave, Compound, etc.).
 *
 * Computes utilization rate from proven supply and borrow amounts.
 */
export const LENDING_PROTOCOL_FIELDS: ComputedFieldSet = [
  {
    name: "utilizationRate",
    description: "Utilization rate (totalBorrows / totalSupply)",
    dependencies: ["totalBorrows", "totalSupply"],
    compute: (record) => {
      const borrows = parseNumeric(record.totalBorrows);
      const supply = parseNumeric(record.totalSupply);

      if (borrows === undefined || supply === undefined || supply === 0) {
        return undefined;
      }

      return borrows / supply;
    },
  },
  {
    name: "availableLiquidity",
    description: "Available liquidity (totalSupply - totalBorrows)",
    dependencies: ["totalBorrows", "totalSupply"],
    compute: (record) => {
      const borrows = parseNumeric(record.totalBorrows);
      const supply = parseNumeric(record.totalSupply);

      if (borrows === undefined || supply === undefined) {
        return undefined;
      }

      return supply - borrows;
    },
  },
];

/**
 * LP share computation fields.
 */
export const LP_SHARE_FIELDS: ComputedFieldSet = [
  {
    name: "shareOfPool",
    description: "User share of pool (userLPBalance / totalLPSupply)",
    dependencies: ["userLPBalance", "totalLPSupply"],
    compute: (record) => {
      const userBalance = parseNumeric(record.userLPBalance);
      const totalSupply = parseNumeric(record.totalLPSupply);

      if (
        userBalance === undefined ||
        totalSupply === undefined ||
        totalSupply === 0
      ) {
        return undefined;
      }

      return userBalance / totalSupply;
    },
  },
  {
    name: "userToken0Amount",
    description: "User share of token0 (shareOfPool * reserve0)",
    dependencies: ["userLPBalance", "totalLPSupply", "reserve0"],
    compute: (record) => {
      const userBalance = parseNumeric(record.userLPBalance);
      const totalSupply = parseNumeric(record.totalLPSupply);
      const reserve0 = parseNumeric(record.reserve0);

      if (
        userBalance === undefined ||
        totalSupply === undefined ||
        reserve0 === undefined ||
        totalSupply === 0
      ) {
        return undefined;
      }

      return (userBalance / totalSupply) * reserve0;
    },
  },
  {
    name: "userToken1Amount",
    description: "User share of token1 (shareOfPool * reserve1)",
    dependencies: ["userLPBalance", "totalLPSupply", "reserve1"],
    compute: (record) => {
      const userBalance = parseNumeric(record.userLPBalance);
      const totalSupply = parseNumeric(record.totalLPSupply);
      const reserve1 = parseNumeric(record.reserve1);

      if (
        userBalance === undefined ||
        totalSupply === undefined ||
        reserve1 === undefined ||
        totalSupply === 0
      ) {
        return undefined;
      }

      return (userBalance / totalSupply) * reserve1;
    },
  },
];

