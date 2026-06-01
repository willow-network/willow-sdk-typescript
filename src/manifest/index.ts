/**
 * Canonical `WillowManifest` builder.
 *
 * Mirrors `willow_types::consensus::manifest::WillowManifest` in the Rust
 * workspace. The consensus validator rejects any `manifest_content` that
 * doesn't decode into this exact shape, so SDK callers should always
 * build their on-chain manifest bytes via `serializeManifest`. Each data
 * source is either EVM (`address` + `abi` + `start_block` + `events`) or
 * Solana (`program_id` + `start_slot` + `instructions`); the family is
 * dispatched at parse time from the `network` field.
 */

import {
  SupportedChain,
  chainFamily,
  isSupportedChain,
} from "./chains";

export {
  SUPPORTED_CHAINS,
  type SupportedChain,
  type ChainFamily,
  chainFamily,
  evmChainId,
  isSupportedChain,
  fromEvmChainId,
} from "./chains";

/** Schema version pinned by the consensus validator. */
export const MANIFEST_SPEC_VERSION = "1.0.0";

/** Mirrors `willow_types::consensus::manifest::MAX_*` constants. */
export const MAX_DATA_SOURCES = 64;
export const MAX_EVENTS_PER_SOURCE = 32;
export const MAX_NAME_LEN = 64;
export const MAX_ABI_LEN = 64;
export const MAX_DESCRIPTION_LEN = 1024;

/** One indexed EVM contract within a manifest. */
export interface EvmDataSource {
  name: string;
  network: SupportedChain;
  /** `0x` + 40 lowercase hex chars. Mixed-case input is normalized on serialize. */
  address: string;
  abi: string;
  start_block: number;
  /** Solidity event signatures, e.g. `Transfer(address,address,uint256)`. */
  events: string[];
}

/** One indexed Solana program within a manifest. */
export interface SolanaDataSource {
  name: string;
  network: SupportedChain;
  /** Base58-encoded 32-byte program id. */
  program_id: string;
  start_slot: number;
  /** Variable-length instruction discriminators, `0x` + even hex chars (>=2). */
  instructions: string[];
}

export type DataSource = EvmDataSource | SolanaDataSource;

/** Type guard: data source is EVM (has `address` field). */
export function isEvmDataSource(ds: DataSource): ds is EvmDataSource {
  return (ds as EvmDataSource).address !== undefined;
}

/** Type guard: data source is Solana (has `program_id` field). */
export function isSolanaDataSource(ds: DataSource): ds is SolanaDataSource {
  return (ds as SolanaDataSource).program_id !== undefined;
}

export interface WillowManifest {
  spec_version: typeof MANIFEST_SPEC_VERSION;
  description?: string;
  data_sources: DataSource[];
  deferred_completeness?: boolean;
}

/**
 * Validate + serialize a manifest into the canonical JSON byte form that
 * goes on-chain via `SubgroveMode.BlockchainIndexing.manifest_content`.
 *
 * Throws a `ManifestValidationError` with a `field` path on the first
 * problem found.
 */
export function serializeManifest(m: WillowManifest): Uint8Array {
  validateManifest(m);
  const normalized: WillowManifest = {
    spec_version: m.spec_version,
    ...(m.description !== undefined ? { description: m.description } : {}),
    data_sources: m.data_sources.map((ds) =>
      isEvmDataSource(ds)
        ? { ...ds, address: ds.address.toLowerCase() }
        : { ...ds, instructions: ds.instructions.map((d) => d.toLowerCase()) },
    ),
    ...(m.deferred_completeness ? { deferred_completeness: true } : {}),
  };
  return new TextEncoder().encode(JSON.stringify(normalized));
}

/**
 * Parse + validate canonical manifest bytes. Accepts the `Uint8Array`
 * that consensus returns (e.g. via `manifest_content`) or a JSON string.
 */
export function parseManifest(input: Uint8Array | string): WillowManifest {
  const text = typeof input === "string" ? input : new TextDecoder().decode(input);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new ManifestValidationError(`manifest is not valid JSON: ${(e as Error).message}`, "");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new ManifestValidationError("manifest must be a JSON object", "");
  }
  validateManifest(parsed as WillowManifest);
  return parsed as WillowManifest;
}

export class ManifestValidationError extends Error {
  constructor(
    message: string,
    public readonly field: string,
  ) {
    super(message);
    this.name = "ManifestValidationError";
  }
}

/**
 * Validate a `WillowManifest`. Same rules as `WillowManifest::from_bytes`
 * + `WillowManifest::validate()` in the Rust workspace.
 */
export function validateManifest(m: WillowManifest): void {
  if (m.spec_version !== MANIFEST_SPEC_VERSION) {
    throw new ManifestValidationError(
      `unsupported spec_version ${JSON.stringify(m.spec_version)} (expected ${JSON.stringify(MANIFEST_SPEC_VERSION)})`,
      "spec_version",
    );
  }
  if (m.description !== undefined && m.description.length > MAX_DESCRIPTION_LEN) {
    throw new ManifestValidationError(
      `description length ${m.description.length} exceeds maximum ${MAX_DESCRIPTION_LEN}`,
      "description",
    );
  }
  if (!Array.isArray(m.data_sources) || m.data_sources.length === 0) {
    throw new ManifestValidationError(
      "manifest must declare at least one data source",
      "data_sources",
    );
  }
  if (m.data_sources.length > MAX_DATA_SOURCES) {
    throw new ManifestValidationError(
      `manifest has ${m.data_sources.length} data sources (maximum ${MAX_DATA_SOURCES})`,
      "data_sources",
    );
  }
  m.data_sources.forEach((ds, idx) => validateDataSource(ds, `data_sources[${idx}]`));
}

function validateDataSource(ds: DataSource, path: string): void {
  validateName(ds.name, path);
  if (!isSupportedChain(ds.network)) {
    throw new ManifestValidationError(
      `${path}.network ${JSON.stringify(ds.network)} is not a canonical chain`,
      `${path}.network`,
    );
  }
  const family = chainFamily(ds.network);
  if (family === "evm") {
    if (!isEvmDataSource(ds)) {
      throw new ManifestValidationError(
        `${path}.network ${JSON.stringify(ds.network)} is EVM-family but data source is missing 'address'`,
        path,
      );
    }
    validateEvmDataSource(ds, path);
  } else {
    if (!isSolanaDataSource(ds)) {
      throw new ManifestValidationError(
        `${path}.network ${JSON.stringify(ds.network)} is Solana-family but data source is missing 'program_id'`,
        path,
      );
    }
    validateSolanaDataSource(ds, path);
  }
}

function validateName(name: string, path: string): void {
  if (!name || name.length === 0) {
    throw new ManifestValidationError(`${path}.name must not be empty`, `${path}.name`);
  }
  if (name.length > MAX_NAME_LEN) {
    throw new ManifestValidationError(
      `${path}.name length ${name.length} exceeds maximum ${MAX_NAME_LEN}`,
      `${path}.name`,
    );
  }
  if (!/^[A-Za-z0-9_-]+$/.test(name)) {
    throw new ManifestValidationError(
      `${path}.name ${JSON.stringify(name)} must be alphanumeric, '-', or '_'`,
      `${path}.name`,
    );
  }
}

function validateEvmDataSource(ds: EvmDataSource, path: string): void {
  if (!/^0x[0-9a-fA-F]{40}$/.test(ds.address)) {
    throw new ManifestValidationError(
      `${path}.address must be 0x + 40 hex chars (got ${JSON.stringify(ds.address)})`,
      `${path}.address`,
    );
  }
  if (!ds.abi || ds.abi.length === 0) {
    throw new ManifestValidationError(`${path}.abi must not be empty`, `${path}.abi`);
  }
  if (ds.abi.length > MAX_ABI_LEN) {
    throw new ManifestValidationError(
      `${path}.abi length ${ds.abi.length} exceeds maximum ${MAX_ABI_LEN}`,
      `${path}.abi`,
    );
  }
  if (!Number.isInteger(ds.start_block) || ds.start_block < 0) {
    throw new ManifestValidationError(
      `${path}.start_block must be a non-negative integer`,
      `${path}.start_block`,
    );
  }
  if (!Array.isArray(ds.events) || ds.events.length === 0) {
    throw new ManifestValidationError(
      `${path}.events must declare at least one event`,
      `${path}.events`,
    );
  }
  if (ds.events.length > MAX_EVENTS_PER_SOURCE) {
    throw new ManifestValidationError(
      `${path}.events has ${ds.events.length} entries (maximum ${MAX_EVENTS_PER_SOURCE})`,
      `${path}.events`,
    );
  }
  ds.events.forEach((sig, eIdx) => validateEventSignature(sig, `${path}.events[${eIdx}]`));
}

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function validateSolanaDataSource(ds: SolanaDataSource, path: string): void {
  if (!ds.program_id || ds.program_id.length < 32 || ds.program_id.length > 44) {
    throw new ManifestValidationError(
      `${path}.program_id must be a base58-encoded 32-byte pubkey (got ${JSON.stringify(ds.program_id)})`,
      `${path}.program_id`,
    );
  }
  for (const c of ds.program_id) {
    if (!BASE58_ALPHABET.includes(c)) {
      throw new ManifestValidationError(
        `${path}.program_id contains invalid base58 character ${JSON.stringify(c)}`,
        `${path}.program_id`,
      );
    }
  }
  if (!Number.isInteger(ds.start_slot) || ds.start_slot < 0) {
    throw new ManifestValidationError(
      `${path}.start_slot must be a non-negative integer`,
      `${path}.start_slot`,
    );
  }
  if (!Array.isArray(ds.instructions) || ds.instructions.length === 0) {
    throw new ManifestValidationError(
      `${path}.instructions must declare at least one discriminator`,
      `${path}.instructions`,
    );
  }
  if (ds.instructions.length > MAX_EVENTS_PER_SOURCE) {
    throw new ManifestValidationError(
      `${path}.instructions has ${ds.instructions.length} entries (maximum ${MAX_EVENTS_PER_SOURCE})`,
      `${path}.instructions`,
    );
  }
  ds.instructions.forEach((d, iIdx) => validateDiscriminator(d, `${path}.instructions[${iIdx}]`));
}

function validateDiscriminator(d: string, path: string): void {
  if (!/^0x([0-9a-fA-F]{2})+$/.test(d)) {
    throw new ManifestValidationError(
      `${path} must be 0x + an even, non-zero number of hex chars (got ${JSON.stringify(d)})`,
      path,
    );
  }
}

/**
 * Mirrors `EventSignature::parse` in `willow-types`. Accepts
 * `Name(type1,type2,...)` with no whitespace; identifier-style name;
 * comma-separated type tokens allowing array notation (`uint256[]`).
 */
function validateEventSignature(sig: string, path: string): void {
  if (sig.length === 0) {
    throw new ManifestValidationError(`${path} must not be empty`, path);
  }
  const open = sig.indexOf("(");
  if (open === -1) {
    throw new ManifestValidationError(
      `${path} ${JSON.stringify(sig)} missing '('`,
      path,
    );
  }
  if (!sig.endsWith(")")) {
    throw new ManifestValidationError(
      `${path} ${JSON.stringify(sig)} missing trailing ')'`,
      path,
    );
  }
  const name = sig.slice(0, open);
  const params = sig.slice(open + 1, -1);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
    throw new ManifestValidationError(
      `${path} event name ${JSON.stringify(name)} is not a valid identifier`,
      path,
    );
  }
  if (params.length === 0) return;
  for (const part of params.split(",")) {
    if (!/^[A-Za-z0-9_[\]]+$/.test(part)) {
      throw new ManifestValidationError(
        `${path} has invalid parameter type ${JSON.stringify(part)}`,
        path,
      );
    }
  }
}
