/**
 * The JSON the SDK sends for the transactions whose signature covers every
 * field: each built field by field, in the order the chain's struct declares
 * them, every value checked and every optional field written out. The signed
 * message (or the bincode a RegisterSubgrove's `Config` hashes) is built from
 * this same object, so the node decodes exactly the values that were signed.
 */

import type { RegisterSubgroveTx } from './types';
import { WillowError } from '../types';
import { base64ToBytes, bytesToHex } from '../internal/bytes';
import {
  bool,
  bytes,
  invalid,
  text,
  texts,
  uint,
  variant,
  wireInt,
  wireUint,
} from './fields';
import { checkStorageSchema } from './schema';

export type WireInt = number | bigint;

const TEE_TYPES = ['AwsNitro', 'IntelSgx', 'AmdSev'];

function teeType(label: string, value: unknown): string {
  if (typeof value !== 'string' || !TEE_TYPES.includes(value)) {
    throw invalid(`${label} must be one of ${TEE_TYPES.join(', ')}`);
  }
  return value;
}

function record(label: string, value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw invalid(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

/** `null` for an absent optional value (`undefined` or `null`), else `f(value)`. */
function optional<T>(value: unknown, f: (v: unknown) => T): T | null {
  return value === undefined || value === null ? null : f(value);
}

/** An `EncryptedKeyGrant`, as the chain's JSON carries it. */
export function keyGrantWire(label: string, value: unknown): Record<string, unknown> {
  const g = record(label, value);
  return {
    grantee_did: text(`${label}.grantee_did`, g.grantee_did),
    key_epoch: wireUint(`${label}.key_epoch`, g.key_epoch, 32),
    grantee_public_key_id: text(`${label}.grantee_public_key_id`, g.grantee_public_key_id),
    ephemeral_public_key: bytes(`${label}.ephemeral_public_key`, g.ephemeral_public_key),
    encrypted_key: bytes(`${label}.encrypted_key`, g.encrypted_key),
    granted_by: text(`${label}.granted_by`, g.granted_by),
    granted_at: wireUint(`${label}.granted_at`, g.granted_at, 64),
  };
}

function readPricingWire(label: string, value: unknown): Record<string, unknown> {
  const p = record(label, value);
  return {
    enabled: bool(`${label}.enabled`, p.enabled),
    price_per_query: wireUint(`${label}.price_per_query`, p.price_per_query, 128),
    owner_revenue_share_bps: wireUint(
      `${label}.owner_revenue_share_bps`,
      p.owner_revenue_share_bps,
      32,
    ),
  };
}

/**
 * A `RetentionWindow`: the SDK's `{ type, value }` form or the chain's own
 * (`{ Blocks: n }`, `{ Seconds: n }`, `"Indefinite"`, `"VerifyOnly"`).
 */
function retentionWindowWire(label: string, value: unknown): unknown {
  let kind: string;
  let n: unknown;
  if (value !== null && typeof value === 'object' && 'type' in (value as object)) {
    const r = value as { type: unknown; value?: unknown };
    kind = String(r.type);
    n = r.value;
  } else {
    [kind, n] = variant(label, value);
  }
  switch (kind) {
    case 'Blocks':
    case 'Seconds':
      return { [kind]: wireUint(`${label}.${kind}`, n, 64) };
    case 'Indefinite':
    case 'VerifyOnly':
      return kind;
    default:
      throw invalid(`${label} must be Blocks, Seconds, Indefinite, or VerifyOnly`);
  }
}

function executionModeWire(label: string, value: unknown): unknown {
  const [kind, fields] = variant(label, value);
  switch (kind) {
    case 'ConsensusExecution':
      if (fields !== undefined && fields !== null) break;
      return 'ConsensusExecution';
    case 'IndexerExecution': {
      const f = record(`${label}.IndexerExecution`, fields);
      return {
        IndexerExecution: {
          sampling_rate_percent: wireUint(
            `${label}.IndexerExecution.sampling_rate_percent`,
            f.sampling_rate_percent,
            8,
          ),
        },
      };
    }
    case 'TeeExecution': {
      const f = record(`${label}.TeeExecution`, fields);
      return { TeeExecution: { tee_type: teeType(`${label}.TeeExecution.tee_type`, f.tee_type) } };
    }
  }
  throw invalid(`${label} must be ConsensusExecution, IndexerExecution, or TeeExecution`);
}

/** The chain's default `epoch_length`, sent when the caller leaves it out. */
const DEFAULT_EPOCH_LENGTH = 100;

function indexerConfigWire(label: string, value: unknown): Record<string, unknown> {
  const c = record(label, value);
  return {
    min_indexers: wireUint(`${label}.min_indexers`, c.min_indexers, 8),
    max_indexers: wireUint(`${label}.max_indexers`, c.max_indexers, 8),
    reward_per_epoch: wireUint(`${label}.reward_per_epoch`, c.reward_per_epoch, 128),
    epoch_length: wireUint(`${label}.epoch_length`, c.epoch_length ?? DEFAULT_EPOCH_LENGTH, 64),
    min_indexer_stake: wireUint(`${label}.min_indexer_stake`, c.min_indexer_stake, 128),
  };
}

function configHash(label: string, value: unknown): number[] {
  if (!Array.isArray(value) || value.length !== 4) {
    throw invalid(`${label} must be four u32 values`);
  }
  return value.map((v, i) => Number(uint(`${label}[${i}]`, v, 32)));
}

function completenessWire(label: string, value: unknown): Record<string, unknown> {
  const c = record(label, value);
  return {
    log_config_hash: configHash(`${label}.log_config_hash`, c.log_config_hash),
    tx_config_hash: configHash(`${label}.tx_config_hash`, c.tx_config_hash),
    deferred: bool(`${label}.deferred`, c.deferred ?? false),
    bond_amount: wireUint(`${label}.bond_amount`, c.bond_amount ?? 0, 128),
  };
}

const HISTORICAL_AUTH_MODES = ['BftEquivalent', 'CanonizedAccumulator'];

function historicalAuthModeWire(label: string, value: unknown): string {
  if (typeof value !== 'string' || !HISTORICAL_AUTH_MODES.includes(value)) {
    throw invalid(`${label} must be BftEquivalent or CanonizedAccumulator`);
  }
  return value;
}

function wasmModuleWire(label: string, value: unknown): Record<string, unknown> {
  const m = record(label, value);
  return {
    name: text(`${label}.name`, m.name),
    hash: bytes(`${label}.hash`, m.hash, { length: 32, hex: true }),
    content: bytes(`${label}.content`, m.content),
  };
}

/**
 * The access lists of a data or file mode. `readers` is taken as
 * `free_readers` (the chain reads that alias in a DataStorage mode); the SDK
 * always sends `free_readers`.
 */
function accessLists(label: string, m: Record<string, unknown>) {
  return {
    writers: texts(`${label}.writers`, m.writers ?? []),
    free_readers: texts(`${label}.free_readers`, m.free_readers ?? m.readers ?? []),
  };
}

function modeWire(tx: RegisterSubgroveTx, name: string): unknown {
  const mode = tx.mode ?? { DataStorage: { name, writers: [tx.ownerDid], free_readers: [] } };
  const [kind, fields] = variant('mode', mode);
  const label = `mode.${kind}`;
  if (kind !== 'BlockchainIndexing' && tx.retention_window !== undefined) {
    throw invalid('A retention window applies only to a BlockchainIndexing subgrove');
  }
  switch (kind) {
    case 'DataStorage': {
      const m = record(label, fields);
      const lists = accessLists(label, m);
      return {
        DataStorage: {
          name: text(`${label}.name`, m.name),
          writers: lists.writers,
          free_readers: lists.free_readers,
          read_pricing: optional(m.read_pricing, (p) => readPricingWire(`${label}.read_pricing`, p)),
        },
      };
    }
    case 'FileStorage': {
      const m = record(label, fields);
      const lists = accessLists(label, m);
      return {
        FileStorage: {
          name: text(`${label}.name`, m.name),
          max_file_size: wireUint(`${label}.max_file_size`, m.max_file_size, 64),
          replication_factor: wireUint(`${label}.replication_factor`, m.replication_factor, 8),
          writers: lists.writers,
          free_readers: lists.free_readers,
          read_pricing: optional(m.read_pricing, (p) => readPricingWire(`${label}.read_pricing`, p)),
          retention_period: wireUint(`${label}.retention_period`, m.retention_period ?? 0, 64),
        },
      };
    }
    case 'BlockchainIndexing': {
      const m = record(label, fields);
      if (m.retention_window !== undefined && tx.retention_window !== undefined) {
        throw invalid('Set the retention window on the mode or on the transaction, not both');
      }
      const modules = m.wasm_modules ?? [];
      if (!Array.isArray(modules)) throw invalid(`${label}.wasm_modules must be an array`);
      return {
        BlockchainIndexing: {
          manifest_content: bytes(`${label}.manifest_content`, m.manifest_content),
          wasm_modules: modules.map((w, i) => wasmModuleWire(`${label}.wasm_modules[${i}]`, w)),
          execution_mode: executionModeWire(`${label}.execution_mode`, m.execution_mode),
          indexer_config: indexerConfigWire(`${label}.indexer_config`, m.indexer_config),
          retention_window: retentionWindowWire(
            `${label}.retention_window`,
            m.retention_window ?? tx.retention_window ?? 'Indefinite',
          ),
          completeness: optional(m.completeness, (c) =>
            completenessWire(`${label}.completeness`, c),
          ),
          historical_auth_mode: historicalAuthModeWire(
            `${label}.historical_auth_mode`,
            m.historical_auth_mode ?? 'BftEquivalent',
          ),
        },
      };
    }
    default:
      throw invalid('mode must be DataStorage, FileStorage, or BlockchainIndexing');
  }
}

const COMMITMENT_FREQUENCIES = ['EveryUpdate', 'EveryNBlocks', 'EveryNSeconds', 'Never'];

function privacyWire(value: unknown): Record<string, unknown> {
  const p = record('privacy', value);
  const [kind, n] = variant('privacy.commitment_frequency', p.commitment_frequency);
  let frequency: unknown;
  if (kind === 'EveryUpdate' || kind === 'Never') {
    if (n !== undefined && n !== null) throw invalid(`privacy.commitment_frequency.${kind} takes no value`);
    frequency = kind;
  } else if (kind === 'EveryNBlocks' || kind === 'EveryNSeconds') {
    frequency = { [kind]: wireUint(`privacy.commitment_frequency.${kind}`, n, 64) };
  } else {
    throw invalid(`privacy.commitment_frequency must be one of ${COMMITMENT_FREQUENCIES.join(', ')}`);
  }
  return {
    allowed_indexers: optional(p.allowed_indexers, (a) => texts('privacy.allowed_indexers', a)),
    commitment_frequency: frequency,
  };
}

function templateWire(value: unknown): Record<string, unknown> {
  const t = record('templateConfig', value);
  return {
    template_id: text('templateConfig.template_id', t.template_id),
    template_version: wireUint('templateConfig.template_version', t.template_version, 32),
    variant_id: text('templateConfig.variant_id', t.variant_id),
    parameters: bytes('templateConfig.parameters', t.parameters),
    contracts: texts('templateConfig.contracts', t.contracts),
    event_signatures: texts('templateConfig.event_signatures', t.event_signatures),
    chain: optional(t.chain, (c) => text('templateConfig.chain', c)),
  };
}

/**
 * `initialFunding` as the wire carries it: a decimal string of the u128,
 * which the chain's `initial_funding` decodes exactly; `null` when there is
 * none.
 */
function initialFundingWire(value: unknown): string | null {
  if (value === undefined || value === null || value === '') return null;
  return uint('initialFunding', value, 128).toString();
}

/**
 * The `RegisterSubgrove` body the SDK sends: every field of the chain's
 * `RegisterSubgroveTx`, in its order, with the values the API would fill in
 * for an omitted field written out.
 */
/** A data or file subgrove id: 1–64 ASCII letters, digits, `-`, or `_`, starting with a letter or digit. */
const STORAGE_SUBGROVE_ID = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

/**
 * The chain's rules for a DataStorage or FileStorage registration, checked
 * before signing: its subgrove id is 1–64 ASCII letters, digits, `-`, or `_`,
 * starting with a letter or digit, and its schema is JSON the chain parses as
 * a schema that declares no indexes (writes to an indexed subgrove are
 * refused); see {@link checkStorageSchema}. The chain refuses a registration
 * that breaks either.
 */
export function checkStorageRegistration(subgroveId: string, schema: string): void {
  if (!STORAGE_SUBGROVE_ID.test(subgroveId)) {
    throw new WillowError(
      `Invalid subgrove id ${JSON.stringify(subgroveId)}: a data or file subgrove's id is 1–64 ` +
        "ASCII letters, digits, '-', or '_', starting with a letter or digit",
      'INVALID_SUBGROVE_ID',
    );
  }
  checkStorageSchema(schema);
}

export function registerSubgroveWire(
  tx: RegisterSubgroveTx,
  signature: number[],
): Record<string, unknown> {
  const name = tx.name ?? tx.subgroveId;
  const checkpoint = tx.checkpointVerification ?? { required_tee: null };
  const mode = modeWire(tx, name) as Record<string, unknown>;
  if ('DataStorage' in mode || 'FileStorage' in mode) {
    checkStorageRegistration(text('subgroveId', tx.subgroveId), text('schema', tx.schema));
  }
  return {
    subgrove_id: text('subgroveId', tx.subgroveId),
    name: text('name', name),
    description: text('description', tx.description ?? ''),
    schema: text('schema', tx.schema),
    owner_did: text('ownerDid', tx.ownerDid),
    admins: texts('admins', tx.admins ?? []),
    initial_funding: initialFundingWire(tx.initialFunding),
    checkpoint_verification: {
      required_tee: optional(record('checkpointVerification', checkpoint).required_tee, (t) =>
        teeType('checkpointVerification.required_tee', t),
      ),
    },
    mode,
    privacy: optional(tx.privacy, privacyWire),
    initial_owner_key_grant: optional(tx.initialOwnerKeyGrant, (g) =>
      keyGrantWire('initialOwnerKeyGrant', g),
    ),
    template_config: optional(tx.templateConfig, templateWire),
    confirmation_depth: wireUint('confirmationDepth', tx.confirmationDepth ?? 0, 32),
    signature,
    public_key_id: text('publicKeyId', tx.publicKeyId ?? ''),
    nonce: wireInt(uint('nonce', tx.nonce ?? 0, 64)),
    cryptographic_completeness: bool(
      'cryptographicCompleteness',
      tx.cryptographicCompleteness ?? false,
    ),
  };
}

/** A public key's hex for the chain's document: `publicKeyHex`, or `publicKeyBase64` as hex. */
function sdkKeyHex(label: string, k: Record<string, unknown>): string | null {
  if (k.publicKeyHex !== undefined && k.publicKeyHex !== null) {
    return text(`${label}.publicKeyHex`, k.publicKeyHex);
  }
  if (k.publicKeyBase64 !== undefined && k.publicKeyBase64 !== null) {
    return bytesToHex(base64ToBytes(text(`${label}.publicKeyBase64`, k.publicKeyBase64)));
  }
  return null;
}

/**
 * The `type` of the key `publicKeyId` in a DID document, in the SDK's shape
 * (`publicKeys`) or the chain's (`public_keys`), when it lists one.
 */
export function didDocumentKeyType(doc: unknown, publicKeyId: string): string | undefined {
  if (doc === null || typeof doc !== 'object') return undefined;
  const d = doc as Record<string, unknown>;
  const keys = Array.isArray(d.publicKeys) ? d.publicKeys : Array.isArray(d.public_keys) ? d.public_keys : [];
  for (const key of keys) {
    const k = key as Record<string, unknown> | null;
    if (k && k.id === publicKeyId && typeof k.type === 'string') return k.type;
  }
  return undefined;
}

/**
 * A DID document as the chain's `DidDocument` carries it, its fields in the
 * order the struct declares them and every optional field written out, so
 * its JSON text is the text the node signs (`serde_json::to_vec` of the
 * document it decodes).
 *
 * Accepts the SDK's {@link DidDocument} (`publicKeys`, from
 * `createDidFromPublicKey` or `createDidFromWallet`): each key is controlled
 * by the document's DID and listed for authentication, and the document has
 * no services and no proof. Accepts the chain's own shape (`public_keys`,
 * `authentication`, `service`, `proof`) as well.
 */
export function chainDidDocument(value: unknown): Record<string, unknown> {
  const d = record('didDocument', value);
  const id = text('didDocument.id', d.id);
  const created = wireUint('didDocument.created', d.created, 64);
  const updated = wireUint('didDocument.updated', d.updated, 64);

  if (Array.isArray(d.public_keys)) {
    const service = d.service ?? [];
    if (!Array.isArray(service)) throw invalid('didDocument.service must be an array');
    return {
      id,
      public_keys: d.public_keys.map((key, i) => {
        const label = `didDocument.public_keys[${i}]`;
        const k = record(label, key);
        return {
          id: text(`${label}.id`, k.id),
          type: text(`${label}.type`, k.type),
          controller: text(`${label}.controller`, k.controller),
          public_key_base58: optional(k.public_key_base58, (v) =>
            text(`${label}.public_key_base58`, v),
          ),
          public_key_hex: optional(k.public_key_hex, (v) => text(`${label}.public_key_hex`, v)),
        };
      }),
      authentication: texts('didDocument.authentication', d.authentication),
      service: service.map((entry, i) => {
        const label = `didDocument.service[${i}]`;
        const s = record(label, entry);
        return {
          id: text(`${label}.id`, s.id),
          type: text(`${label}.type`, s.type),
          service_endpoint: text(`${label}.service_endpoint`, s.service_endpoint),
        };
      }),
      created,
      updated,
      proof: optional(d.proof, (p) => {
        const r = record('didDocument.proof', p);
        return {
          type: text('didDocument.proof.type', r.type),
          created: wireUint('didDocument.proof.created', r.created, 64),
          verification_method: text('didDocument.proof.verification_method', r.verification_method),
          proof_purpose: text('didDocument.proof.proof_purpose', r.proof_purpose),
          jws: text('didDocument.proof.jws', r.jws),
        };
      }),
    };
  }

  if (Array.isArray(d.publicKeys)) {
    const keys = d.publicKeys.map((key, i) => {
      const label = `didDocument.publicKeys[${i}]`;
      const k = record(label, key);
      return {
        id: text(`${label}.id`, k.id),
        type: text(`${label}.type`, k.type),
        controller: id,
        public_key_base58: null,
        public_key_hex: sdkKeyHex(label, k),
      };
    });
    return {
      id,
      public_keys: keys,
      authentication: keys.map((k) => k.id),
      service: [],
      created,
      updated,
      proof: null,
    };
  }

  throw invalid('didDocument must have public keys (publicKeys or public_keys)');
}
