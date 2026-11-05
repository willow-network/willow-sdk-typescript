/**
 * The bincode (1.x default) of a `RegisterSubgroveTx`, which a
 * RegisterSubgrove's `Config` line hashes: integers fixed-width little-endian,
 * `String` and `Vec<T>` a u64 length then the bytes or elements, fixed-size
 * arrays the elements only, `Option<T>` a 0 or 1 byte then T, and an enum a
 * u32 variant index then its fields.
 *
 * It encodes the wire object {@link registerSubgroveWire} builds, the same
 * object the SDK sends, so the bytes hashed are the values the node decodes.
 */

import { utf8ToBytes } from '../internal/bytes';
import { invalid, uint, variant } from './fields';

class Writer {
  private buf = new Uint8Array(256);
  private len = 0;

  private reserve(n: number): void {
    if (this.len + n <= this.buf.length) return;
    let size = this.buf.length * 2;
    while (size < this.len + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.len));
    this.buf = next;
  }

  /** `value` as `width` little-endian bytes. */
  private int(value: unknown, bits: 8 | 32 | 64 | 128): void {
    let v = uint('integer', value, bits);
    const width = bits / 8;
    this.reserve(width);
    for (let i = 0; i < width; i++) {
      this.buf[this.len++] = Number(v & 0xffn);
      v >>= 8n;
    }
  }

  u8(v: unknown): void {
    this.int(v, 8);
  }
  u32(v: unknown): void {
    this.int(v, 32);
  }
  u64(v: unknown): void {
    this.int(v, 64);
  }
  u128(v: unknown): void {
    this.int(v, 128);
  }
  bool(v: unknown): void {
    this.u8(v ? 1 : 0);
  }
  /** Bytes with no length: a fixed-size array. */
  raw(b: ArrayLike<number>): void {
    this.reserve(b.length);
    this.buf.set(b, this.len);
    this.len += b.length;
  }
  /** A `Vec<u8>`: its u64 length, then the bytes. */
  bytes(b: ArrayLike<number>): void {
    this.u64(b.length);
    this.raw(b);
  }
  string(s: unknown): void {
    this.bytes(utf8ToBytes(s as string));
  }
  strings(xs: unknown): void {
    const list = xs as unknown[];
    this.u64(list.length);
    for (const x of list) this.string(x);
  }
  option<T>(v: T | null | undefined, write: (v: T) => void): void {
    if (v === null || v === undefined) {
      this.u8(0);
    } else {
      this.u8(1);
      write(v);
    }
  }
  finish(): Uint8Array {
    return this.buf.slice(0, this.len);
  }
}

type Obj = Record<string, any>;

/** The u32 index of `name` among an enum's variants, in declaration order. */
function index(variants: readonly string[], name: string, label: string): number {
  const i = variants.indexOf(name);
  if (i < 0) throw invalid(`${label}: no variant ${name}`);
  return i;
}

const TEE_TYPES = ['AwsNitro', 'IntelSgx', 'AmdSev'] as const;
const COMMITMENT_FREQUENCIES = ['EveryUpdate', 'EveryNBlocks', 'EveryNSeconds', 'Never'] as const;
const RETENTION_WINDOWS = ['Blocks', 'Seconds', 'Indefinite', 'VerifyOnly'] as const;
const EXECUTION_MODES = ['ConsensusExecution', 'IndexerExecution', 'TeeExecution'] as const;
const HISTORICAL_AUTH_MODES = ['BftEquivalent', 'CanonizedAccumulator'] as const;
const SUBGROVE_MODES = ['DataStorage', 'FileStorage', 'BlockchainIndexing'] as const;

function readPricing(w: Writer, p: Obj): void {
  w.bool(p.enabled);
  w.u128(p.price_per_query);
  w.u32(p.owner_revenue_share_bps);
}

function keyGrant(w: Writer, g: Obj): void {
  w.string(g.grantee_did);
  w.u32(g.key_epoch);
  w.string(g.grantee_public_key_id);
  w.bytes(g.ephemeral_public_key);
  w.bytes(g.encrypted_key);
  w.string(g.granted_by);
  w.u64(g.granted_at);
}

function subgroveMode(w: Writer, mode: unknown): void {
  const [name, m] = variant('mode', mode) as [string, Obj];
  w.u32(index(SUBGROVE_MODES, name, 'mode'));
  if (name === 'DataStorage') {
    w.string(m.name);
    w.strings(m.writers);
    w.strings(m.free_readers);
    w.option(m.read_pricing, (p) => readPricing(w, p));
  } else if (name === 'FileStorage') {
    w.string(m.name);
    w.u64(m.max_file_size);
    w.u8(m.replication_factor);
    w.strings(m.writers);
    w.strings(m.free_readers);
    w.option(m.read_pricing, (p) => readPricing(w, p));
    w.u64(m.retention_period);
  } else {
    w.bytes(m.manifest_content);
    w.u64(m.wasm_modules.length);
    for (const module of m.wasm_modules as Obj[]) {
      w.string(module.name);
      w.raw(module.hash);
      w.bytes(module.content);
    }
    const [ex, exFields] = variant('execution_mode', m.execution_mode) as [string, Obj];
    w.u32(index(EXECUTION_MODES, ex, 'execution_mode'));
    if (ex === 'IndexerExecution') {
      w.u8(exFields.sampling_rate_percent);
    } else if (ex === 'TeeExecution') {
      w.u32(index(TEE_TYPES, exFields.tee_type, 'tee_type'));
    }
    const ic = m.indexer_config as Obj;
    w.u8(ic.min_indexers);
    w.u8(ic.max_indexers);
    w.u128(ic.reward_per_epoch);
    w.u64(ic.epoch_length);
    w.u128(ic.min_indexer_stake);
    const [rw, rwValue] = variant('retention_window', m.retention_window);
    w.u32(index(RETENTION_WINDOWS, rw, 'retention_window'));
    if (rw === 'Blocks' || rw === 'Seconds') w.u64(rwValue);
    w.option(m.completeness as Obj | null, (c) => {
      for (const x of [...c.log_config_hash, ...c.tx_config_hash]) w.u32(x);
      w.bool(c.deferred);
      w.u128(c.bond_amount);
    });
    w.u32(index(HISTORICAL_AUTH_MODES, m.historical_auth_mode, 'historical_auth_mode'));
  }
}

/**
 * The bincode of a RegisterSubgrove wire body (the object inside
 * `{"RegisterSubgrove": …}`) with an empty signature, whatever signature the
 * body carries.
 */
export function registerSubgroveBincode(t: Obj): Uint8Array {
  const w = new Writer();
  for (const k of ['subgrove_id', 'name', 'description', 'schema', 'owner_did']) {
    w.string(t[k]);
  }
  w.strings(t.admins);
  w.option(t.initial_funding, (v) => w.u128(v));
  w.option(t.checkpoint_verification.required_tee, (v: string) =>
    w.u32(index(TEE_TYPES, v, 'required_tee')),
  );
  subgroveMode(w, t.mode);
  w.option(t.privacy as Obj | null, (p) => {
    w.option(p.allowed_indexers, (a) => w.strings(a));
    const [cf, n] = variant('commitment_frequency', p.commitment_frequency);
    w.u32(index(COMMITMENT_FREQUENCIES, cf, 'commitment_frequency'));
    if (cf === 'EveryNBlocks' || cf === 'EveryNSeconds') w.u64(n);
  });
  w.option(t.initial_owner_key_grant as Obj | null, (g) => keyGrant(w, g));
  w.option(t.template_config as Obj | null, (c) => {
    w.string(c.template_id);
    w.u32(c.template_version);
    w.string(c.variant_id);
    w.bytes(c.parameters);
    w.strings(c.contracts);
    w.strings(c.event_signatures);
    w.option(c.chain, (s) => w.string(s));
  });
  w.u32(t.confirmation_depth);
  w.bytes([]); // the signature, empty
  w.string(t.public_key_id);
  w.u64(t.nonce);
  w.bool(t.cryptographic_completeness);
  return w.finish();
}
