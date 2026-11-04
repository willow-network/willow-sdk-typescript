/**
 * Choosing transaction nonces for an identity that sends more than one write.
 *
 * The chain accepts a nonce in `base + 1 … base + 24` that it hasn't used, and
 * `base` only advances over used nonces with no gap. A client that read the
 * base and signed `base + 1` for every write gave each write in flight the same
 * nonce, so all but one were refused; and a nonce taken and never used blocks
 * the window until something uses it. A `NonceAllocator` keeps, per DID, the
 * nonces it has handed out that haven't landed (each with when it was handed
 * out) and the newest nonce state the chain has reported, and hands out the
 * lowest nonce in the window that is neither used nor handed out within the
 * last 120 s (the node's admission hold).
 */

import { ConsensusError, BroadcastResult } from './types';
import { base64ToBytes } from '../internal/bytes';

/** How many nonces above the base the chain accepts. */
export const NONCE_WINDOW = 24;

/** How long a nonce handed out and not seen to land stays taken, in ms. */
export const NONCE_HOLD_MS = 120_000;

/** An account's nonce state as the chain reports it. */
export interface AccountNonceState {
  /** Every nonce at or below the base is used. */
  base: number;
  /**
   * Bit `i` set: `base + 1 + i` is used (24 bits). 0 when only the base is
   * known (the API's `/account/{did}/nonce`).
   */
  used: number;
}

export interface NonceAllocatorOptions {
  /** The clock, in ms. Defaults to `Date.now`. */
  now?: () => number;
}

interface DidNonces {
  /** Each nonce handed out and not seen to land, with when it was taken. */
  taken: Map<number, number>;
  /** The newest state the chain has reported, once it has. */
  latest: AccountNonceState | null;
}

/** The 24 used bits of `state` read against `base` (at or above its own). */
function usedAbove(state: AccountNonceState, base: number): number {
  const shift = base - state.base;
  // A shift of 24 or more leaves none of the window (and `>>>` takes its
  // count mod 32, so it can't be left to the shift).
  if (shift >= NONCE_WINDOW) return 0;
  return (state.used >>> shift) & ((1 << NONCE_WINDOW) - 1);
}

/**
 * Two reports of one account's nonce state as one: the higher base, and every
 * nonce either marks used above it. A used nonce stays used, so neither
 * report's bits are dropped when the other's base is higher (a base-only
 * read that advances the base keeps the bits seen above it).
 */
function mergeStates(a: AccountNonceState, b: AccountNonceState): AccountNonceState {
  const base = Math.max(a.base, b.base);
  return { base, used: usedAbove(a, base) | usedAbove(b, base) };
}

/** Whether `chain` shows `nonce` used: at or below the base, or its bit set. */
export function isUsed(chain: AccountNonceState, nonce: number): boolean {
  if (nonce <= chain.base) return true;
  const offset = nonce - chain.base - 1;
  return offset < NONCE_WINDOW && (chain.used & (1 << offset)) !== 0;
}

/**
 * Parse the value of the ABCI query `/store/account_nonce_state/{did}`: the
 * base as a big-endian u64, then 3 bytes in which bit `i % 8` of byte `i / 8`
 * marks `base + 1 + i` used. 8 bytes is the base alone; none is a fresh
 * account.
 */
export function parseAccountNonceState(bytes: Uint8Array): AccountNonceState {
  if (bytes.length === 0) return { base: 0, used: 0 };
  if (bytes.length !== 8 && bytes.length !== 11) {
    throw new ConsensusError(`Nonce state of ${bytes.length} bytes`, 'NONCE_STATE_INVALID');
  }
  let base = 0n;
  for (let i = 0; i < 8; i++) base = (base << 8n) | BigInt(bytes[i]);
  if (base > BigInt(Number.MAX_SAFE_INTEGER - NONCE_WINDOW)) {
    throw new ConsensusError(`Nonce base ${base} is beyond what this SDK sends`, 'NONCE_STATE_INVALID');
  }
  const used = bytes.length === 11 ? bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) : 0;
  return { base: Number(base), used };
}

/** {@link parseAccountNonceState} of an ABCI query's base64 `value`. */
export function parseAccountNonceStateBase64(value: string): AccountNonceState {
  return parseAccountNonceState(base64ToBytes(value));
}

/**
 * Whether a refusal says the nonce is not free: held by a pending
 * transaction, already used (or at or below the base), or spent by a refusal
 * in its block (`(nonce N spent)`).
 */
export function refusalKeepsNonce(log: string): boolean {
  return (
    log.includes('held by a pending transaction') ||
    log.includes('already used') ||
    /<= base nonce/.test(log) ||
    /\(nonce \d+ spent\)/.test(log)
  );
}

const SHARED = new Map<string, NonceAllocator>();

/**
 * Hands out one account's transaction nonces so that no two writes in flight
 * share one. Every write path of the SDK that picks a nonce takes it here:
 * `ConsensusClient` (and so `WillowClient` and `WillowData`) and
 * `PrivacyOperations` use {@link NonceAllocator.shared} for their API URL
 * unless given one.
 *
 * Taking a nonce is synchronous once the chain's state is in hand, so two
 * concurrent writes can't take the same one.
 */
export class NonceAllocator {
  private readonly accounts = new Map<string, DidNonces>();
  private readonly now: () => number;

  constructor(options: NonceAllocatorOptions = {}) {
    this.now = options.now ?? Date.now;
  }

  /** The process's allocator for one API URL: every client of it shares it. */
  static shared(apiUrl: string): NonceAllocator {
    const key = apiUrl.replace(/\/+$/, '');
    let allocator = SHARED.get(key);
    if (!allocator) {
      allocator = new NonceAllocator();
      SHARED.set(key, allocator);
    }
    return allocator;
  }

  /** Whether the chain's state for `did` has been seen. */
  hasState(did: string): boolean {
    return this.accounts.get(did)?.latest != null;
  }

  /**
   * Take a nonce for `did`: the lowest in `base + 1 … base + 24` that isn't
   * used, seen to land, or handed out within the last 120 s. `chain` is the
   * state just read; without it, the newest state seen is used (it throws if
   * there is none). Throws `NONCE_WINDOW_FULL` when every nonce in the window
   * is taken: wait for earlier writes to land.
   */
  take(did: string, chain?: AccountNonceState): number {
    const account = this.refresh(did, chain);
    const latest = account.latest!;
    const { base } = latest;
    for (let n = base + 1; n <= base + NONCE_WINDOW; n++) {
      if (!isUsed(latest, n) && !account.taken.has(n)) {
        account.taken.set(n, this.now());
        return n;
      }
    }
    throw new ConsensusError(
      `Nonce window full for ${did}: every nonce the chain accepts (${base + 1}–${base + NONCE_WINDOW}) ` +
        'is used or held by a write in flight; send more once earlier writes land',
      'NONCE_WINDOW_FULL',
    );
  }

  /** The write signed with `nonce` was refused without spending it: free it now. */
  release(did: string, nonce: number): void {
    this.accounts.get(did)?.taken.delete(nonce);
  }

  /**
   * `nonce` is taken (its write was accepted, or a refusal says the nonce is
   * held, used, or spent): its 120 s hold runs from now.
   */
  hold(did: string, nonce: number): void {
    const account = this.account(did);
    account.taken.set(nonce, this.now());
  }

  /**
   * Record a submission's outcome: accepted, or pending (its outcome
   * unknown), holds the nonce; refused gives it back unless the refusal says
   * it is held, used, or spent.
   */
  settle(did: string, nonce: number, result: BroadcastResult): void {
    if (result.success || result.pending) {
      this.hold(did, nonce);
      return;
    }
    const log = `${result.rawLog ?? ''}\n${result.errorMessage ?? ''}`;
    if (refusalKeepsNonce(log)) {
      this.hold(did, nonce);
    } else {
      this.release(did, nonce);
    }
  }

  private account(did: string): DidNonces {
    let account = this.accounts.get(did);
    if (!account) {
      account = { taken: new Map(), latest: null };
      this.accounts.set(did, account);
    }
    return account;
  }

  /**
   * Merge `chain` into the newest state seen (an older answer can't lower the
   * base or clear a used bit, and a newer one keeps the used bits seen above
   * its base), then drop the nonces seen used and the holds that ran out.
   */
  private refresh(did: string, chain?: AccountNonceState): DidNonces {
    const account = this.account(did);
    const seen = account.latest;
    if (chain) {
      account.latest = seen ? mergeStates(seen, chain) : { base: chain.base, used: chain.used };
    }
    const latest = account.latest;
    if (!latest) {
      throw new ConsensusError(`No nonce state known for ${did}`, 'NONCE_STATE_UNKNOWN');
    }
    const now = this.now();
    for (const [n, at] of account.taken) {
      if (isUsed(latest, n) || now - at >= NONCE_HOLD_MS) account.taken.delete(n);
    }
    return account;
  }
}
