/**
 * Client-side verification + ergonomic helpers for verifiable Ethereum
 * state reads. Counterpart to the indexer's `/verifiable-rpc/eth/state`
 * and `/verifiable-rpc/eth/call` routes.
 *
 * Three trust modes follow `StateVerifyMode`:
 *   - `Strict` (default): every account proof + every storage proof
 *     must verify against the carried `state_root`.
 *   - `AnchorOnly`: skip the MPT walks; trust the indexer's word.
 *   - `Disabled`: no verification, raw passthrough.
 */

import { keccak_256 } from "@noble/hashes/sha3";
import { encodeRlp, getBytes, hexlify, toBeArray, toBigInt } from "ethers";

import { HttpClient } from "../internal/http";
import { base64ToBytes, bytesToHex } from "../internal/bytes";
import { verifyMptProof } from "./mpt";
import {
  type AccountState,
  type EthCallRequestBody,
  type EthVerifiableRpcResponse,
  type MptProof,
  type StateProof,
  type StorageSlotProof,
  type VerifiedCall,
  type VerifiedStateRead,
  type VerifiedStorage,
  StateVerifyMode,
} from "./types";

export * from "./types";
export { verifyMptProof } from "./mpt";

/** SDK operations for verifiable Ethereum state reads. */
export class EthOperations {
  private http: HttpClient;
  private mode: StateVerifyMode = StateVerifyMode.Strict;

  constructor(private indexerBaseUrl: string, http?: HttpClient, apiKey?: string) {
    this.http =
      http ??
      new HttpClient({
        baseURL: indexerBaseUrl,
        headers: apiKey ? { 'X-API-Key': apiKey } : {},
      });
  }

  /** Return a copy of this client that verifies with `mode`. */
  withMode(mode: StateVerifyMode): EthOperations {
    const next = new EthOperations(this.indexerBaseUrl, this.http);
    next.mode = mode;
    return next;
  }

  /**
   * Fetch `address`'s account state (+ optional storage slots) at
   * `blockNumber` and verify the response.
   */
  async getState(
    address: string,
    slots: string[],
    blockNumber: number,
  ): Promise<VerifiedStateRead> {
    const body = {
      address,
      slots,
      block: blockNumber,
    };
    const envelope = await this.http.post<EthVerifiableRpcResponse>(
      "/verifiable-rpc/eth/state",
      body,
    );
    const proof = envelope.state_proofs?.[0];
    if (!proof) {
      throw new Error("response carried no state proof");
    }

    if (this.mode === StateVerifyMode.Strict) {
      verifyStateProof(proof);
    }
    return toVerifiedStateRead(proof, this.mode);
  }

  /**
   * Execute `tx` via the indexer's verified-REVM at `blockNumber` and
   * verify state proofs for every touched account.
   */
  async getCall(
    tx: EthCallRequestBody["tx"],
    blockNumber: number,
  ): Promise<VerifiedCall> {
    const body: EthCallRequestBody = { tx, block: blockNumber };
    const envelope = await this.http.post<EthVerifiableRpcResponse>(
      "/verifiable-rpc/eth/call",
      body,
    );
    const proofs = envelope.state_proofs ?? [];
    if (this.mode === StateVerifyMode.Strict) {
      for (const p of proofs) {
        verifyStateProof(p);
      }
    }
    const result = `0x${bytesToHex(base64ToBytes(envelope.answer))}`;
    const blockNumberResp = envelope.block_range[0];
    const blockHash = proofs[0]
      ? bytesToHex32(proofs[0].block_hash)
      : `0x${"00".repeat(32)}`;
    return {
      block_number: blockNumberResp,
      block_hash: blockHash,
      state_root: bytesToHex32(envelope.state_root),
      result,
      access_state_reads: proofs.map((p) => toVerifiedStateRead(p, this.mode)),
      mode: this.mode,
    };
  }

  /**
   * ERC-20 `balanceOf(holder)`. `balanceSlot` is the storage-mapping slot
   * index for the token (0 for OpenZeppelin-style, 9 for USDC). Always
   * check the token source if unsure.
   */
  async erc20Balance(
    token: string,
    holder: string,
    balanceSlot: number,
    blockNumber: number,
  ): Promise<bigint> {
    const slot = mappingSlotForAddress(holder, balanceSlot);
    const state = await this.getState(token, [slot], blockNumber);
    if (state.storage.length === 0) {
      throw new Error("erc20Balance: no storage proof returned");
    }
    return state.storage[0].value;
  }

  /** ERC-20 `totalSupply()` for tokens whose `_totalSupply` lives at `slot`. */
  async erc20TotalSupply(
    token: string,
    slot: number,
    blockNumber: number,
  ): Promise<bigint> {
    const slotHex = numberSlotToHex(slot);
    const state = await this.getState(token, [slotHex], blockNumber);
    if (state.storage.length === 0) {
      throw new Error("erc20TotalSupply: no storage proof returned");
    }
    return state.storage[0].value;
  }

  /** ERC-20 nested-mapping `allowance(holder, spender)`. */
  async erc20Allowance(
    token: string,
    holder: string,
    spender: string,
    allowanceSlot: number,
    blockNumber: number,
  ): Promise<bigint> {
    const inner = mappingSlotForAddressBytes(getBytes(asAddress(holder)), allowanceSlot);
    const buf = new Uint8Array(64);
    // left-pad spender to 32 bytes
    buf.set(getBytes(asAddress(spender)), 12);
    buf.set(inner, 32);
    const slot = hexlify(keccak_256(buf));
    const state = await this.getState(token, [slot], blockNumber);
    if (state.storage.length === 0) {
      throw new Error("erc20Allowance: no storage proof returned");
    }
    return state.storage[0].value;
  }

  /** ERC-721 `ownerOf(tokenId)` from the `_owners` mapping at `slot`. */
  async erc721Owner(
    contract: string,
    tokenId: bigint,
    slot: number,
    blockNumber: number,
  ): Promise<string> {
    const tokenIdBytes = padBigIntTo32(tokenId);
    const buf = new Uint8Array(64);
    buf.set(tokenIdBytes, 0);
    buf.set(slotIndexTo32(slot), 32);
    const storageSlot = hexlify(keccak_256(buf));
    const state = await this.getState(contract, [storageSlot], blockNumber);
    if (state.storage.length === 0) {
      throw new Error("erc721Owner: no storage proof returned");
    }
    const value = state.storage[0].value;
    const bytes = padBigIntTo32(value);
    return `0x${bytesToHex(bytes.slice(12))}`;
  }

  /**
   * Uniswap V2 `getReserves()` — packed in slot 8 as
   * `[blockTimestampLast (4 bytes) | reserve1 (14) | reserve0 (14)]`
   * in big-endian on-the-wire order.
   */
  async uniV2Reserves(
    pair: string,
    blockNumber: number,
  ): Promise<{ reserve0: bigint; reserve1: bigint; blockTimestampLast: number }> {
    const slot = numberSlotToHex(8);
    const state = await this.getState(pair, [slot], blockNumber);
    if (state.storage.length === 0) {
      throw new Error("uniV2Reserves: no storage proof returned");
    }
    const bytes = padBigIntTo32(state.storage[0].value);
    const blockTimestampLast =
      (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    const reserve1 = bytesToBigInt(bytes.slice(4, 18));
    const reserve0 = bytesToBigInt(bytes.slice(18, 32));
    return { reserve0, reserve1, blockTimestampLast: blockTimestampLast >>> 0 };
  }
}

/* ---------- verification ---------- */

/**
 * Walk every MPT proof inside `proof`. Throws on first mismatch.
 */
export function verifyStateProof(proof: StateProof): void {
  const stateRoot = bytesFromArray(proof.state_root);
  const addressHash = keccak_256(bytesFromArray(proof.address));
  const accountLeaf = rlpEncodeAccount(proof.account_state);

  const r = verifyMptProof(
    stateRoot,
    addressHash,
    accountLeaf,
    proof.account_proof.proof_nodes.map((n) => bytesFromArray(n)),
  );
  if (!r.ok) {
    throw new Error(`state proof: account proof failed: ${r.error}`);
  }

  const storageHash = bytesFromArray(proof.account_state.storage_hash);
  for (const sp of proof.storage_proofs) {
    verifyStorageSlot(sp, storageHash);
  }
}

function verifyStorageSlot(sp: StorageSlotProof, storageHash: Uint8Array): void {
  const slotBytes = bytesFromArray(sp.slot);
  const slotHash = keccak_256(slotBytes);
  const valueBig = bytesToBigInt(bytesFromArray(sp.value));
  const valueRlp = getBytes(encodeRlp(valueBig === 0n ? "0x" : "0x" + valueBig.toString(16)));
  const r = verifyMptProof(
    storageHash,
    slotHash,
    valueRlp,
    sp.proof.proof_nodes.map((n) => bytesFromArray(n)),
  );
  if (!r.ok) {
    throw new Error(
      `state proof: storage slot 0x${bytesToHex(slotBytes)} failed: ${r.error}`,
    );
  }
}

/** RLP-encode an account leaf: [nonce, balance, storageRoot, codeHash]. */
function rlpEncodeAccount(state: AccountState): Uint8Array {
  const nonceHex = state.nonce === 0 ? "0x" : "0x" + state.nonce.toString(16);
  const balanceBig = bytesToBigInt(bytesFromArray(state.balance));
  const balanceHex = balanceBig === 0n ? "0x" : "0x" + balanceBig.toString(16);
  const storageRoot = "0x" + bytesToHex(bytesFromArray(state.storage_hash));
  const codeHash = "0x" + bytesToHex(bytesFromArray(state.code_hash));
  return getBytes(encodeRlp([nonceHex, balanceHex, storageRoot, codeHash]));
}

/* ---------- conversions ---------- */

function toVerifiedStateRead(proof: StateProof, mode: StateVerifyMode): VerifiedStateRead {
  return {
    address: bytesToHex20(proof.address),
    block_number: proof.block_number,
    block_hash: bytesToHex32(proof.block_hash),
    state_root: bytesToHex32(proof.state_root),
    nonce: proof.account_state.nonce,
    balance: bytesToBigInt(bytesFromArray(proof.account_state.balance)),
    storage_hash: bytesToHex32(proof.account_state.storage_hash),
    code_hash: bytesToHex32(proof.account_state.code_hash),
    storage: proof.storage_proofs.map<VerifiedStorage>((sp) => ({
      slot: bytesToHex32(sp.slot),
      value: bytesToBigInt(bytesFromArray(sp.value)),
    })),
    mode,
  };
}

function bytesFromArray(arr: number[]): Uint8Array {
  return new Uint8Array(arr);
}

function bytesToHex20(arr: number[]): string {
  return "0x" + bytesToHex(bytesFromArray(arr)).padStart(40, "0");
}

function bytesToHex32(arr: number[]): string {
  return "0x" + bytesToHex(bytesFromArray(arr)).padStart(64, "0");
}

function bytesToBigInt(arr: Uint8Array): bigint {
  if (arr.length === 0) return 0n;
  return toBigInt(arr);
}

function asAddress(s: string): string {
  return s.toLowerCase().startsWith("0x") ? s : `0x${s}`;
}

function padBigIntTo32(value: bigint): Uint8Array {
  const minimal = value === 0n ? new Uint8Array(1) : toBeArray(value);
  if (minimal.length === 32) return minimal;
  const padded = new Uint8Array(32);
  padded.set(minimal, 32 - minimal.length);
  return padded;
}

/** Encode a slot index as a 32-byte big-endian word. */
function slotIndexTo32(slot: number): Uint8Array {
  if (!Number.isSafeInteger(slot) || slot < 0) {
    throw new Error(`storage slot index must be a non-negative integer, got ${slot}`);
  }
  return padBigIntTo32(BigInt(slot));
}

function numberSlotToHex(slot: number): string {
  return hexlify(slotIndexTo32(slot));
}

/** keccak256(left_pad(address, 32) || left_pad(slot_index, 32)). */
function mappingSlotForAddress(address: string, slotIndex: number): string {
  return hexlify(mappingSlotForAddressBytes(getBytes(asAddress(address)), slotIndex));
}

function mappingSlotForAddressBytes(
  addrBytes: Uint8Array,
  slotIndex: number,
): Uint8Array {
  const buf = new Uint8Array(64);
  buf.set(addrBytes, 12);
  buf.set(slotIndexTo32(slotIndex), 32);
  return keccak_256(buf);
}
