/**
 * Wire types for verifiable Ethereum state reads.
 *
 * Fixed-byte arrays are serialized as JSON arrays of numbers (matching
 * the server's default serde behavior). Hex-string accessors are
 * exposed via `EthOperations` for ergonomics.
 */

import { type AddressLike, type BytesLike } from "ethers";

export type Bytes20 = number[];
export type Bytes32 = number[];

export interface MptProof {
  key: number[];
  value: number[];
  proof_nodes: number[][];
}

export interface AccountState {
  nonce: number;
  balance: Bytes32;
  storage_hash: Bytes32;
  code_hash: Bytes32;
}

export interface StorageSlotProof {
  slot: Bytes32;
  value: Bytes32;
  proof: MptProof;
}

export interface StateProof {
  address: Bytes20;
  block_number: number;
  block_hash: Bytes32;
  state_root: Bytes32;
  account_proof: MptProof;
  account_state: AccountState;
  storage_proofs: StorageSlotProof[];
}

/**
 * Indexer's `POST /verifiable-rpc/eth/state` and `/eth/call` envelope.
 *
 * Mirrors `VerifiableRpcResponse`; for the eth/* routes only the
 * `state_proofs`, `state_root`, `block_range`, and `answer` (for
 * eth_call's ABI-encoded return data) fields are populated.
 */
export interface EthVerifiableRpcResponse {
  subgrove_id: string;
  key: string; // base64
  answer: string; // base64
  answer_exists: boolean;
  checkpoint_id: Bytes32;
  state_root: Bytes32;
  block_range: [number, number];
  grovedb_proof: string; // base64
  gkr_proofs: unknown[];
  completeness_proof: string | null;
  state_proofs?: StateProof[];
  served_at_unix_secs: number;
}

export interface EthStateRequest {
  address: string; // 0x-prefixed
  slots: string[]; // 0x-prefixed
  block: number;
}

export interface EthCallRequestBody {
  tx: {
    from?: AddressLike;
    to: AddressLike;
    gas?: BytesLike | string | number;
    gasPrice?: BytesLike | string;
    value?: BytesLike | string;
    data?: BytesLike;
    [k: string]: unknown;
  };
  block: number;
}

/** Verification trust modes — mirrors the Rust SDK's `StateVerifyMode`. */
export enum StateVerifyMode {
  /** Walk every MPT proof against the carried `state_root`. Default. */
  Strict = "strict",
  /** Skip the proof walks; trust the indexer's word. */
  AnchorOnly = "anchor_only",
  /** No verification. Intended for debugging. */
  Disabled = "disabled",
}

export interface VerifiedStorage {
  slot: string; // 0x-prefixed hex
  value: bigint;
}

export interface VerifiedStateRead {
  address: string;
  block_number: number;
  block_hash: string;
  state_root: string;
  nonce: number;
  balance: bigint;
  storage_hash: string;
  code_hash: string;
  storage: VerifiedStorage[];
  mode: StateVerifyMode;
}

export interface VerifiedCall {
  block_number: number;
  block_hash: string;
  state_root: string;
  result: string; // 0x-prefixed hex
  access_state_reads: VerifiedStateRead[];
  mode: StateVerifyMode;
}
