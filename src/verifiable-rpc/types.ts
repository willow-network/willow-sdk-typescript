/**
 * Wire + result types for the verifiable-RPC flow.
 *
 * An indexer serves a query result with proofs attached and the client
 * verifies locally. Fixed-byte fields are serialized by the server as JSON
 * arrays of numbers (default serde), mirroring `src/eth-state/types.ts`.
 *
 * This is the general envelope behind `GET /verifiable-rpc/:subgrove/:key`;
 * `EthVerifiableRpcResponse` is the same shape specialized for the eth/* routes.
 */

import type { StateProof, Bytes32 } from "../eth-state/types";

/** Public inputs that bind a GKR transformation proof to specific data. */
export interface GkrPublicInputs {
  /** Merkle root of the output entities after transformation. */
  output_root: Bytes32;
  /** Inclusive (start_block, end_block) covered by this proof. */
  block_range: [number, number];
  /** Hash of the subgrove transformation config the proof was produced under. */
  config_hash: Bytes32;
  /** Starting state this proof transitioned from; zeroed for stateless/genesis. */
  starting_state_root: Bytes32;
}

/** One GKR transformation proof (one per chunk for chunked submissions). */
export interface GkrProofData {
  proof_version: number;
  /** The serialized `GKR_PROOF_FULL` byte stream. */
  proof: number[];
  public_inputs: GkrPublicInputs;
  /**
   * Content hash of the circuit/VK this proof verifies under
   * (`SHA-256(circuit_bytes)`). Both `/circuit/:hash` and `/vk/:hash` are
   * keyed by it, and the client re-pins `SHA-256(circuit) === this`.
   */
  verification_key_hash: Bytes32;
  proof_size_bytes: number;
  generation_time_ms: number;
  gpu_accelerated: boolean;
}

/** Response served by `GET /verifiable-rpc/:subgrove_id/:query_key`. */
export interface VerifiableRpcResponse {
  subgrove_id: string;
  /** base64 — the queried key, echoed back. */
  key: string;
  /** base64 — the value at `key` (empty when `answer_exists === false`). */
  answer: string;
  answer_exists: boolean;
  checkpoint_id: Bytes32;
  /** State root the answer is proven against. */
  state_root: Bytes32;
  /** Inclusive (start, end) block range covered by the checkpoint. */
  block_range: [number, number];
  /** base64 — GroveDB Merkle proof binding `answer` to `state_root`. */
  grovedb_proof: string;
  /** Transformation proofs, one per chunk; empty if none generated yet. */
  gkr_proofs: GkrProofData[];
  /** base64 — combined completeness proof; null when absent. */
  completeness_proof: string | null;
  /** Ethereum MPT inclusion proofs (eth/* routes only). */
  state_proofs?: StateProof[];
  /** When the indexer produced this response (unix seconds). */
  served_at_unix_secs: number;
}

/**
 * The minimal surface of the `@willow-network/gkr-verify-wasm` companion
 * package the client needs. Each method THROWS on a failed/invalid proof and
 * returns `void`/the value on success — matching the wasm-bindgen bindings.
 */
export interface GkrVerifier {
  verify_full_proof_explicit(
    circuit_bytes: Uint8Array,
    vk_bytes: Uint8Array,
    proof_bytes: Uint8Array,
    output_root: Uint8Array,
    config_hash: Uint8Array,
    starting_state_root: Uint8Array,
    block_range_start: bigint,
    block_range_end: bigint,
    circuit_version: Uint8Array,
  ): void;
}

/**
 * - `strict`: every attached proof must be present and verify, else throw.
 * - `inclusion`: verify only the GroveDB inclusion proof against `state_root`
 *   (+ optional light-client anchoring); skip transformation verification.
 */
export type VerifyMode = "strict" | "inclusion";

export interface VerifyOptions {
  mode?: VerifyMode;
  /**
   * GKR transformation verifier (the wasm module). Required to verify
   * `gkr_proofs` in `strict` mode. Pass `loadGkrVerifier()`'s result, or omit
   * to skip transformation verification (allowed only in `inclusion` mode).
   */
  gkrVerifier?: GkrVerifier;
  /**
   * When true, cross-check `state_root` against a light-client-verified app
   * hash at the response's block height before trusting the inclusion proof.
   */
  anchorStateRoot?: boolean;
  /** Reject responses older than this many seconds (freshness bound). */
  maxAgeSecs?: number;
}

/** Which legs were verified, for transparency. */
export interface VerifiedLegs {
  inclusion: boolean;
  /** null = no transformation proofs attached; true/false = verified result. */
  transformation: boolean | null;
  stateRootAnchored: boolean;
  /** Always false for now — completeness verification lands with the wasm repoint. */
  completeness: boolean;
}

export interface VerifiedResult {
  /** Decoded answer bytes (empty when the key is absent). */
  answer: Uint8Array;
  answerExists: boolean;
  stateRoot: Uint8Array;
  blockRange: [number, number];
  verified: VerifiedLegs;
  /** The raw response, for callers that want the proofs. */
  raw: VerifiableRpcResponse;
}

export class VerifiableRpcError extends Error {
  constructor(
    message: string,
    readonly code:
      | "MISSING_PROOF"
      | "INCLUSION_FAILED"
      | "TRANSFORMATION_FAILED"
      | "CIRCUIT_PIN_FAILED"
      | "CHAIN_BROKEN"
      | "STALE"
      | "ROOT_MISMATCH",
  ) {
    super(message);
    this.name = "VerifiableRpcError";
  }
}
