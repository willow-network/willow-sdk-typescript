/**
 * Verifiable RPC: fetch a query result from an indexer and verify the attached
 * proofs locally — no consensus round-trip, no trusted RPC.
 *
 * Two legs verify today:
 *  - inclusion: the GroveDB Merkle proof roots at the response's `state_root`,
 *    so `answer` is bound to that committed root.
 *  - transformation: each GKR proof verifies (via the `@willow-network/gkr-verify-wasm`
 *    companion package), the chunks chain (`starting_state_root[i+1] === output_root[i]`),
 *    and the final `output_root` equals `state_root` — so `state_root` is the proven
 *    output of applying the subgrove transformation to the committed events.
 *
 * Together they bind `answer` to a GKR-proven transformation output. Two anchors
 * are follow-ups (documented inline): cross-checking `state_root` continuity
 * against a light client, and the completeness leg (lands with the
 * binius-verify-wasm repoint).
 */

import { sha256 } from "@noble/hashes/sha256";
import { HttpClient } from "../internal/http";
import { base64ToBytes } from "../internal/bytes";
import { bytesToHex } from "../grovedb/bincode";
import { computeProofRootHash } from "../proof";
import {
  type GkrProofData,
  type GkrVerifier,
  type VerifiableRpcResponse,
  type VerifiedResult,
  type VerifyOptions,
  VerifiableRpcError,
} from "./types";

export * from "./types";

const toBytes = (a: number[]): Uint8Array => Uint8Array.from(a);
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);
const normRoot = (hex: string): string => hex.toLowerCase().replace(/^0x/, "");

/** gunzip a byte stream isomorphically (browser DecompressionStream / Node zlib). */
async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  // DOM stream types aren't in the ES2020 lib; access the browser globals via
  // minimal `unknown` shapes, fall back to Node's zlib off-DOM.
  const G = globalThis as unknown as {
    DecompressionStream?: new (format: string) => unknown;
    Blob?: new (parts: [Uint8Array]) => { stream(): { pipeThrough(t: unknown): unknown } };
    Response?: new (body: unknown) => { arrayBuffer(): Promise<ArrayBuffer> };
  };
  if (G.DecompressionStream && G.Blob && G.Response) {
    const ds = new G.DecompressionStream("gzip");
    const stream = new G.Blob([data]).stream().pipeThrough(ds);
    return new Uint8Array(await new G.Response(stream).arrayBuffer());
  }
  const { gunzipSync } = await import("node:zlib");
  return new Uint8Array(gunzipSync(data));
}

/**
 * Fetch a content-addressed `.bin.gz` artifact, gunzip it, and pin
 * `SHA-256(bytes) === expected`. A tampered indexer fails the pin before any
 * bytes reach the verifier — so no trust in the serving indexer is required.
 */
async function fetchPinnedArtifact(
  baseUrl: string,
  route: "circuit" | "vk",
  hashHex: string,
  expected: Uint8Array,
  pin: boolean,
): Promise<Uint8Array> {
  const url = `${baseUrl.replace(/\/+$/, "")}/${route}/${hashHex}.bin.gz`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new VerifiableRpcError(
      `fetch ${route} ${hashHex} failed: ${res.status}`,
      "CIRCUIT_PIN_FAILED",
    );
  }
  const bytes = await gunzip(new Uint8Array(await res.arrayBuffer()));
  // Only the circuit is content-addressed by `verification_key_hash`; a wrong
  // VK is caught by the proof failing to verify, so it is not separately pinned.
  if (pin && !bytesEqual(sha256(bytes), expected)) {
    throw new VerifiableRpcError(
      `${route} SHA-256 does not match verification_key_hash`,
      "CIRCUIT_PIN_FAILED",
    );
  }
  return bytes;
}

/**
 * Verify the transformation proofs in a response: each GKR proof verifies, the
 * chunks chain, and the final `output_root` equals `stateRoot`. Throws on the
 * first failure. Fetches each circuit/VK from `indexerBaseUrl` content-addressed
 * by `verification_key_hash`.
 */
export async function verifyTransformationProofs(
  indexerBaseUrl: string,
  gkrProofs: GkrProofData[],
  stateRoot: Uint8Array,
  verifier: GkrVerifier,
): Promise<void> {
  let prevOutputRoot: Uint8Array | null = null;
  // Cache circuit/VK per hash so chunked proofs of one shape fetch once.
  const cache = new Map<string, { circuit: Uint8Array; vk: Uint8Array }>();

  for (let i = 0; i < gkrProofs.length; i++) {
    const gp = gkrProofs[i];
    const cv = toBytes(gp.verification_key_hash);
    const hashHex = bytesToHex(cv);
    const pi = gp.public_inputs;
    const startRoot = toBytes(pi.starting_state_root);

    if (prevOutputRoot && !bytesEqual(startRoot, prevOutputRoot)) {
      throw new VerifiableRpcError(
        `chunk ${i} starting_state_root does not chain to chunk ${i - 1} output_root`,
        "CHAIN_BROKEN",
      );
    }

    let art = cache.get(hashHex);
    if (!art) {
      const [circuit, vk] = await Promise.all([
        fetchPinnedArtifact(indexerBaseUrl, "circuit", hashHex, cv, true),
        fetchPinnedArtifact(indexerBaseUrl, "vk", hashHex, cv, false),
      ]);
      art = { circuit, vk };
      cache.set(hashHex, art);
    }

    try {
      verifier.verify_full_proof_explicit(
        art.circuit,
        art.vk,
        toBytes(gp.proof),
        toBytes(pi.output_root),
        toBytes(pi.config_hash),
        startRoot,
        BigInt(pi.block_range[0]),
        BigInt(pi.block_range[1]),
        cv,
      );
    } catch (e) {
      throw new VerifiableRpcError(
        `GKR transformation proof ${i} did not verify: ${(e as Error)?.message ?? e}`,
        "TRANSFORMATION_FAILED",
      );
    }
    prevOutputRoot = toBytes(pi.output_root);
  }

  if (prevOutputRoot && !bytesEqual(prevOutputRoot, stateRoot)) {
    throw new VerifiableRpcError(
      "final transformation output_root does not equal the response state_root",
      "ROOT_MISMATCH",
    );
  }
}

/**
 * Load the GKR transformation verifier from the optional
 * `@willow-network/gkr-verify-wasm` companion package and initialize the wasm.
 * Throws a clear error if the package is not installed.
 */
export async function loadGkrVerifier(): Promise<GkrVerifier> {
  let mod: Record<string, unknown>;
  try {
    mod = (await import(
      /* webpackIgnore: true */ "@willow-network/gkr-verify-wasm" as string
    )) as Record<string, unknown>;
  } catch {
    throw new VerifiableRpcError(
      "transformation verification requires the optional '@willow-network/gkr-verify-wasm' package; install it or pass mode:'inclusion'",
      "TRANSFORMATION_FAILED",
    );
  }
  if (typeof mod.default === "function") {
    await (mod.default as () => Promise<unknown>)();
  }
  return mod as unknown as GkrVerifier;
}

/** Direct indexer→client verifiable reads. */
export class VerifiableRpcOperations {
  constructor(
    private readonly indexerBaseUrl: string,
    private readonly http: HttpClient = new HttpClient({ baseURL: indexerBaseUrl }),
  ) {}

  /** Fetch the raw response (proofs attached, unverified). */
  async get(subgroveId: string, queryKey: string): Promise<VerifiableRpcResponse> {
    return this.http.get<VerifiableRpcResponse>(
      `/verifiable-rpc/${encodeURIComponent(subgroveId)}/${encodeURIComponent(queryKey)}`,
    );
  }

  /**
   * Fetch and verify. In `strict` mode (default) the inclusion proof must root
   * at `state_root` AND every attached GKR proof must verify and chain to it;
   * any failure throws. In `inclusion` mode only the GroveDB proof is checked.
   */
  async verify(
    subgroveId: string,
    queryKey: string,
    opts: VerifyOptions = {},
  ): Promise<VerifiedResult> {
    const mode = opts.mode ?? "strict";
    const resp = await this.get(subgroveId, queryKey);

    if (opts.maxAgeSecs !== undefined) {
      const ageSecs = Math.floor(Date.now() / 1000) - resp.served_at_unix_secs;
      if (ageSecs > opts.maxAgeSecs) {
        throw new VerifiableRpcError(
          `response is ${ageSecs}s old, exceeds maxAgeSecs ${opts.maxAgeSecs}`,
          "STALE",
        );
      }
    }

    const stateRoot = toBytes(resp.state_root);
    const stateRootHex = bytesToHex(stateRoot);

    // Inclusion: the GroveDB proof must verify and root at state_root.
    const proofHex = bytesToHex(base64ToBytes(resp.grovedb_proof));
    let inclusion = false;
    try {
      const computedRoot = await computeProofRootHash(proofHex);
      inclusion = normRoot(computedRoot) === normRoot(stateRootHex);
    } catch (e) {
      throw new VerifiableRpcError(
        `inclusion proof did not verify: ${(e as Error)?.message ?? e}`,
        "INCLUSION_FAILED",
      );
    }
    if (!inclusion) {
      throw new VerifiableRpcError(
        "inclusion proof root does not match the response state_root",
        "INCLUSION_FAILED",
      );
    }

    // Transformation: verify the GKR proofs (strict mode only).
    let transformation: boolean | null = null;
    if (mode === "strict" && resp.gkr_proofs.length > 0) {
      const verifier = opts.gkrVerifier ?? (await loadGkrVerifier());
      await verifyTransformationProofs(
        this.indexerBaseUrl,
        resp.gkr_proofs,
        stateRoot,
        verifier,
      );
      transformation = true;
    } else if (resp.gkr_proofs.length > 0) {
      transformation = false; // present but not verified (inclusion mode)
    }

    return {
      answer: base64ToBytes(resp.answer),
      answerExists: resp.answer_exists,
      stateRoot,
      blockRange: resp.block_range,
      verified: {
        inclusion,
        transformation,
        // Follow-ups: state_root light-client continuity anchor + the
        // completeness leg (lands with the binius-verify-wasm repoint).
        stateRootAnchored: false,
        completeness: false,
      },
      raw: resp,
    };
  }
}
