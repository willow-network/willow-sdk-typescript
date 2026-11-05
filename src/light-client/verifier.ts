/**
 * Light Client Verification
 *
 * Header verification using CometBFT light client protocol and GroveDB proof verification.
 * Uses @noble/curves for Ed25519 and secp256k1 signature verification.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { LightBlock, Header, Commit, ValidatorSet, CommitSig, TrustThreshold, VerificationResult, LightClientError, GroveDBQueryProof, getTrustFraction, bytesToHex } from './types';
import { verifyGroveDBProof, verifyKeyAbsence } from '../grovedb';
import { WillowLogger, silentLogger } from '../internal/logger';

/**
 * Verifies block headers using CometBFT light client protocol.
 *
 * @experimental Commit-signature verification does NOT yet work against
 * real CometBFT chains: votes are verified over a canonical-JSON encoding,
 * but CometBFT 0.34+ signs the protobuf `CanonicalVote` message (see
 * `createVoteSignBytes`). Until protobuf sign-bytes are implemented, every
 * real commit signature fails verification and `verifyHeader` reports
 * insufficient voting power.
 */
export class HeaderVerifier {
  private chainId: string;
  private trustThreshold: TrustThreshold;
  private logger: WillowLogger;

  constructor(chainId: string, trustThreshold: TrustThreshold, logger?: WillowLogger) {
    this.chainId = chainId;
    this.trustThreshold = trustThreshold;
    this.logger = logger ?? silentLogger;
  }

  /**
   * Verify an untrusted header against a trusted state.
   *
   * @experimental This will NOT validate real CometBFT commits yet — the
   * sign-bytes encoding is canonical JSON while CometBFT 0.34+ signs
   * protobuf `CanonicalVote`, so genuine validator signatures fail the
   * check and the trust threshold is never met. Do not rely on this for
   * security until protobuf sign-bytes land.
   */
  async verifyHeader(
    untrustedHeader: LightBlock,
    trustedHeader?: LightBlock,
    trustedValidators?: ValidatorSet,
    maxClockDriftSecs: number = 10
  ): Promise<VerificationResult> {
    try {
      // Basic header validation
      this.validateBasicHeader(untrustedHeader.header, maxClockDriftSecs);

      // If we have a trusted header, verify sequential progression
      if (trustedHeader) {
        this.verifySequential(untrustedHeader, trustedHeader);
      }

      // Verify commit signatures
      const votingPowerResult = await this.verifyCommitSignatures(
        untrustedHeader.commit,
        untrustedHeader.validators,
        untrustedHeader.header
      );

      // Check trust threshold
      const trustLevel = votingPowerResult.trustLevel || 0;
      const requiredTrust = getTrustFraction(this.trustThreshold);

      if (trustLevel < requiredTrust) {
        return {
          success: false,
          error: `Insufficient voting power: ${trustLevel.toFixed(3)} < ${requiredTrust.toFixed(3)}`,
          height: untrustedHeader.header.height,
          trustLevel
        };
      }

      // Additional validation for validator set transitions
      if (trustedHeader) {
        this.verifyValidatorSetTransition(untrustedHeader, trustedHeader);
      }

      return {
        success: true,
        height: untrustedHeader.header.height,
        trustLevel
      };

    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : String(error),
        height: untrustedHeader.header.height
      };
    }
  }

  /**
   * Validate basic header properties
   */
  private validateBasicHeader(header: Header, maxClockDriftSecs: number): void {
    // Chain ID must match
    if (header.chainId !== this.chainId) {
      throw new LightClientError(`Chain ID mismatch: ${header.chainId} !== ${this.chainId}`);
    }

    // Height must be positive
    if (header.height <= 0) {
      throw new LightClientError(`Invalid height: ${header.height}`);
    }

    // Time must be reasonable (not too far in future/past)
    const now = new Date();
    const timeDiff = Math.abs(header.time.getTime() - now.getTime()) / 1000;
    if (timeDiff > maxClockDriftSecs) {
      throw new LightClientError(`Clock drift too large: ${timeDiff}s > ${maxClockDriftSecs}s`);
    }
  }

  /**
   * Verify sequential header progression
   */
  private verifySequential(untrusted: LightBlock, trusted: LightBlock): void {
    // Height must increase by exactly 1
    if (untrusted.header.height !== trusted.header.height + 1) {
      throw new LightClientError(
        `Non-sequential height: ${untrusted.header.height} !== ${trusted.header.height + 1}`
      );
    }

    // Time must progress forward
    if (untrusted.header.time <= trusted.header.time) {
      throw new LightClientError('Time did not progress forward');
    }
  }

  /**
   * Verify commit signatures and calculate voting power
   */
  private async verifyCommitSignatures(
    commit: Commit,
    validators: ValidatorSet,
    header: Header
  ): Promise<VerificationResult> {
    if (commit.signatures.length !== validators.validators.length) {
      throw new LightClientError('Signature count mismatch with validator count');
    }

    let totalVotingPower = 0;
    let validVotingPower = 0;

    for (let i = 0; i < commit.signatures.length; i++) {
      const sig = commit.signatures[i];
      const validator = validators.validators[i];

      totalVotingPower += validator.votingPower;

      // Skip nil signatures (validator didn't sign)
      // blockIdFlag: 1 = absent, 2 = commit, 3 = nil
      if (!sig.signature || sig.blockIdFlag !== 2) {
        continue;
      }

      // Verify signature
      try {
        if (await this.verifySignature(commit, header, validator, sig)) {
          validVotingPower += validator.votingPower;
        }
      } catch (error) {
        // Invalid signature - skip this validator
        this.logger.debug(`Signature verification failed for validator ${i}:`, error);
        continue;
      }
    }

    const trustLevel = totalVotingPower > 0 ? validVotingPower / totalVotingPower : 0.0;

    return {
      success: true,
      trustLevel
    };
  }

  /**
   * Verify individual validator signature using Ed25519
   */
  private async verifySignature(
    commit: Commit,
    header: Header,
    validator: ValidatorSet['validators'][0],
    sig: CommitSig
  ): Promise<boolean> {
    if (!sig.signature) {
      return false;
    }

    // Create canonical sign bytes (CometBFT vote format)
    const signBytes = this.createVoteSignBytes(commit, header, sig);

    try {
      // CometBFT uses Ed25519 for validator signatures
      // The public key should be 32 bytes for Ed25519
      if (validator.pubKey.length === 32) {
        return ed25519.verify(sig.signature, signBytes, validator.pubKey);
      } else if (validator.pubKey.length === 33 || validator.pubKey.length === 65) {
        // secp256k1 compressed (33) or uncompressed (65) public key
        // Hash the message first for secp256k1
        const messageHash = sha256(signBytes);
        return secp256k1.verify(sig.signature, messageHash, validator.pubKey);
      } else {
        this.logger.warn(`Unknown public key length: ${validator.pubKey.length}`);
        return false;
      }
    } catch (error) {
      this.logger.debug('Signature verification error:', error);
      return false;
    }
  }

  /**
   * Create sign bytes for CometBFT vote signature verification.
   *
   * KNOWN LIMITATION: this builds a canonical-JSON encoding, but CometBFT
   * 0.34+ signs the protobuf-encoded `CanonicalVote` message
   * (https://github.com/cometbft/cometbft/blob/main/types/canonical.go),
   * NOT canonical JSON. The bytes produced here therefore never match what
   * real validators signed, and signature verification against a live
   * chain always fails. Kept as a placeholder until protobuf sign-bytes
   * are implemented.
   */
  private createVoteSignBytes(commit: Commit, header: Header, sig: CommitSig): Uint8Array {
    // CometBFT uses a specific canonical JSON format for vote signing
    // The format is: {"@type":"/tendermint.types.CanonicalVote", ...}
    const canonicalVote = {
      '@type': '/tendermint.types.CanonicalVote',
      block_id: {
        hash: bytesToHex(commit.blockId.hash).toUpperCase(),
        part_set_header: {
          total: commit.blockId.partSetHeaderTotal,
          hash: bytesToHex(commit.blockId.partSetHeaderHash).toUpperCase()
        }
      },
      chain_id: header.chainId,
      height: commit.height.toString(),
      round: commit.round.toString(),
      timestamp: sig.timestamp.toISOString(),
      type: 2 // PrecommitType
    };

    // Sort keys alphabetically for canonical encoding
    const canonicalJson = JSON.stringify(canonicalVote, Object.keys(canonicalVote).sort());
    return new TextEncoder().encode(canonicalJson);
  }

  /**
   * Verify validator set hash transition
   */
  private verifyValidatorSetTransition(untrusted: LightBlock, trusted: LightBlock): void {
    // The untrusted header's validators_hash should match the trusted next_validators_hash
    if (!this.arraysEqual(untrusted.header.validatorsHash, trusted.header.nextValidatorsHash)) {
      throw new LightClientError('Validator set transition hash mismatch');
    }
  }

  /**
   * Utility: Compare two Uint8Arrays for equality
   */
  private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

/**
 * Verifies GroveDB proofs against trusted headers. Each check verifies the
 * proof and compares its root to the trusted one, and binds what it is asked
 * about to the proof: a value to its key and path, an absence to the place
 * its key would have.
 */
export class ProofVerifier {
  /**
   * Verify a GroveDB query proof against a trusted app hash. The proof must
   * verify to `trustedAppHash`, and each entry of `queryResult` (or of
   * `proof.queryResult` when none is given) must be the bytes of an Item the
   * proof proves, as the `KV` node grovedb proves an Item in. It does not tie those values to a path, nor show that
   * they are a query's whole result (membership only): to check one key at
   * a known path, use {@link verifyInclusionProof}; to verify a query's
   * result, `verifyQuerySelection`.
   */
  async verifyQueryProof(
    proof: GroveDBQueryProof,
    trustedAppHash: Uint8Array,
    queryResult?: Uint8Array[]
  ): Promise<VerificationResult> {
    try {
      const values = queryResult ?? proof.queryResult ?? [];
      const verification = verifyGroveDBProof(proof.proof);

      if (!this.arraysEqual(verification.rootHash, trustedAppHash)) {
        return {
          success: false,
          error: `Root hash mismatch: computed ${bytesToHex(verification.rootHash)} !== trusted ${bytesToHex(trustedAppHash)}`,
          height: proof.height
        };
      }

      // Each Item a KV node proves: a reference's value (KVRefValueHash) is
      // the element it points to, not one stored at its key.
      const proven = verification.results.flatMap((r) =>
        r.nodeType === 'KV' && r.element?.type === 'Item' ? [r.element.value] : []
      );
      for (let i = 0; i < values.length; i++) {
        if (!proven.some((v) => this.arraysEqual(v, values[i]))) {
          return {
            success: false,
            error: `Query result ${i} is not a value the proof proves`,
            height: proof.height
          };
        }
      }

      return {
        success: true,
        height: proof.height
      };

    } catch (error) {
      return {
        success: false,
        error: `Proof verification failed: ${error instanceof Error ? error.message : String(error)}`,
        height: proof.height
      };
    }
  }

  /**
   * Verify that `key` holds the Item `value` (its bytes) at `path`: the proof
   * verifies to `trustedRoot`, descends to `path` with no lower layer off it,
   * and proves at `path` an Item at `key` whose bytes are `value`, as the
   * `KV` node grovedb proves an Item in. False for any other proof,
   * including a valid one of another key or path, and one that gives a
   * reference at the key (whose value is the element it points to).
   *
   * @param path - The GroveDB path of the subtree holding `key` (e.g. the
   *   UTF-8 bytes of `["subgroves", id, "data"]`). Required: a key is only
   *   meaningful at its path.
   */
  async verifyInclusionProof(
    key: Uint8Array,
    value: Uint8Array,
    proofBytes: Uint8Array,
    trustedRoot: Uint8Array,
    path: Uint8Array[]
  ): Promise<boolean> {
    requirePath(path);
    try {
      const verification = verifyGroveDBProof(proofBytes, { expectedPath: path });
      if (!this.arraysEqual(verification.rootHash, trustedRoot)) return false;
      // The value is the payload of the Item grovedb proves at the key, as a
      // KV node: a reference (KVRefValueHash) carries the element it points
      // to, which is not stored at the key.
      return verification.results.some(
        (r) =>
          this.pathEqual(r.path, path) &&
          this.arraysEqual(r.key, key) &&
          r.nodeType === 'KV' &&
          r.element?.type === 'Item' &&
          this.arraysEqual(r.element.value, value)
      );
    } catch {
      return false;
    }
  }

  /**
   * Verify that `key` is absent at `path`: the proof verifies to
   * `trustedRoot` and shows where `key` would be in the subtree at `path`
   * with nothing there (see `verifyKeyAbsence` in the GroveDB module). False
   * for any other proof, including one in which `key` is present.
   *
   * @param path - The GroveDB path of the subtree `key` would be in.
   *   Required: a key is only absent at a path.
   */
  async verifyAbsenceProof(
    key: Uint8Array,
    proofBytes: Uint8Array,
    trustedRoot: Uint8Array,
    path: Uint8Array[]
  ): Promise<boolean> {
    requirePath(path);
    try {
      return this.arraysEqual(verifyKeyAbsence(proofBytes, path, key), trustedRoot);
    } catch {
      return false;
    }
  }

  private pathEqual(a: Uint8Array[], b: Uint8Array[]): boolean {
    return a.length === b.length && a.every((segment, i) => this.arraysEqual(segment, b[i]));
  }

  /**
   * Utility: Compare two Uint8Arrays for equality
   */
  private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

function requirePath(path: unknown): void {
  if (!Array.isArray(path) || !path.every((segment) => segment instanceof Uint8Array)) {
    throw new LightClientError('A GroveDB path (an array of byte arrays) is required', 'PATH_REQUIRED');
  }
}
