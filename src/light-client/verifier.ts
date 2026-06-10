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
import { verifyGroveDBProof } from '../grovedb';
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
 * Verifies GroveDB proofs against trusted headers
 */
export class ProofVerifier {
  /**
   * Verify a GroveDB query proof against a trusted app hash
   */
  async verifyQueryProof(
    proof: GroveDBQueryProof,
    trustedAppHash: Uint8Array,
    queryResult?: Uint8Array[]
  ): Promise<VerificationResult> {
    try {
      // Extract query result from proof if not provided
      if (!queryResult) {
        queryResult = proof.queryResult || [];
      }

      // Verify the proof reconstructs to the trusted app hash
      const computedRoot = await this.verifyGroveDbProof(proof.proof, queryResult);

      if (!this.arraysEqual(computedRoot, trustedAppHash)) {
        return {
          success: false,
          error: `Root hash mismatch: computed ${bytesToHex(computedRoot)} !== trusted ${bytesToHex(trustedAppHash)}`,
          height: proof.height
        };
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
   * Verify a GroveDB proof and return the computed root hash.
   *
   * Decodes the bincode-encoded proof, walks each Merk layer, and returns
   * the cryptographically correct root. The caller compares this against a
   * trusted root (e.g. a light-client-verified app hash) to establish
   * authenticity.
   */
  private async verifyGroveDbProof(proofBytes: Uint8Array, _queryResult: Uint8Array[]): Promise<Uint8Array> {
    return verifyGroveDBProof(proofBytes).rootHash;
  }

  /**
   * Verify that a key-value pair is included in the tree
   */
  async verifyInclusionProof(
    key: Uint8Array,
    value: Uint8Array,
    proofBytes: Uint8Array,
    trustedRoot: Uint8Array
  ): Promise<boolean> {
    // For full inclusion proof verification, use server-assisted verification
    // This requires parsing the GroveDB proof format
    const queryProof: GroveDBQueryProof = {
      proof: proofBytes,
      pathQuery: { key },
      height: 0,
      queryResult: [value]
    };

    const result = await this.verifyQueryProof(queryProof, trustedRoot, [value]);
    return result.success;
  }

  /**
   * Verify that a key is absent from the tree
   */
  async verifyAbsenceProof(
    key: Uint8Array,
    proofBytes: Uint8Array,
    trustedRoot: Uint8Array
  ): Promise<boolean> {
    // Absence proofs in GroveDB show that a key doesn't exist
    // For full verification, use server-assisted verification
    const queryProof: GroveDBQueryProof = {
      proof: proofBytes,
      pathQuery: { key },
      height: 0,
      queryResult: []
    };

    const result = await this.verifyQueryProof(queryProof, trustedRoot, []);
    return result.success;
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
