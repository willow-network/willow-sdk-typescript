/**
 * Bincode 2 decoder for `GroveDBProof`.
 *
 * Schema (grovedb-3.1.0/src/operations/proof/mod.rs):
 *
 *   pub enum GroveDBProof {
 *       V0(GroveDBProofV0),
 *   }
 *   pub struct GroveDBProofV0 {
 *       pub root_layer: LayerProof,
 *       pub prove_options: ProveOptions,
 *   }
 *   pub struct LayerProof {
 *       pub merk_proof: Vec<u8>,
 *       pub lower_layers: BTreeMap<Key, LayerProof>,  // Key = Vec<u8>
 *   }
 *   pub struct ProveOptions {
 *       pub decrease_limit_on_empty_sub_query_result: bool,
 *   }
 */

import { BincodeReader, bytesToHex } from './bincode';
import {
  GroveDBProof,
  GroveDBProofV0,
  GroveDBVerificationError,
  LayerProof,
  ProveOptions,
} from './types';

/**
 * Maximum nesting depth for layer proofs. A real GroveDB path is a handful of
 * segments deep; this cap only exists so a crafted proof (~3 bytes per level)
 * can't drive the recursive decode — and the recursive verification walks over
 * the decoded structure — into a stack overflow.
 */
const MAX_LAYER_DEPTH = 64;

function decodeLayerProof(reader: BincodeReader, depth: number): LayerProof {
  if (depth > MAX_LAYER_DEPTH) {
    throw new GroveDBVerificationError(
      `Layer proof nesting exceeds maximum depth of ${MAX_LAYER_DEPTH}`,
    );
  }

  const merkProof = reader.readByteVec();
  const mapLen = reader.readLength();
  const lowerLayers = new Map<string, LayerProof>();

  for (let i = 0; i < mapLen; i++) {
    const keyBytes = reader.readByteVec();
    const value = decodeLayerProof(reader, depth + 1);
    lowerLayers.set(bytesToHex(keyBytes), value);
  }

  return { merkProof, lowerLayers };
}

function decodeProveOptions(reader: BincodeReader): ProveOptions {
  return {
    decreaseLimitOnEmptySubQueryResult: reader.readBool(),
  };
}

function decodeGroveDBProofV0(reader: BincodeReader): GroveDBProofV0 {
  const rootLayer = decodeLayerProof(reader, 0);
  const proveOptions = decodeProveOptions(reader);
  return { rootLayer, proveOptions };
}

export function decodeGroveDBProof(bytes: Uint8Array): GroveDBProof {
  const reader = new BincodeReader(bytes);

  const variant = reader.readVariant();
  if (variant !== 0) {
    throw new GroveDBVerificationError(
      `Unknown GroveDBProof variant: ${variant} (only V0 supported)`,
    );
  }

  const proof = decodeGroveDBProofV0(reader);

  if (reader.hasMore()) {
    throw new GroveDBVerificationError(
      `Trailing bytes after GroveDBProof decode: ${reader.remaining()} bytes at offset ${reader.position()}`,
    );
  }

  return { version: 0, proof };
}
