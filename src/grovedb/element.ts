/**
 * GroveDB `Element` deserialization.
 *
 * Matches the bincode 2 wire format used by grovedb 3.1.0. The Rust type is:
 *
 *   pub enum Element {
 *       Item(Vec<u8>, Option<ElementFlags>),
 *       Reference(ReferencePathType, MaxReferenceHop, Option<ElementFlags>),
 *       Tree(Option<Vec<u8>>, Option<ElementFlags>),
 *       SumItem(SumValue, Option<ElementFlags>),
 *       SumTree(Option<Vec<u8>>, SumValue, Option<ElementFlags>),
 *       BigSumTree(Option<Vec<u8>>, BigSumValue, Option<ElementFlags>),
 *       CountTree(Option<Vec<u8>>, CountValue, Option<ElementFlags>),
 *       CountSumTree(Option<Vec<u8>>, CountValue, SumValue, Option<ElementFlags>),
 *   }
 *
 * where:
 *   ElementFlags = Vec<u8>
 *   MaxReferenceHop = Option<u8>
 *   SumValue = i64       (zigzag varint)
 *   BigSumValue = i128   (zigzag varint)
 *   CountValue = u64     (unsigned varint)
 *
 * `ReferencePathType` is a 7-variant enum (see reference_path.rs). Variants
 * use byte-slice payloads and small u8 heights; all encoded with bincode 2.
 */

import { BincodeReader } from './bincode';
import { Element, GroveDBVerificationError } from './types';

const ELEMENT_ITEM = 0;
const ELEMENT_REFERENCE = 1;
const ELEMENT_TREE = 2;
const ELEMENT_SUM_ITEM = 3;
const ELEMENT_SUM_TREE = 4;
const ELEMENT_BIG_SUM_TREE = 5;
const ELEMENT_COUNT_TREE = 6;
const ELEMENT_COUNT_SUM_TREE = 7;

export function deserializeElement(bytes: Uint8Array): Element {
  const reader = new BincodeReader(bytes);
  return readElement(reader);
}

function readElement(reader: BincodeReader): Element {
  const variant = reader.readVariant();

  switch (variant) {
    case ELEMENT_ITEM: {
      const value = reader.readByteVec();
      const flags = reader.readOptionByteVec();
      return { type: 'Item', value, flags };
    }

    case ELEMENT_REFERENCE: {
      const path = readReferencePath(reader);
      // MaxReferenceHop = Option<u8>
      const _maxHop = reader.readOptionU8();
      void _maxHop;
      const flags = reader.readOptionByteVec();
      return { type: 'Reference', path, flags };
    }

    case ELEMENT_TREE: {
      const rootKey = reader.readOptionByteVec();
      const flags = reader.readOptionByteVec();
      return { type: 'Tree', rootKey, flags };
    }

    case ELEMENT_SUM_ITEM: {
      const value = reader.readVarintI64();
      const flags = reader.readOptionByteVec();
      return { type: 'SumItem', value, flags };
    }

    case ELEMENT_SUM_TREE: {
      const rootKey = reader.readOptionByteVec();
      const sumValue = reader.readVarintI64();
      const flags = reader.readOptionByteVec();
      return { type: 'SumTree', rootKey, sumValue, flags };
    }

    case ELEMENT_BIG_SUM_TREE: {
      const rootKey = reader.readOptionByteVec();
      const sumValue = reader.readVarintI128();
      const flags = reader.readOptionByteVec();
      return { type: 'BigSumTree', rootKey, sumValue, flags };
    }

    case ELEMENT_COUNT_TREE: {
      const rootKey = reader.readOptionByteVec();
      const count = reader.readVarintU64();
      const flags = reader.readOptionByteVec();
      return { type: 'CountTree', rootKey, count, flags };
    }

    case ELEMENT_COUNT_SUM_TREE: {
      const rootKey = reader.readOptionByteVec();
      const count = reader.readVarintU64();
      const sum = reader.readVarintI64();
      const flags = reader.readOptionByteVec();
      return { type: 'CountSumTree', rootKey, count, sum, flags };
    }

    default:
      throw new GroveDBVerificationError(`Unknown element variant: ${variant}`);
  }
}

/**
 * Read `ReferencePathType`. The 7 variants are documented in
 * grovedb/src/reference_path.rs.
 *
 * We don't reconstruct the full typed path tree into our TS `Element.Reference`
 * payload — the consumer of a Reference element typically needs the
 * destination, not the raw path-type variant. For now we decode all variants
 * into a uniform `Uint8Array[][]` by flattening their path fields. Callers who
 * need the structured reference type should call a dedicated helper; this one
 * exists so that `deserializeElement` can walk the full byte stream without
 * throwing on reference elements.
 */
function readReferencePath(reader: BincodeReader): Uint8Array[][] {
  const variant = reader.readVariant();

  switch (variant) {
    case 0: {
      // AbsolutePathReference(Vec<Vec<u8>>)
      const path = reader.readVecOfByteVec();
      return [path];
    }
    case 1:
    case 2:
    case 3: {
      // UpstreamRootHeightReference(u8, Vec<Vec<u8>>)
      // UpstreamRootHeightWithParentPathAdditionReference(u8, Vec<Vec<u8>>)
      // UpstreamFromElementHeightReference(u8, Vec<Vec<u8>>)
      reader.readU8();
      const path = reader.readVecOfByteVec();
      return [path];
    }
    case 4: {
      // CousinReference(Vec<u8>)
      const single = reader.readByteVec();
      return [[single]];
    }
    case 5: {
      // RemovedCousinReference(Vec<Vec<u8>>)
      const path = reader.readVecOfByteVec();
      return [path];
    }
    case 6: {
      // SiblingReference(Vec<u8>)
      const single = reader.readByteVec();
      return [[single]];
    }
    default:
      throw new GroveDBVerificationError(
        `Unknown ReferencePathType variant: ${variant}`,
      );
  }
}

export function isTreeElement(element: Element): boolean {
  return (
    element.type === 'Tree' ||
    element.type === 'SumTree' ||
    element.type === 'BigSumTree' ||
    element.type === 'CountTree' ||
    element.type === 'CountSumTree'
  );
}

export function hasRootKey(element: Element): boolean {
  switch (element.type) {
    case 'Tree':
    case 'SumTree':
    case 'BigSumTree':
    case 'CountTree':
    case 'CountSumTree':
      return element.rootKey !== null;
    default:
      return false;
  }
}

export function getTreeFeatureType(element: Element): string | null {
  switch (element.type) {
    case 'Tree':
      return 'BasicMerkNode';
    case 'SumTree':
      return 'SummedMerkNode';
    case 'BigSumTree':
      return 'BigSummedMerkNode';
    case 'CountTree':
      return 'CountedMerkNode';
    case 'CountSumTree':
      return 'CountedSummedMerkNode';
    default:
      return null;
  }
}
