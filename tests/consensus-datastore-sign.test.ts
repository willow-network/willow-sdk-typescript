import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { createSignMessage, createTransactionWrapper, DataStoreTx } from '../src/consensus/types';

const sha256Hex = (s: string) => bytesToHex(sha256(new TextEncoder().encode(s)));

describe('createSignMessage — DataStore', () => {
  function makeTx(data: string): DataStoreTx {
    return {
      subgroveId: 'audit-log',
      key: 'rec-1',
      data,
      ownerDid: 'did:willow:test',
      nonce: 1,
    };
  }

  it('hashes the raw data string as sent (preserves key order, no sort)', () => {
    // The chain hashes the wire bytes (StoreData.data is Vec<u8>, the UTF-8 of
    // the original JSON string). Sorting on the SDK side would hash other
    // bytes than the ones sent.
    const tx = makeTx('{"z":1,"a":2}');
    const msg = createSignMessage('DataStore', tx);
    expect(msg).toBe(
      [
        'StoreData',
        'Subgrove: audit-log',
        'Key: rec-1',
        'Owner: did:willow:test',
        `DataHash: ${sha256Hex('{"z":1,"a":2}')}`,
        'Nonce: 1',
      ].join('\n'),
    );
    expect(msg).not.toContain(sha256Hex('{"a":2,"z":1}'));
  });

  it('refuses to sign data that is not a JSON object, which the node refuses in its block', () => {
    const refusal = (data: unknown) => {
      try {
        createSignMessage('DataStore', makeTx(data as string));
      } catch (error) {
        return (error as { code?: string }).code;
      }
      return 'signed';
    };
    for (const data of ['not json at all', '[1]', '"text"', '42', 'null', '{"a":1} x', '{"s":"\\ud800"}', '', undefined]) {
      expect(refusal(data)).toBe('INVALID_SIGNED_FIELD');
    }
    // Any JSON object, in any form the node reads, is signed as its bytes.
    for (const data of ['{}', ' {"b":[1,{"c":null}],"a":"\\u00e9"} ', '{"a":1,"a":2}']) {
      expect(createSignMessage('DataStore', makeTx(data))).toContain(`\nDataHash: ${sha256Hex(data)}\n`);
    }
  });

  it('hashes exactly the bytes the wrapper sends', () => {
    const tx = makeTx('{"name":"Zoë 🌳"}');
    const sent = createTransactionWrapper('DataStore', tx).StoreData.data as number[];
    expect(createSignMessage('DataStore', tx)).toContain(
      `\nDataHash: ${bytesToHex(sha256(Uint8Array.from(sent)))}\n`,
    );
  });

  it('signs the nonce the transaction carries', () => {
    expect(createSignMessage('DataStore', { ...makeTx('{}'), nonce: 7 })).toMatch(/\nNonce: 7$/);
    expect(createSignMessage('DataStore', { ...makeTx('{}'), nonce: 8 })).toMatch(/\nNonce: 8$/);
  });
});
