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

  it('hashes non-JSON data as its raw string', () => {
    const msg = createSignMessage('DataStore', makeTx('not json at all'));
    expect(msg).toContain(`\nDataHash: ${sha256Hex('not json at all')}\n`);
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
