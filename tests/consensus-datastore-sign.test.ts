import { createSignMessage, DataStoreTx } from '../src/consensus/types';

describe('createSignMessage — DataStore', () => {
  it('signs over the raw data string (preserves key order, no sort)', () => {
    // Server reconstructs the sign message from the wire bytes (StoreData.data
    // is Vec<u8>, UTF-8 of the original JSON string). Sorting on the SDK side
    // breaks signature verification because the server's reconstructed message
    // contains the original-order JSON.
    const tx: DataStoreTx = {
      subgroveId: 'audit-log',
      key: 'rec-1',
      data: '{"z":1,"a":2}',
      ownerDid: 'did:willow:test',
      nonce: 1,
    };
    const msg = createSignMessage('DataStore', tx);
    expect(msg).toBe('audit-log:rec-1:{"z":1,"a":2}');
  });

  it('handles non-JSON data by signing over the raw string', () => {
    const tx: DataStoreTx = {
      subgroveId: 'audit-log',
      key: 'rec-1',
      data: 'not json at all',
      ownerDid: 'did:willow:test',
      nonce: 1,
    };
    const msg = createSignMessage('DataStore', tx);
    expect(msg).toBe('audit-log:rec-1:not json at all');
  });
});
