import { createTransactionWrapper, DataStoreTx } from '../src/consensus/types';

describe('createTransactionWrapper — DataStore', () => {
  function makeTx(dataJson: string): DataStoreTx {
    return {
      subgroveId: 'audit-log',
      key: 'rec-1',
      data: dataJson,
      ownerDid: 'did:willow:test',
      signature: '00'.repeat(32),
      publicKeyId: 'did:willow:test#key-1',
      nonce: 1,
    };
  }

  it('encodes data as Vec<u8> (byte array) — matches Rust server StoreData.data type', () => {
    const dataJson = '{"merkle_root":"abc","count":1}';
    const wrapper = createTransactionWrapper('DataStore', makeTx(dataJson));

    expect(wrapper.StoreData).toBeDefined();
    const sentData = wrapper.StoreData.data;
    expect(Array.isArray(sentData)).toBe(true);
    expect(sentData.every((b: unknown) => typeof b === 'number' && b >= 0 && b <= 255)).toBe(true);

    const decoded = new TextDecoder().decode(new Uint8Array(sentData));
    expect(decoded).toBe(dataJson);
  });

  it('preserves the exact UTF-8 bytes of the data string', () => {
    const dataJson = '{"emoji":"🎉","arr":[1,2,3]}';
    const wrapper = createTransactionWrapper('DataStore', makeTx(dataJson));

    const decoded = new TextDecoder().decode(new Uint8Array(wrapper.StoreData.data));
    expect(decoded).toBe(dataJson);
  });
});
