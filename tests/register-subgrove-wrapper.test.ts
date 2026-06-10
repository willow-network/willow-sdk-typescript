import { createTransactionWrapper, RegisterSubgroveTx } from '../src/consensus/types';

/**
 * Guards that RegisterSubgrove threads the caller's name + access lists into
 * the wire shape instead of hard-coding owner-only. The previous wrapper
 * hard-coded `name: subgroveId` and `DataStorage { writers: [owner], free_readers: [] }`,
 * silently dropping any writers/readers the caller supplied.
 */
describe('createTransactionWrapper — RegisterSubgrove access lists', () => {
  function baseTx(overrides: Partial<RegisterSubgroveTx> = {}): RegisterSubgroveTx {
    return {
      subgroveId: 'sg',
      schema: JSON.stringify({ version: 1, fields: {} }),
      ownerDid: 'did:willow:owner',
      signature: '00'.repeat(64),
      publicKeyId: 'did:willow:owner#key-1',
      nonce: 3,
      ...overrides,
    };
  }

  it('carries the supplied DataStorage writers/free_readers through to the wire mode', () => {
    const tx = baseTx({
      name: 'My Subgrove',
      mode: {
        DataStorage: {
          name: 'My Subgrove',
          writers: ['did:willow:owner', 'did:willow:writer2'],
          free_readers: ['did:willow:reader1'],
        },
      },
    });
    const wrapper = createTransactionWrapper('RegisterSubgrove', tx).RegisterSubgrove;
    expect(wrapper.name).toBe('My Subgrove');
    expect(wrapper.mode).toEqual({
      DataStorage: {
        name: 'My Subgrove',
        writers: ['did:willow:owner', 'did:willow:writer2'],
        free_readers: ['did:willow:reader1'],
      },
    });
  });

  it('uses the top-level name (not the subgrove id) when supplied', () => {
    const wrapper = createTransactionWrapper(
      'RegisterSubgrove',
      baseTx({ name: 'Human Name' }),
    ).RegisterSubgrove;
    expect(wrapper.name).toBe('Human Name');
    // The default DataStorage mode mirrors the top-level name, not the id.
    expect((wrapper.mode as any).DataStorage.name).toBe('Human Name');
  });

  it('defaults the name to the subgrove id when omitted (backward compatible)', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect(wrapper.name).toBe('sg');
    expect((wrapper.mode as any).DataStorage).toEqual({
      name: 'sg',
      writers: ['did:willow:owner'],
      free_readers: [],
    });
  });

  it('encodes the signature as a byte array, not a hex string', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect(Array.isArray(wrapper.signature)).toBe(true);
    expect((wrapper.signature as number[]).length).toBe(64);
  });
});
