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
        read_pricing: null,
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
      read_pricing: null,
    });
  });

  it('encodes the signature as a byte array, not a hex string', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect(Array.isArray(wrapper.signature)).toBe(true);
    expect((wrapper.signature as number[]).length).toBe(64);
  });

  it('sends initialFunding as a string so u128 values above 2^53 round-trip exactly', () => {
    // The chain's `initial_funding` is u128 and its `option_u128_flexible`
    // deserializer accepts a JSON string; parseInt would lose precision here.
    const big = '340282366920938463463374607431768211455'; // u128::MAX
    const wrapper = createTransactionWrapper(
      'RegisterSubgrove',
      baseTx({ initialFunding: big }),
    ).RegisterSubgrove;
    expect(wrapper.initial_funding).toBe(big);
    expect(typeof wrapper.initial_funding).toBe('string');
  });

  it('sends initial_funding as null when no funding is supplied', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect(wrapper.initial_funding).toBeNull();
  });

  it('writes initialFunding without leading zeros, as the chain decodes it', () => {
    const wrapper = createTransactionWrapper(
      'RegisterSubgrove',
      baseTx({ initialFunding: '007' }),
    ).RegisterSubgrove;
    expect(wrapper.initial_funding).toBe('7');
  });

  it('sends every field of the chain struct, in its order, defaults written out', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect(Object.keys(wrapper)).toEqual([
      'subgrove_id',
      'name',
      'description',
      'schema',
      'owner_did',
      'admins',
      'initial_funding',
      'checkpoint_verification',
      'mode',
      'privacy',
      'initial_owner_key_grant',
      'template_config',
      'confirmation_depth',
      'signature',
      'public_key_id',
      'nonce',
      'cryptographic_completeness',
    ]);
    expect(wrapper).toMatchObject({
      description: '',
      admins: [],
      checkpoint_verification: { required_tee: null },
      privacy: null,
      initial_owner_key_grant: null,
      template_config: null,
      confirmation_depth: 0,
      cryptographic_completeness: false,
    });
  });

  it('sends no top-level retention_window, which the chain struct does not have', () => {
    const wrapper = createTransactionWrapper('RegisterSubgrove', baseTx()).RegisterSubgrove;
    expect('retention_window' in wrapper).toBe(false);
  });
});
