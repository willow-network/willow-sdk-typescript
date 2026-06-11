import { WillowClient } from '../src/client';

describe('WillowClient — propagate consensus rejection', () => {
  function makeClient(broadcastResult: { success: boolean; errorMessage?: string; rawLog?: string }) {
    const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
    client.auth.setIdentity('did:willow:test', '00'.repeat(32), 'did:willow:test#key-1');
    // Stub the consensus methods to return whatever BroadcastResult we want
    (client as any).consensus = {
      storeData: jest.fn().mockResolvedValue(broadcastResult),
      registerSubgrove: jest.fn().mockResolvedValue(broadcastResult),
    };
    return client;
  }

  describe('client.store', () => {
    it('throws when the consensus tx is rejected (code !== 0)', async () => {
      const client = makeClient({
        success: false,
        errorMessage: 'Insufficient subgrove balance',
        rawLog: 'Insufficient subgrove balance: ...',
      });
      await expect(
        client.store('sg', 'k', { v: 1 }),
      ).rejects.toThrow(/Insufficient subgrove balance/);
    });

    it('returns normally when broadcast succeeds', async () => {
      const client = makeClient({ success: true });
      await expect(client.store('sg', 'k', { v: 1 })).resolves.toBeUndefined();
    });
  });

  describe('client.registerSubgrove', () => {
    it('throws when the consensus tx is rejected', async () => {
      const client = makeClient({
        success: false,
        errorMessage: 'Invalid signature',
        rawLog: 'Invalid signature',
      });
      await expect(
        client.registerSubgrove({
          dataset_id: 'sg',
          name: 'test',
          owner_did: 'did:willow:test',
        } as any),
      ).rejects.toThrow(/Invalid signature/);
    });

    it('returns the BroadcastResult on success (no fabricated registration object)', async () => {
      const broadcast = { success: true, txHash: 'AB12CD', height: 42 };
      const client = makeClient(broadcast);
      const result = await client.registerSubgrove({
        dataset_id: 'sg',
        name: 'test',
        owner_did: 'did:willow:test',
      } as any);
      expect(result).toBe(broadcast);
    });
  });

  describe('client.registerDataset (deprecated alias)', () => {
    it('delegates to registerSubgrove and throws when the consensus tx is rejected', async () => {
      const client = makeClient({
        success: false,
        errorMessage: 'Invalid signature',
        rawLog: 'Invalid signature',
      });
      await expect(
        client.registerDataset({
          dataset_id: 'sg',
          name: 'test',
          owner_did: 'did:willow:test',
        } as any),
      ).rejects.toThrow(/Invalid signature/);
    });
  });

  describe('client.registerSubgrove — access lists reach the chain', () => {
    /** Stub consensus.registerSubgrove and capture the args it was called with. */
    function makeCapturingClient() {
      const client = new WillowClient({ apiUrl: 'http://localhost:3031' });
      client.auth.setIdentity('did:willow:owner', '00'.repeat(32), 'did:willow:owner#key-1');
      const registerSubgrove = jest
        .fn()
        .mockResolvedValue({ success: true, txHash: 'AB12CD' });
      (client as any).consensus = { registerSubgrove };
      return { client, registerSubgrove };
    }

    it('builds a DataStorage mode from name/writers/readers (readers → free_readers)', async () => {
      const { client, registerSubgrove } = makeCapturingClient();
      await client.registerSubgrove({
        dataset_id: 'sg',
        name: 'My Subgrove',
        schema: { version: 1, fields: {} },
        owner_did: 'did:willow:owner',
        writers: ['did:willow:owner', 'did:willow:writer2'],
        readers: ['did:willow:reader1'],
      } as any);

      const options = registerSubgrove.mock.calls[0][4];
      expect(options.name).toBe('My Subgrove');
      expect(options.mode).toEqual({
        DataStorage: {
          name: 'My Subgrove',
          writers: ['did:willow:owner', 'did:willow:writer2'],
          free_readers: ['did:willow:reader1'],
        },
      });
    });

    it('an explicit options.mode overrides the request access lists', async () => {
      const { client, registerSubgrove } = makeCapturingClient();
      const mode = {
        FileStorage: {
          name: 'files',
          max_file_size: 1000,
          replication_factor: 1,
          writers: ['did:willow:owner'],
          free_readers: [],
        },
      };
      await client.registerSubgrove(
        {
          dataset_id: 'sg',
          name: 'My Subgrove',
          schema: { version: 1, fields: {} },
          owner_did: 'did:willow:owner',
          writers: ['did:willow:ignored'],
          readers: ['did:willow:ignored'],
        } as any,
        { mode } as any,
      );

      const options = registerSubgrove.mock.calls[0][4];
      expect(options.mode).toBe(mode);
    });
  });
});
