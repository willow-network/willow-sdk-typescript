/**
 * The message a RegisterSubgrove is signed over, in every mode: the kind,
 * the subgrove, the owner, `Config` (the SHA-256 of the transaction's
 * bincode with an empty signature), and the nonce. The known answers are in
 * signed-second-set.test.ts; these pin the shape and what `Config` binds.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import {
  createSignMessage,
  registerSubgroveSignMessage,
  registerSubgroveUnsignedBincode,
} from '../src/consensus/types';
import type { RegisterSubgroveTx } from '../src/consensus/types';

function baseTx(overrides: Partial<RegisterSubgroveTx> = {}): RegisterSubgroveTx {
  return {
    subgroveId: 'test-sg',
    schema: JSON.stringify({ version: 1, fields: {} }),
    ownerDid: 'did:willow:validator1',
    nonce: 7,
    ...overrides,
  };
}

const MODES: Record<string, RegisterSubgroveTx['mode']> = {
  DataStorage: {
    DataStorage: { name: 'test-sg', writers: ['did:willow:validator1'], free_readers: [] },
  },
  FileStorage: {
    FileStorage: {
      name: 'my-files',
      max_file_size: 100,
      replication_factor: 1,
      writers: ['did:willow:validator1'],
      free_readers: [],
    },
  },
  BlockchainIndexing: {
    BlockchainIndexing: {
      manifest_content: [],
      execution_mode: 'ConsensusExecution',
      indexer_config: {
        min_indexers: 1,
        max_indexers: 3,
        reward_per_epoch: 0,
        min_indexer_stake: 0,
      },
    },
  },
};

describe('registerSubgroveSignMessage', () => {
  it.each(Object.keys(MODES))('%s signs the Config form', (mode) => {
    const tx = baseTx({ mode: MODES[mode] });
    const config = bytesToHex(sha256(registerSubgroveUnsignedBincode(tx)));
    const msg = registerSubgroveSignMessage(tx);
    expect(msg).toBe(
      [
        'RegisterSubgrove',
        'Subgrove: test-sg',
        'Owner: did:willow:validator1',
        `Config: ${config}`,
        'Nonce: 7',
      ].join('\n'),
    );
    expect(createSignMessage('RegisterSubgrove', tx)).toBe(msg);
  });

  it('defaults to a DataStorage mode named for the subgrove, the owner its only writer', () => {
    expect(registerSubgroveSignMessage(baseTx())).toBe(
      registerSubgroveSignMessage(baseTx({ mode: MODES.DataStorage })),
    );
  });

  it('binds every field: the names, the access lists, the funding, the nonce', () => {
    const base = registerSubgroveSignMessage(baseTx({ mode: MODES.DataStorage }));
    const changed = [
      baseTx({ mode: MODES.DataStorage, name: 'Human Name' }),
      baseTx({
        mode: { DataStorage: { name: 'mode-only-name', writers: ['did:willow:validator1'] } },
      }),
      baseTx({ mode: { DataStorage: { name: 'test-sg', writers: [] } } }),
      baseTx({ mode: MODES.DataStorage, initialFunding: '1' }),
      baseTx({ mode: MODES.DataStorage, schema: '{}' }),
      baseTx({ mode: MODES.DataStorage, publicKeyId: 'did:willow:validator1#key-2' }),
      baseTx({ mode: MODES.DataStorage, nonce: 8 }),
    ];
    for (const tx of changed) {
      expect(registerSubgroveSignMessage(tx)).not.toBe(base);
    }
  });

  it('refuses to sign without a nonce', () => {
    expect(() => registerSubgroveSignMessage(baseTx({ nonce: undefined }))).toThrow(/Nonce/);
  });
});
