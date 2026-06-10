/**
 * Locks in the canonical signing payload for RegisterSubgrove across all
 * three subgrove modes.
 *
 * These strings MUST match what the Rust consensus validator reconstructs
 * server-side. If they drift, every registration fails signature validation
 * with no client-side warning.
 */

import { createSignMessage } from '../src/consensus/types';
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

describe('createSignMessage — RegisterSubgrove', () => {
  it('DataStorage mode uses the multi-line format with name/writers/readers', () => {
    const tx = baseTx({
      mode: {
        DataStorage: {
          name: 'test-sg',
          writers: ['did:willow:validator1'],
          free_readers: [],
        },
      },
    });
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toContain('RegisterSubgrove\n');
    expect(msg).toContain('ID: test-sg');
    expect(msg).toContain('Name: test-sg');
    expect(msg).toContain('Owner: did:willow:validator1');
    expect(msg).toContain('Nonce: 7');
    expect(msg).toContain('Writers: did:willow:validator1');
    // DataStorage payload does NOT include a "Mode:" line.
    expect(msg).not.toContain('Mode:');
  });

  it('FileStorage mode uses the multi-line format with Mode: FileStorage', () => {
    // The server's FileStorage signing line reads the top-level name
    // (params.name), so the SDK must too — the per-mode name is not signed.
    const tx = baseTx({
      name: 'my-files',
      mode: {
        FileStorage: {
          name: 'my-files',
          max_file_size: 100,
          replication_factor: 1,
          writers: ['did:willow:validator1'],
          free_readers: [],
        },
      },
    });
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toContain('Mode: FileStorage');
    expect(msg).toContain('Name: my-files');
    expect(msg).toContain('Owner: did:willow:validator1');
    expect(msg).toContain('Nonce: 7');
  });

  it('BlockchainIndexing mode uses the compact colon-separated format', () => {
    // This is the critical case that used to be wrong. The live
    // validator builds exactly this string — any deviation (including
    // the multi-line format the other modes use) causes signature
    // verification to fail server-side.
    const tx = baseTx({
      mode: {
        BlockchainIndexing: {
          manifest_content: [],
          execution_mode: 'ConsensusExecution',
        },
      },
    });
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toBe('RegisterSubgrove:test-sg:did:willow:validator1:7');
  });

  it('omitting nonce defaults to 0 in the BlockchainIndexing payload', () => {
    const tx = baseTx({
      nonce: undefined,
      mode: {
        BlockchainIndexing: { manifest_content: [] },
      },
    });
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toBe('RegisterSubgrove:test-sg:did:willow:validator1:0');
  });

  it('no mode supplied defaults to the DataStorage multi-line format', () => {
    // Backward compatibility: old callers that never set `mode` must
    // still produce a DataStorage payload matching the server default.
    const tx = baseTx();
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toContain('RegisterSubgrove\n');
    expect(msg).toContain('Name: test-sg');
    expect(msg).not.toContain('Mode:');
  });

  it('signs over the top-level name, which the validator reads (not the per-mode name)', () => {
    // The Rust validator's create_register_subgrove_message uses params.name
    // (the top-level RegisterSubgroveTx.name); the DataStorage mode `name`
    // is `name: _` in the handler. Signing over the mode name instead would
    // diverge from the server whenever a human-readable name is supplied.
    const tx = baseTx({
      name: 'Human Name',
      mode: {
        DataStorage: {
          name: 'mode-only-name',
          writers: ['did:willow:validator1'],
          free_readers: [],
        },
      },
    });
    const msg = createSignMessage('RegisterSubgrove', tx);
    expect(msg).toContain('Name: Human Name');
    expect(msg).not.toContain('mode-only-name');
  });
});
