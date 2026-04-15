/**
 * Locks in the canonical signing payload for RegisterSubgrove across all
 * three subgrove modes.
 *
 * These strings MUST match what the Rust consensus validator reconstructs
 * server-side. If they drift, every registration fails signature
 * validation with no client-side warning — exactly the bug this test
 * caught (BlockchainIndexing was signing the wrong thing).
 *
 * Server-side references:
 *   - DataStorage / FileStorage → crates/consensus/src/transaction_validator.rs
 *     `create_register_subgrove_message` → `validate_register_subgrove_signature`
 *   - BlockchainIndexing → crates/consensus/src/willow_cometbft/subgrove_transactions.rs
 *     `let signing_payload = format!("RegisterSubgrove:{}:{}:{}", ...)`
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
    const tx = baseTx({
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
});
