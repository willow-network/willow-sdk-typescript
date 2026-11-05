/**
 * The package exports what a caller needs to check a write's outcome: the
 * `TransactionStatus` values `waitForTransaction` resolves with, and the
 * function the client's writes build their `TransactionSubmitError` with.
 */
import { TransactionStatus, TransactionSubmitError, writeNotAccepted } from '../src';
import type { BroadcastResult } from '../src';

describe("the package exports what checks a write's outcome", () => {
  it('TransactionStatus is a value', () => {
    expect(TransactionStatus.SUCCESS).toBe('success');
    expect(TransactionStatus.FAILED).toBe('failed');
  });

  it('writeNotAccepted gives a result carrying its submission as a TransactionSubmitError', () => {
    const submission = { did: 'did:willow:writer', nonce: 5, transaction: { RegisterSubgrove: {} } };
    const result: BroadcastResult = { success: false, pending: true, errorMessage: 'unconfirmed', submission };
    const error = writeNotAccepted('registerSubgrove', result);
    expect(error).toBeInstanceOf(TransactionSubmitError);
    expect(error).toMatchObject({ code: 'TX_SUBMIT_FAILED', did: 'did:willow:writer', nonce: 5, result });
    expect((error as TransactionSubmitError).transaction).toBe(submission.transaction);
    expect(error.message).toBe('registerSubgrove failed: unconfirmed');
    // Without a submission there is nothing to post again: a plain Error.
    const plain = writeNotAccepted('registerSubgrove', { success: false, errorMessage: 'refused' });
    expect(plain).not.toBeInstanceOf(TransactionSubmitError);
    expect(plain.message).toBe('registerSubgrove failed: refused');
  });
});
