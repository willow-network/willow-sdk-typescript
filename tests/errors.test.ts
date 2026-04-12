import { WillowError } from '../src/types';

describe('WillowError', () => {
  it('should create error with message', () => {
    const error = new WillowError('Test error');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(WillowError);
    expect(error.message).toBe('Test error');
    expect(error.name).toBe('WillowError');
  });

  it('should include error code', () => {
    const error = new WillowError('Not found', 'NOT_FOUND');
    expect(error.message).toBe('Not found');
    expect(error.code).toBe('NOT_FOUND');
  });

  it('should include status code', () => {
    const error = new WillowError('Not found', 'NOT_FOUND', 404);
    expect(error.message).toBe('Not found');
    expect(error.code).toBe('NOT_FOUND');
    expect(error.statusCode).toBe(404);
  });

  it('should have proper stack trace', () => {
    const error = new WillowError('Stack test');
    expect(error.stack).toBeDefined();
    expect(error.stack).toContain('Stack test');
  });

  it('should work with instanceof', () => {
    const error = new WillowError('Test');
    expect(error instanceof Error).toBe(true);
    expect(error instanceof WillowError).toBe(true);
  });

  it('should expose fields for serialization', () => {
    const error = new WillowError('JSON test', 'BAD_REQUEST', 400);
    // Fields declared via `public` parameter properties are enumerable
    expect(error.code).toBe('BAD_REQUEST');
    expect(error.statusCode).toBe(400);
  });

  it('should handle undefined optional fields', () => {
    const error = new WillowError('Basic error');
    expect(error.code).toBeUndefined();
    expect(error.statusCode).toBeUndefined();
  });
});
