import { WillowError } from '../src/errors';

describe('WillowError', () => {
  it('should create error with message', () => {
    const error = new WillowError('Test error');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(WillowError);
    expect(error.message).toBe('Test error');
    expect(error.name).toBe('WillowError');
  });

  it('should include status code', () => {
    const error = new WillowError('Not found', 404);
    expect(error.message).toBe('Not found');
    expect(error.statusCode).toBe(404);
  });

  it('should include details', () => {
    const details = { field: 'email', reason: 'Invalid format' };
    const error = new WillowError('Validation failed', 422, details);
    expect(error.message).toBe('Validation failed');
    expect(error.statusCode).toBe(422);
    expect(error.details).toEqual(details);
  });

  it('should have proper stack trace', () => {
    const error = new WillowError('Stack test');
    expect(error.stack).toBeDefined();
    expect(error.stack).toContain('WillowError');
    expect(error.stack).toContain('Stack test');
  });

  it('should work with instanceof', () => {
    const error = new WillowError('Test');
    expect(error instanceof Error).toBe(true);
    expect(error instanceof WillowError).toBe(true);
  });

  it('should serialize to JSON', () => {
    const error = new WillowError('JSON test', 400, { foo: 'bar' });
    const json = JSON.stringify(error);
    const parsed = JSON.parse(json);

    expect(parsed.message).toBe('JSON test');
    expect(parsed.statusCode).toBe(400);
    expect(parsed.details).toEqual({ foo: 'bar' });
  });

  it('should handle undefined values', () => {
    const error = new WillowError('Basic error');
    expect(error.statusCode).toBeUndefined();
    expect(error.details).toBeUndefined();
  });
});