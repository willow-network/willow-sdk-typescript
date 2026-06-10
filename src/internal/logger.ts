/**
 * Injectable logging for SDK internals.
 *
 * Library code must never log unconditionally: every class that wants to
 * log accepts an optional `WillowLogger` and defaults to `silentLogger`.
 * Pass `consoleLogger` (or your own implementation) to surface SDK
 * diagnostics, e.g. `new WillowClient({ apiUrl, logger: consoleLogger })`.
 */

export interface WillowLogger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

/** Default logger: discards everything. */
export const silentLogger: WillowLogger = {
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

/** Opt-in logger that forwards to the global `console`. */
export const consoleLogger: WillowLogger = {
  debug: (message, ...args) => console.debug(message, ...args),
  info: (message, ...args) => console.info(message, ...args),
  warn: (message, ...args) => console.warn(message, ...args),
  error: (message, ...args) => console.error(message, ...args),
};
